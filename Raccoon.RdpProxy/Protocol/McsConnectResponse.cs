namespace Raccoon.RdpProxy.Protocol;

// MCS Connect Response 内 serverCoreData(TS_UD_SC_CORE) の clientRequestedProtocols を差し替える。
// バックエンドは「プロキシが送った要求(0x03)」をエコーするが、mstsc は「自分の要求(0xB)」を期待する。
// 不一致だと mstsc が認証エラー(0x609)で切断するため、mstsc の要求値に書き換える。in-place。
// Replaces clientRequestedProtocols in serverCoreData (TS_UD_SC_CORE) inside the MCS Connect Response.
// The backend echoes "the request the proxy sent (0x03)", but mstsc expects "its own request (0xB)".
// A mismatch makes mstsc disconnect with an authentication error (0x609), so rewrite it to mstsc's value. In-place.
internal static class McsConnectResponse
{
    // SC_CORE 先頭からの clientRequestedProtocols オフセット = header(4)+version(4)
    // clientRequestedProtocols offset from the start of SC_CORE = header(4)+version(4)
    private const int ReqProtoOffsetInBlock = 8;
    private const int MinBlockLen = ReqProtoOffsetInBlock + 4;

    public static bool PatchClientRequestedProtocols(Span<byte> tpkt, uint expectedCurrent, uint newValue)
    {
        var len = tpkt.Length;
        if ((len < 12) || (tpkt[0] != 0x03))
        {
            return false;
        }

        if ((tpkt[4] != 0x02) || (tpkt[5] != 0xF0) || (tpkt[6] != 0x80))
        {
            return false; // X.224 Data
        }

        if ((tpkt[7] != 0x7F) || (tpkt[8] != 0x66))
        {
            return false; // MCS Connect Response (BER 7F66)
        }

        for (var p = 9; (p + MinBlockLen) <= len; p++)
        {
            if ((tpkt[p] != 0x01) || (tpkt[p + 1] != 0x0C))
            {
                continue; // SC_CORE (0x0C01, LE)
            }

            var blockLen = tpkt[p + 2] | (tpkt[p + 3] << 8);
            if ((blockLen < MinBlockLen) || ((p + blockLen) > len))
            {
                continue;
            }

            var pos = p + ReqProtoOffsetInBlock;
            if (ByteOps.U32Le(tpkt, pos) != expectedCurrent)
            {
                continue;
            }

            ByteOps.W32Le(tpkt, pos, newValue);
            return true;
        }

        return false;
    }
}
