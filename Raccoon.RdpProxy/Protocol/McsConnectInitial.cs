namespace Raccoon.RdpProxy.Protocol;

using System.Text;

// MCS Connect Initial 内 clientCoreData(TS_UD_CS_CORE) の書き換え。
// クライアント脚を SSL に落としているため serverSelectedProtocol が SSL のまま残る。
// バックエンドが選択した HYBRID に合わせないとダウングレード検知で RST される。
// clientName/clientDigProductId のマスクも同ブロックで行う。いずれも同サイズの in-place 書き換え。
// Rewrites clientCoreData (TS_UD_CS_CORE) inside the MCS Connect Initial.
// Because the client leg is downgraded to SSL, serverSelectedProtocol stays SSL;
// it must be aligned to the HYBRID the backend selected, or a downgrade is detected and RST is sent.
// Masking of clientName/clientDigProductId happens in the same block. All are same-size in-place rewrites.
internal static class McsConnectInitial
{
    // CS_CORE ブロック先頭からの serverSelectedProtocol オフセット
    // serverSelectedProtocol offset from the start of the CS_CORE block
    // header(4) + version(4)+w(2)+h(2)+color(2)+sas(2)+kbl(4)+build(4)+name(32)
    //  + kbType(4)+kbSub(4)+kbFn(4)+ime(64)+postBeta2(2)+prodId(2)+serial(4)+highColor(2)
    //  + supportedColor(2)+earlyCap(2)+digProductId(64)+connType(1)+pad(1) = 212
    private const int SspOffsetInBlock = 212;
    private const int MinBlockLen = SspOffsetInBlock + 4;

    // CS_CORE 各フィールドの先頭からのオフセット(header 4byte 含む)
    // Offsets of each CS_CORE field from the start of the block (including the 4-byte header)
    private const int ClientNameOffset = 24; // 32byte (UTF-16, NUL終端) / 32 bytes (UTF-16, NUL-terminated)
    private const int ClientDigProductIdOffset = 146; // 64byte

    public static bool PatchServerSelectedProtocol(Span<byte> tpkt, uint expectedCurrent, uint newValue)
    {
        var p = FindCsCore(tpkt, out _);
        if (p < 0)
        {
            return false;
        }

        var sspPos = p + SspOffsetInBlock;
        if (ByteOps.U32Le(tpkt, sspPos) != expectedCurrent)
        {
            return false; // 誤検出防止(期待値のみ書換) / avoid false positives (rewrite only when it matches the expected value)
        }

        ByteOps.W32Le(tpkt, sspPos, newValue);
        return true;
    }

    // clientName を指定値に書き換え(clientName!=null時)、clientDigProductId をゼロ化(zeroProductId時)。
    // 何か書き換えたら true。
    // Rewrites clientName to the given value (when clientName != null) and zeros clientDigProductId (when zeroProductId).
    // Returns true if anything was rewritten.
    public static bool PatchClientIdentity(Span<byte> tpkt, string? clientName, bool zeroProductId)
    {
        var p = FindCsCore(tpkt, out var blockLen);
        if (p < 0)
        {
            return false;
        }

        var did = false;

        if (clientName is not null)
        {
            // clientName (32byte, UTF-16LE, NUL終端) を差し替え
            // Replace clientName (32 bytes, UTF-16LE, NUL-terminated)
            var nameField = tpkt.Slice(p + ClientNameOffset, 32);
            nameField.Clear();
            var nb = Encoding.Unicode.GetBytes(clientName);
            nb.AsSpan(0, Math.Min(nb.Length, 30)).CopyTo(nameField); // 15文字+NUL 分を残す / leave room for 15 chars + NUL
            did = true;
        }

        if (zeroProductId && (blockLen >= (ClientDigProductIdOffset + 64)))
        {
            tpkt.Slice(p + ClientDigProductIdOffset, 64).Clear(); // clientDigProductId をゼロ化 / zero out clientDigProductId
            did = true;
        }

        return did;
    }

    // CS_CORE ブロックを探す。serverSelectedProtocol==SSL で本物と確定(クライアント脚は常に SSL)。
    // Find the CS_CORE block. serverSelectedProtocol==SSL confirms the real one (the client leg is always SSL).
    private static int FindCsCore(ReadOnlySpan<byte> tpkt, out int blockLen)
    {
        blockLen = 0;
        var len = tpkt.Length;
        if ((len < 12) || (tpkt[0] != 0x03))
        {
            return -1;
        }

        if ((tpkt[4] != 0x02) || (tpkt[5] != 0xF0) || (tpkt[6] != 0x80))
        {
            return -1; // X.224 Data
        }

        if ((tpkt[7] != 0x7F) || (tpkt[8] != 0x65))
        {
            return -1; // MCS Connect Initial (BER 7F65)
        }

        for (var p = 9; (p + MinBlockLen) <= len; p++)
        {
            if ((tpkt[p] != 0x01) || (tpkt[p + 1] != 0xC0))
            {
                continue; // CS_CORE (0xC001, LE)
            }

            var bl = tpkt[p + 2] | (tpkt[p + 3] << 8);
            if ((bl < MinBlockLen) || ((p + bl) > len))
            {
                continue;
            }

            if (ByteOps.U32Le(tpkt, p + SspOffsetInBlock) != RdpConstants.ProtocolSsl)
            {
                continue; // 確定 / confirmed
            }

            blockLen = bl;
            return p;
        }

        return -1;
    }
}
