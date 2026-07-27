namespace Raccoon.RdpProxy.Protocol;

// Build/parse X.224 connection request/confirm (RDP Negotiation).
internal static class RdpNegotiation
{
    // TPKT(4) + LI(1) + [E0/D0 + dstref2 + srcref2 + class1](6) + Neg(8) = 19 / fixed
    private const int NegPduSize = 19;

    // Extract the requested protocols from the client's CR (cookie ignored; informational)
    public static uint ParseRequestedProtocols(ReadOnlySpan<byte> cr)
    {
        const int varStart = 4 + 1 + 6;
        if ((cr.Length >= (varStart + 8)) && (cr[^8] == RdpConstants.TypeRdpNegReq))
        {
            return ByteOps.U32Le(cr, cr.Length - 4);
        }

        return RdpConstants.ProtocolRdp;
    }

    // Build the CR sent to the server (requesting the specified protocols)
    public static byte[] BuildConnectionRequest(uint requestedProtocols)
    {
        Span<byte> b = stackalloc byte[NegPduSize]; // Zero-initialized by default
        b[0] = 0x03;
        ByteOps.W16Be(b, 2, NegPduSize);
        b[4] = 14; // LI = 6 + 8
        b[5] = RdpConstants.X224Cr;
        b[11] = RdpConstants.TypeRdpNegReq;
        ByteOps.W16Le(b, 13, 8);
        ByteOps.W32Le(b, 15, requestedProtocols);
        return b.ToArray();
    }

    // Build the CC sent to the client (selecting the specified protocol)
    public static byte[] BuildConnectionConfirm(uint selectedProtocol, byte respFlags)
    {
        Span<byte> b = stackalloc byte[NegPduSize];
        b[0] = 0x03;
        ByteOps.W16Be(b, 2, NegPduSize);
        b[4] = 14;
        b[5] = RdpConstants.X224Cc;
        b[11] = RdpConstants.TypeRdpNegRsp;
        b[12] = respFlags;
        ByteOps.W16Le(b, 13, 8);
        ByteOps.W32Le(b, 15, selectedProtocol);
        return b.ToArray();
    }

    // Parse the server's CC. Returns selected for RSP; throws on FAILURE
    public static (uint Selected, byte Flags) ParseConnectionConfirm(ReadOnlySpan<byte> cc)
    {
        const int negStart = 4 + 1 + 6;
        if (cc.Length < (negStart + 8))
        {
            return (RdpConstants.ProtocolRdp, 0); // No Neg = standard RDP
        }

        var type = cc[negStart];
        var flags = cc[negStart + 1];
        var value = ByteOps.U32Le(cc, negStart + 4);

        if (type == RdpConstants.TypeRdpNegFailure)
        {
            throw new RdpNegFailureException(value);
        }

        if (type == RdpConstants.TypeRdpNegRsp)
        {
            return (value, flags);
        }

        return (RdpConstants.ProtocolRdp, 0);
    }
}
