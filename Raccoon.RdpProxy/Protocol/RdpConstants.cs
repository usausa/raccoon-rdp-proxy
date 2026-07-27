namespace Raccoon.RdpProxy.Protocol;

// Constants used by MS-RDPBCGR
internal static class RdpConstants
{
    // RDP Negotiation (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1 / 2.2.1.2.2)
    public const byte TypeRdpNegReq = 0x01;
    public const byte TypeRdpNegRsp = 0x02;
    public const byte TypeRdpNegFailure = 0x03;

    // requested / selected protocol (LE 32bit)
    public const uint ProtocolRdp = 0x00000000;
    public const uint ProtocolSsl = 0x00000001;
    public const uint ProtocolHybrid = 0x00000002;
    public const uint ProtocolHybridEx = 0x00000008;

    // Basic Security Header flags (MS-RDPBCGR 2.2.8.1.1.2.1)
    public const ushort SecInfoPkt = 0x0040;
    public const ushort SecEncrypt = 0x0008;

    // Info Packet flags (MS-RDPBCGR 2.2.1.11.1.1)
    public const uint InfoUnicode = 0x00000010;

    // MCS DomainMCSPDU choice tag (T.125) = value << 2
    public const byte McsSendDataRequest = 0x64;

    // X.224 TPDU codes
    public const byte X224Cr = 0xE0;
    public const byte X224Cc = 0xD0;
    public const byte X224Dt = 0xF0;
}
