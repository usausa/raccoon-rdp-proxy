namespace Raccoon.RdpProxy.Ntlm;

// NTLM negotiate flags (MS-NLMP 2.2.2.5)。
[Flags]
internal enum NtlmFlags : uint
{
    None = 0x00000000,
    Unicode = 0x00000001,
    RequestTarget = 0x00000004,
    Sign = 0x00000010,
    Seal = 0x00000020,
    Ntlm = 0x00000200,
    AlwaysSign = 0x00008000,
    ExtendedSessionSecurity = 0x00080000,
    TargetInfo = 0x00800000,
    Version = 0x02000000,
    Negotiate128 = 0x20000000,
    KeyExchange = 0x40000000,
    Negotiate56 = 0x80000000
}
