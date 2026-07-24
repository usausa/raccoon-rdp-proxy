namespace Raccoon.RdpProxy.Protocol;

// サーバが RDP Negotiation を FAILURE で返したときの例外。
// Exception thrown when the server returns an RDP Negotiation FAILURE.
internal sealed class RdpNegFailureException : Exception
{
    public RdpNegFailureException(uint code)
        : base(Describe(code))
    {
        Code = code;
    }

    public RdpNegFailureException()
    {
    }

    public RdpNegFailureException(string message)
        : base(message)
    {
    }

    public RdpNegFailureException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public uint Code { get; }

    private static string Describe(uint code) => code switch
    {
        0x00000001 => "SSL_REQUIRED_BY_SERVER: server requires TLS.",
        0x00000002 => "SSL_NOT_ALLOWED_BY_SERVER: server does not allow TLS.",
        0x00000003 => "SSL_CERT_NOT_ON_SERVER: server has no certificate.",
        0x00000004 => "INCONSISTENT_FLAGS",
        0x00000005 => "HYBRID_REQUIRED_BY_SERVER: server requires NLA (CredSSP). " +
                      "Disable the NLA requirement on the target, or use the credential-bridge mode.",
        0x00000006 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
        _ => $"RDP Negotiation Failure code=0x{code:X8}",
    };
}
