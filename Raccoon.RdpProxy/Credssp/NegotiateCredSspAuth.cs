namespace Raccoon.RdpProxy.Credssp;

using System.Net.Security;

// CredSSP authentication using the standard .NET NegotiateAuthentication (SSPI/GSSAPI)
// Requires native SSPI on Windows, and gss-ntlmssp on Linux
// Fallback for when the hand-rolled implementation does not work against a real Windows host (credssp-impl=negotiate)
internal sealed class NegotiateCredSspAuth : ICredSspAuth, IDisposable
{
    private readonly NegotiateAuthentication na;

    public NegotiateCredSspAuth(string domain, string user, string password, string spn)
    {
        na = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
        {
            Package = "NTLM", // Specify NTLM explicitly because this is an IP connection (Kerberos would require SPN resolution)
            Credential = new NetworkCredential(user, password, domain),
            TargetName = spn,
            RequiredProtectionLevel = ProtectionLevel.EncryptAndSign
        });
    }

    public byte[] BuildInitialToken()
    {
        var blob = na.GetOutgoingBlob([], out var status);
        Require(status, "NEGOTIATE");
        return blob ?? [];
    }

    public byte[] ProcessChallenge(byte[] challenge, string spn)
    {
        var blob = na.GetOutgoingBlob(challenge, out var status);
        Require(status, "AUTHENTICATE");
        return blob ?? [];
    }

    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        var w = new ArrayBufferWriter<byte>();
        var st = na.Wrap(plaintext, w, true, out _);
        if (st != NegotiateAuthenticationStatusCode.Completed)
        {
            throw new IOException($"Negotiate Wrap failed: {st}");
        }

        return w.WrittenSpan.ToArray();
    }

    public byte[] Unseal(ReadOnlySpan<byte> token)
    {
        var w = new ArrayBufferWriter<byte>();
        var st = na.Unwrap(token, w, out _);
        if (st != NegotiateAuthenticationStatusCode.Completed)
        {
            throw new IOException($"Negotiate Unwrap failed: {st}");
        }

        return w.WrittenSpan.ToArray();
    }

    public void Dispose() => na.Dispose();

    private static void Require(NegotiateAuthenticationStatusCode st, string step)
    {
        if (st is not (NegotiateAuthenticationStatusCode.ContinueNeeded or NegotiateAuthenticationStatusCode.Completed))
        {
            throw new IOException($"Negotiate({step}) failed: {st}");
        }
    }
}
