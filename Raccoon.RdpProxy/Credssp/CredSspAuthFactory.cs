namespace Raccoon.RdpProxy.Credssp;

using Raccoon.RdpProxy.Ntlm;

// Creates an ICredSspAuth from the impl name
internal static class CredSspAuthFactory
{
    public static ICredSspAuth Create(string? impl, string domain, string user, string password, string? ntHashHex, string spn)
    {
        if (String.Equals(impl, "negotiate", StringComparison.OrdinalIgnoreCase))
        {
            return new NegotiateCredSspAuth(domain, user, password, spn);
        }

        var ntHash = ntHashHex is not null ? Convert.FromHexString(ntHashHex) : null;
        return new NtlmClientAuth(domain, user, password, ntHash: ntHash);
    }
}
