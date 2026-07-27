namespace Raccoon.RdpProxy.Credssp;

// Abstraction that makes the CredSSP authentication mechanism pluggable
// The default is the hand-rolled one (NtlmClientAuth, no dependencies), with the standard .NET NegotiateCredSspAuth as fallback
internal interface ICredSspAuth
{
    byte[] BuildInitialToken(); // Equivalent to NTLM NEGOTIATE

    byte[] ProcessChallenge(byte[] challenge, string spn); // Equivalent to NTLM AUTHENTICATE

    byte[] Seal(ReadOnlySpan<byte> plaintext); // EncryptMessage (pubKeyAuth/authInfo)

    byte[] Unseal(ReadOnlySpan<byte> token); // DecryptMessage
}
