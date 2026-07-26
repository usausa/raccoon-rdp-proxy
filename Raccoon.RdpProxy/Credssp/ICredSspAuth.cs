namespace Raccoon.RdpProxy.Credssp;

// CredSSP の認証機構を差し替え可能にする抽象。
// 既定はハンドロール(NtlmClientAuth, 依存なし)、フォールバックに .NET 標準 NegotiateCredSspAuth。
// Abstraction that makes the CredSSP authentication mechanism pluggable.
// The default is the hand-rolled one (NtlmClientAuth, no dependencies), with the standard .NET NegotiateCredSspAuth as fallback.
internal interface ICredSspAuth
{
    byte[] BuildInitialToken(); // NTLM NEGOTIATE 相当 / equivalent to NTLM NEGOTIATE

    byte[] ProcessChallenge(byte[] challenge, string spn); // NTLM AUTHENTICATE 相当 / equivalent to NTLM AUTHENTICATE

    byte[] Seal(ReadOnlySpan<byte> plaintext); // EncryptMessage (pubKeyAuth/authInfo)

    byte[] Unseal(ReadOnlySpan<byte> token); // DecryptMessage
}
