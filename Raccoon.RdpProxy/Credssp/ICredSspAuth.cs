namespace Raccoon.RdpProxy.Credssp;

// CredSSP の認証機構を差し替え可能にする抽象。
// 既定はハンドロール(NtlmClientAuth, 依存なし)、フォールバックに .NET 標準 NegotiateCredSspAuth。
internal interface ICredSspAuth
{
    byte[] BuildInitialToken(); // NTLM NEGOTIATE 相当

    byte[] ProcessChallenge(byte[] challenge, string spn); // NTLM AUTHENTICATE 相当

    byte[] Seal(ReadOnlySpan<byte> plaintext); // EncryptMessage (pubKeyAuth/authInfo)

    byte[] Unseal(ReadOnlySpan<byte> token); // DecryptMessage
}
