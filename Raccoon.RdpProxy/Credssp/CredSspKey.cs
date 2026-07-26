namespace Raccoon.RdpProxy.Credssp;

using System.Security.Cryptography.X509Certificates;

// CredSSP の pubKeyAuth に使うサーバ公開鍵を取り出す。
// 重要: SubjectPublicKeyInfo ではなく PKCS#1 RSAPublicKey (OpenSSL i2d_PublicKey 相当)。
// FreeRDP / Windows / pyspnego と同じ形式でないとサーバの pubKeyAuth 検証に失敗する。
// Extracts the server public key used for the CredSSP pubKeyAuth.
// Important: PKCS#1 RSAPublicKey, not SubjectPublicKeyInfo (equivalent to OpenSSL i2d_PublicKey).
// Unless the format matches FreeRDP / Windows / pyspnego, the server's pubKeyAuth verification fails.
internal static class CredSspKey
{
    public static byte[] FromCertificate(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.ExportRSAPublicKey(); // PKCS#1 RSAPublicKey
        }

        using var ec = cert.GetECDsaPublicKey();
        if (ec is not null)
        {
            return ec.ExportSubjectPublicKeyInfo(); // 非RSA(まれ)はフォールバック / non-RSA (rare) falls back to SPKI
        }

        throw new NotSupportedException("CredSSP: unsupported server public-key type.");
    }
}
