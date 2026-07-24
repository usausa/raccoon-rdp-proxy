namespace Raccoon.RdpProxy.Credssp;

using System.Security.Cryptography.X509Certificates;

// CredSSP の pubKeyAuth に使うサーバ公開鍵を取り出す。
// 重要: SubjectPublicKeyInfo ではなく PKCS#1 RSAPublicKey (OpenSSL i2d_PublicKey 相当)。
// FreeRDP / Windows / pyspnego と同じ形式でないとサーバの pubKeyAuth 検証に失敗する。
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
            return ec.ExportSubjectPublicKeyInfo(); // 非RSA(まれ)はフォールバック
        }

        throw new NotSupportedException("CredSSP: unsupported server public-key type.");
    }
}
