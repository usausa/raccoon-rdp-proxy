namespace Raccoon.RdpProxy.Credssp;

using System.Security.Cryptography.X509Certificates;

// Extracts the server public key used for the CredSSP pubKeyAuth.
// Important: PKCS#1 RSAPublicKey, not SubjectPublicKeyInfo (equivalent to OpenSSL i2d_PublicKey).
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
            return ec.ExportSubjectPublicKeyInfo(); // Non-RSA (rare) falls back to SPKI
        }

        throw new NotSupportedException("CredSSP: unsupported server public-key type.");
    }
}
