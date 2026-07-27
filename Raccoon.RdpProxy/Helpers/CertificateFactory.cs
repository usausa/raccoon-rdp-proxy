namespace Raccoon.RdpProxy.Helpers;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// Result of loading a certificate
// Path is the file used (null if none), Created tells whether it was newly generated
internal readonly record struct CertificateLoadResult(string? Path, bool Created);

// Loading / generation of the server certificate
internal static class CertificateFactory
{
    // certPath given: load the existing file if present; otherwise generate a 10-year certificate, save it, and reuse it
    // certPath omitted: generate one in memory every time, created is true when a new certificate was generated
    public static X509Certificate2 LoadOrCreate(string? certPath, string? certPassword, out CertificateLoadResult result)
    {
        if (certPath is not null)
        {
            if (File.Exists(certPath))
            {
                result = new CertificateLoadResult(certPath, false);
                return X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(certPath), certPassword);
            }

            using var created = CreateSelfSigned10Y();
            var pfx = created.Export(X509ContentType.Pfx, certPassword);
            File.WriteAllBytes(certPath, pfx);
            try
            {
                File.WriteAllBytes(Path.ChangeExtension(certPath, ".cer"), created.Export(X509ContentType.Cert));
            }
            catch (IOException)
            {
                // Writing the companion .cer is optional
            }

            result = new CertificateLoadResult(certPath, true);
            return X509CertificateLoader.LoadPkcs12(pfx, certPassword);
        }

        result = new CertificateLoadResult(null, true);
        using var tmp = CreateSelfSigned10Y();
        return X509CertificateLoader.LoadPkcs12(tmp.Export(X509ContentType.Pfx), null);
    }

    // Write out a PFX (with private key) and a CER (public key, for the client to trust) for distribution
    public static X509Certificate2 MakeFile(string pfxPath, out string cerPath)
    {
        var cert = CreateSelfSigned10Y();
        File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pfx));
        cerPath = Path.ChangeExtension(pfxPath, ".cer");
        File.WriteAllBytes(cerPath, cert.Export(X509ContentType.Cert));
        return cert;
    }

    // Generate a self-signed certificate (serverAuth) valid for 10 years
    private static X509Certificate2 CreateSelfSigned10Y()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=rdp-proxy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], false)); // serverAuth
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }
}
