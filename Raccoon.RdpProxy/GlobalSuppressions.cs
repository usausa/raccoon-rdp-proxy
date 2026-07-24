using System.Diagnostics.CodeAnalysis;

// DI / Options / async の慣例 (Raccoon 共通)。
// DI / Options / async conventions (shared across Raccoon).
[assembly: SuppressMessage("Maintainability", "CA1515:Consider making public types internal", Justification = "Ignore")]
[assembly: SuppressMessage("Maintainability", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated by DI / configuration binding.")]
[assembly: SuppressMessage("Reliability", "CA2007:DoNotDirectlyAwaitATaskAnalyzer", Justification = "Ignore")]

// NTLM / CredSSP は仕様上 MD4 / MD5 / HMAC-MD5 / RC4 を必須とし、代替アルゴリズムが存在しない。
// NTLM / CredSSP mandate MD4 / MD5 / HMAC-MD5 / RC4 by spec; there is no alternative algorithm.
[assembly: SuppressMessage("Security", "CA5351:Do Not Use Broken Cryptographic Algorithms", Justification = "NTLM/CredSSP protocol mandates MD4/MD5/HMAC-MD5/RC4; there is no alternative.")]

// バックエンド RDP サーバは自己署名証明書が普通。TLS 証明書ではなく CredSSP の pubKeyAuth
// (公開鍵チャネルバインディング) で完全性を担保するため、TLS 証明書検証は行わない。
// Backend RDP servers commonly use self-signed certs. Integrity is enforced by CredSSP pubKeyAuth
// (public-key channel binding) rather than the TLS certificate, so TLS certificate validation is skipped.
[assembly: SuppressMessage("Security", "CA5359:Do Not Disable Certificate Validation", Justification = "RDP backend uses self-signed certs; integrity is enforced by CredSSP pubKeyAuth channel binding.")]

// accept したクライアントの所有権はハンドラタスクへ移譲され、そこで破棄される (TCP サーバの定型)。
// Ownership of the accepted client is transferred to the handler task, which disposes it (standard TCP-server pattern).
[assembly: SuppressMessage("Reliability", "CA2025:Ensure tasks using IDisposable complete before the instance is disposed", Justification = "Ownership of the accepted client is transferred to the handler task, which disposes it.")]
