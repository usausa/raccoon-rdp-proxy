namespace Raccoon.RdpProxy.Settings;

// The "Proxy" section, Represents all mappings via defaults plus maps[] overrides.
internal sealed class ProxySetting
{
    public const string SectionName = "Proxy";

    public string Listen { get; set; } = "0.0.0.0";

    // Server certificate (PFX). If absent, a 10-year cert is generated and saved on first run
    public string? Cert { get; set; }

    public string? CertPassword { get; set; }

    // TCP source bind toward the target (null = default route)
    public string? Source { get; set; }

    // The clientAddress to write into the RDP packet
    public string ClientAddress { get; set; } = string.Empty;

    // When set, rewrite clientName. Pass through if null
    public string? ClientName { get; set; }

    // When true, also erase clientDigProductId/clientDir
    public bool MaskClientInfo { get; set; }

    // handroll (no dependencies) | negotiate (SSPI/gss-ntlmssp)
    public string CredsspImpl { get; set; } = "handroll";

    public CredentialSetting Credentials { get; set; } = new();

    // Source-IP allowlist (CIDR). Empty means allow all
    public string[] Allow { get; set; } = [];

    public MapSetting[] Maps { get; set; } = [];
}
