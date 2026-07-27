namespace Raccoon.RdpProxy.Settings;

// CredSSP credentials. Used for the global default and per-map overrides
internal sealed class CredentialSetting
{
    public string Domain { get; set; } = string.Empty;

    public string User { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    // Instead of a plaintext Password, the 16-byte hex of MD4(password) may be specified
    public string? NtHash { get; set; }
}
