namespace Raccoon.RdpProxy.Settings;

// CredSSP 資格情報。グローバル既定と map 毎の上書きに使う。
// CredSSP credentials. Used for the global default and per-map overrides.
internal sealed class CredentialSetting
{
    public string Domain { get; set; } = string.Empty;

    public string User { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    // 平文 Password の代わりに MD4(password) の 16byte hex を指定可能。
    // Instead of a plaintext Password, the 16-byte hex of MD4(password) may be specified.
    public string? NtHash { get; set; }
}
