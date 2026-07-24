namespace Raccoon.RdpProxy.Settings;

// appsettings.json の "Proxy" セクション。既定値と maps[] の上書きで全マッピングを表す。
// The "Proxy" section of appsettings.json. Represents all mappings via defaults plus maps[] overrides.
internal sealed class ProxySetting
{
    public const string SectionName = "Proxy";

    public string Listen { get; set; } = "0.0.0.0";

    // サーバ証明書(PFX)。無ければ初回に 10 年物を生成して保存する。
    // Server certificate (PFX). If absent, a 10-year cert is generated and saved on first run.
    public string? Cert { get; set; }

    public string? CertPassword { get; set; }

    // ターゲットへの TCP 送信元 bind (null=既定ルート)。
    // TCP source bind toward the target (null = default route).
    public string? Source { get; set; }

    // RDP パケットに書き込む clientAddress。
    // The clientAddress to write into the RDP packet.
    public string ClientAddress { get; set; } = string.Empty;

    // 指定時 clientName を書き換え。null なら素通し。
    // When set, rewrite clientName. Pass through if null.
    public string? ClientName { get; set; }

    // true 時 clientDigProductId/clientDir も消去。
    // When true, also erase clientDigProductId/clientDir.
    public bool MaskClientInfo { get; set; }

    // handroll(依存なし) | negotiate(SSPI/gss-ntlmssp)
    // handroll (no dependencies) | negotiate (SSPI/gss-ntlmssp)
    public string CredsspImpl { get; set; } = "handroll";

    public CredentialSetting Credentials { get; set; } = new();

    // 接続元IP許可(CIDR)。空なら全許可。
    // Source-IP allowlist (CIDR). Empty means allow all.
    public string[] Allow { get; set; } = [];

    public MapSetting[] Maps { get; set; } = [];
}
