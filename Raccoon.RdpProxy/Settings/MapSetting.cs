namespace Raccoon.RdpProxy.Settings;

// 受付ポート -> ターゲット の 1 マッピング。source/clientAddress/資格情報/allow を上書き可能。
// One listen-port -> target mapping. source/clientAddress/credentials/allow can be overridden.
internal sealed class MapSetting
{
    public int ListenPort { get; set; }

    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 3389;

    public string? Source { get; set; }

    public string? ClientAddress { get; set; }

    public string? ClientName { get; set; }

    public bool? MaskClientInfo { get; set; }

    public CredentialSetting? Credentials { get; set; }

    public string[]? Allow { get; set; }
}
