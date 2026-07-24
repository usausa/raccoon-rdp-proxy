using System.Runtime;

using Microsoft.Extensions.Hosting.Systemd;
using Microsoft.Extensions.Hosting.WindowsServices;

using Raccoon.RdpProxy;
using Raccoon.RdpProxy.Diagnostics;
using Raccoon.RdpProxy.Helpers;
using Raccoon.RdpProxy.Server;
using Raccoon.RdpProxy.Settings;

using Serilog;
using Serilog.Settings.Configuration;

// サービス(Windows/systemd)として起動された場合は作業ディレクトリが System32 や / になり得るため、
// 設定(appsettings.json)/証明書/ログを実行ファイルの隣で解決できるようカレントを固定する。
// コンテナ/対話実行では作業ディレクトリを尊重し、WORKDIR や cd で設定を差し込めるようにする。
// When started as a service (Windows/systemd) the working directory can be System32 or /, so pin
// the current directory to the executable so config (appsettings.json)/certificate/logs resolve next to it.
// For containers/interactive runs the working directory is respected, so WORKDIR or cd can inject config.
if (WindowsServiceHelpers.IsWindowsService() || SystemdHelpers.IsSystemdService())
{
    Directory.SetCurrentDirectory(AppContext.BaseDirectory);
}

// CLI ユーティリティ/診断モード (ホストを立てずに実行して終了)。
// CLI utility/diagnostic modes (run without starting the host, then exit).
if (args.Length > 0)
{
    switch (args[0])
    {
        case "--selftest":
            return SelfTestRunner.RunAll();
        case "--e2etest":
            return await E2ETest.RunAsync().ConfigureAwait(false);
        case "--make-cert" when args.Length >= 2:
            return MakeCert(args[1]);
        case "--credssp-probe" when args.Length >= 2:
            return await CredSspProbe.RunAsync(args).ConfigureAwait(false);
    }
}

var builder = Host.CreateApplicationBuilder(args);

// Service (Windows / systemd)
builder.Services
    .AddWindowsService(static options => options.ServiceName = "Raccoon.RdpProxy")
    .AddSystemd();

// Logging (Serilog, appsettings.json の "Serilog" セクション)
// Logging (Serilog, the "Serilog" section of appsettings.json)
builder.Logging.ClearProviders();
builder.Services.AddSerilog(options =>
{
    options.ReadFrom.Configuration(
        builder.Configuration,
        new ConfigurationReaderOptions(
            typeof(ConsoleLoggerConfigurationExtensions).Assembly,
            typeof(FileLoggerConfigurationExtensions).Assembly));
});

// Options
builder.Services.AddOptions<ProxySetting>()
    .Bind(builder.Configuration.GetSection(ProxySetting.SectionName))
    .Validate(static o => IPAddress.TryParse(o.Listen, out _), "Proxy:Listen must be a valid IP address.")
    .Validate(static o => o.Maps.Length > 0, "Proxy:Maps must contain at least one entry.")
    .Validate(static o => Array.TrueForAll(o.Maps, static m => (m.ListenPort is >= 1 and <= 65535) && (m.Port is >= 1 and <= 65535) && !string.IsNullOrEmpty(m.Host)), "Proxy:Maps entries must have a host and valid ports.")
    .ValidateOnStart();

// Service
builder.Services.AddHostedService<RdpProxyService>();

var host = builder.Build();

var log = host.Services.GetRequiredService<ILogger<Program>>();
log.InfoServiceStart();
log.InfoServiceEnvironment(typeof(Program).Assembly.GetName().Version, Environment.Version, Environment.CurrentDirectory);
log.InfoServiceGC(GCSettings.IsServerGC, GCSettings.LatencyMode, GCSettings.LargeObjectHeapCompactionMode);

await host.RunAsync().ConfigureAwait(false);
return 0;

static int MakeCert(string pfxPath)
{
    try
    {
        using var cert = CertificateFactory.MakeFile(pfxPath, out var cerPath);
        Console.WriteLine($"PFX written: {pfxPath}");
        Console.WriteLine($"CER written: {cerPath}");
        Console.WriteLine($"Valid {cert.NotBefore:yyyy-MM-dd} - {cert.NotAfter:yyyy-MM-dd}");
        return 0;
    }
    catch (Exception e) when (e is IOException or System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"Certificate error: {e.Message}");
        return 3;
    }
}
