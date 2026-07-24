namespace Raccoon.RdpProxy.Diagnostics;

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using Raccoon.RdpProxy.Helpers;
using Raccoon.RdpProxy.Protocol;
using Raccoon.RdpProxy.Server;
using Raccoon.RdpProxy.Settings;

// 疑似クライアント -> プロキシ(実サービス) -> 疑似バックエンド を流し、
// バックエンドが受け取った Client Info PDU の clientAddress が書き換わっているか確認する。
// Drives fake client -> proxy (real service) -> fake backend, and verifies that the clientAddress
// in the Client Info PDU received by the backend has been rewritten.
internal static class E2eTest
{
    public static async Task<int> RunAsync()
    {
        const string writeAddr = "10.13.8.100";
        const string clientOrigAddr = "192.168.10.11";

        using var cert = CertificateFactory.LoadOrCreate(null, null, out _);

        using var backendListener = new TcpListener(IPAddress.Loopback, 0);
        backendListener.Start();
        var backendPort = ((IPEndPoint)backendListener.LocalEndpoint).Port;
        string? seen = null;
        var backendDone = new TaskCompletionSource();
        var backendTask = FakeBackendAsync(backendListener, cert, a =>
        {
            seen = a;
            backendDone.TrySetResult();
        });

        var proxyPort = GetFreePort();
        var setting = new ProxySetting
        {
            Listen = "127.0.0.1",
            ClientAddress = writeAddr,
            Source = null,
            Maps = [new MapSetting { ListenPort = proxyPort, Host = "127.0.0.1", Port = backendPort }]
        };

        using var service = new RdpProxyService(Options.Create(setting), NullLogger<RdpProxyService>.Instance);
        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token).ConfigureAwait(false);
        await Task.Delay(300, cts.Token).ConfigureAwait(false);

        Exception? clientError = null;
        try
        {
            await FakeClientAsync(proxyPort, clientOrigAddr).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or AuthenticationException)
        {
            clientError = e;
        }

        var finished = await Task.WhenAny(backendDone.Task, Task.Delay(5000, cts.Token)).ConfigureAwait(false);
        await cts.CancelAsync().ConfigureAwait(false);
        await service.StopAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            await backendTask.ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or SocketException or AuthenticationException or OperationCanceledException)
        {
            // ignore
        }

        Console.WriteLine();
        if (clientError is not null)
        {
            Console.WriteLine($"  [FAIL] fake client error: {clientError.Message}");
            return 1;
        }

        if (finished != backendDone.Task)
        {
            Console.WriteLine("  [FAIL] backend did not receive the Client Info PDU (timeout)");
            return 1;
        }

        Console.WriteLine($"  client sent clientAddress : {clientOrigAddr}");
        Console.WriteLine($"  backend saw clientAddress : {seen}");
        if (seen == writeAddr)
        {
            Console.WriteLine($"E2ETEST: PASSED (rewrite {clientOrigAddr} -> {writeAddr})");
            return 0;
        }

        Console.WriteLine($"E2ETEST: FAILED (expected {writeAddr}, got {seen})");
        return 1;
    }

    private static async Task FakeBackendAsync(TcpListener l, X509Certificate2 cert, Action<string> onAddr)
    {
        using var c = await l.AcceptTcpClientAsync().ConfigureAwait(false);
        c.NoDelay = true;
        var ns = c.GetStream();

        var cr = await StreamHelper.ReadTpktAsync(ns, default).ConfigureAwait(false);
        if (cr is null)
        {
            return;
        }

        await ns.WriteAsync(RdpNegotiation.BuildConnectionConfirm(RdpConstants.ProtocolSsl, 0)).ConfigureAwait(false);

        using var ssl = new SslStream(ns, false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = cert,
            EnabledSslProtocols = SslProtocols.None
        }).ConfigureAwait(false);

        var info = await StreamHelper.ReadTpktAsync(ssl, default).ConfigureAwait(false);
        if (info is null)
        {
            return;
        }

        ClientInfoRewriter.TryRewrite(info, "PARSE-ONLY", false, out var addr);
        onAddr(addr ?? "(none)");
    }

    private static async Task FakeClientAsync(int proxyPort, string clientAddr)
    {
        using var c = new TcpClient();
        c.NoDelay = true;
        await c.ConnectAsync(IPAddress.Loopback, proxyPort).ConfigureAwait(false);
        var ns = c.GetStream();

        await ns.WriteAsync(RdpNegotiation.BuildConnectionRequest(RdpConstants.ProtocolSsl | RdpConstants.ProtocolHybrid)).ConfigureAwait(false);
        var cc = await StreamHelper.ReadTpktAsync(ns, default).ConfigureAwait(false);
        if (cc is null)
        {
            throw new IOException("no CC received");
        }

        await using var ssl = new SslStream(ns, false, static (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "rdp-proxy",
            EnabledSslProtocols = SslProtocols.None
        }).ConfigureAwait(false);

        var pdu = SelfTestRunner.BuildClientInfoPduForTest(clientAddr);
        await ssl.WriteAsync(pdu).ConfigureAwait(false);
        await ssl.FlushAsync().ConfigureAwait(false);
        await Task.Delay(300).ConfigureAwait(false);
    }

    private static int GetFreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
