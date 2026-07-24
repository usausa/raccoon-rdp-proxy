namespace Raccoon.RdpProxy.Diagnostics;

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Raccoon.RdpProxy.Credssp;
using Raccoon.RdpProxy.Helpers;
using Raccoon.RdpProxy.Protocol;

// 指定ホストへバックエンド脚だけ実行して CredSSP 認証を検証するプローブ (mstsc 不要)。
//   --credssp-probe HOST:PORT --user U --password P --domain D [--credssp-impl handroll|negotiate]
internal static class CredSspProbe
{
    public static async Task<int> RunAsync(string[] args)
    {
        var spec = args[1];
        var user = ArgValue(args, "--user") ?? "Administrator";
        var password = ArgValue(args, "--password") ?? string.Empty;
        var domain = ArgValue(args, "--domain") ?? string.Empty;
        var impl = ArgValue(args, "--credssp-impl") ?? "handroll";

        var colon = spec.LastIndexOf(':');
        var host = colon > 0 ? spec[..colon] : spec;
        var port = colon > 0 ? int.Parse(spec[(colon + 1)..], CultureInfo.InvariantCulture) : 3389;

        Console.WriteLine($"CredSSP probe -> {host}:{port}  user={domain}\\{user}  impl={impl}");

        using var tcp = new TcpClient();
        tcp.NoDelay = true;
        try
        {
            await tcp.ConnectAsync(host, port).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or TimeoutException)
        {
            Console.WriteLine($"x TCP connect failed: {e.Message}");
            return 2;
        }

        var ns = tcp.GetStream();
        await ns.WriteAsync(RdpNegotiation.BuildConnectionRequest(RdpConstants.ProtocolHybrid | RdpConstants.ProtocolSsl)).ConfigureAwait(false);
        var cc = await StreamHelper.ReadTpktAsync(ns, default).ConfigureAwait(false);
        if (cc is null)
        {
            Console.WriteLine("x no CC response");
            return 2;
        }

        uint selected;
        try
        {
            (selected, _) = RdpNegotiation.ParseConnectionConfirm(cc);
        }
        catch (RdpNegFailureException nf)
        {
            Console.WriteLine($"x Negotiation Failure: {nf.Message}");
            return 2;
        }

        if (selected != RdpConstants.ProtocolHybrid)
        {
            Console.WriteLine($"! server did not select HYBRID (0x{selected:X}); NLA may be disabled.");
            return 3;
        }

        using var tls = new SslStream(ns, false, static (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.None
        }).ConfigureAwait(false);

        if (tls.RemoteCertificate is not X509Certificate2 sc)
        {
            Console.WriteLine("x could not get server certificate");
            return 2;
        }

        var spki = CredSspKey.FromCertificate(sc);
        var spn = $"TERMSRV/{host}";
        var auth = CredSspAuthFactory.Create(impl, domain, user, password, null, spn);
        try
        {
            var credssp = new CredSspClient(auth, spki, spn, domain, user, password);
            await credssp.RunAsync(tls, Console.WriteLine, default).ConfigureAwait(false);
            Console.WriteLine($"* CredSSP authenticated (impl={impl}) - credentials and implementation OK");
            return 0;
        }
        catch (Exception e) when (e is IOException or AuthenticationException or InvalidOperationException)
        {
            Console.WriteLine($"x CredSSP failed (impl={impl}): {ExceptionHelper.FullMessage(e)}");
            return 1;
        }
        finally
        {
            (auth as IDisposable)?.Dispose();
        }
    }

    private static string? ArgValue(string[] args, string name)
    {
        for (var i = 0; i < (args.Length - 1); i++)
        {
            if (string.Equals(args[i], name, StringComparison.Ordinal))
            {
                return args[i + 1];
            }
        }

        return null;
    }
}
