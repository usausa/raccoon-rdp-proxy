namespace Raccoon.RdpProxy.Server;

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Options;

using Raccoon.RdpProxy.Credssp;
using Raccoon.RdpProxy.Helpers;
using Raccoon.RdpProxy.Protocol;
using Raccoon.RdpProxy.Security;
using Raccoon.RdpProxy.Settings;

// RDP 中継の本体。map ごとにリスナーを張り、TLS を両脚で終端して clientAddress 等を書き換える。
// Core of the RDP relay. Opens a listener per map, terminates TLS on both legs, and rewrites clientAddress and friends.
internal sealed class RdpProxyService : BackgroundService
{
    private const int MaxFrame = 64 * 1024;

    private readonly ProxySetting settings;
    private readonly ILogger<RdpProxyService> logger;

    private X509Certificate2? certificate;

    public RdpProxyService(IOptions<ProxySetting> settings, ILogger<RdpProxyService> logger)
    {
        this.settings = settings.Value;
        this.logger = logger;
    }

    public override void Dispose()
    {
        certificate?.Dispose();
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var cert = CertificateFactory.LoadOrCreate(settings.Cert, settings.CertPassword, out var certResult);
        certificate = cert;
        if (certResult.Path is not null)
        {
            if (certResult.Created)
            {
                logger.InfoCertificateCreated(certResult.Path);
            }
            else
            {
                logger.InfoCertificateLoaded(certResult.Path);
            }
        }

        logger.InfoCertificate(cert.Subject, cert.NotAfter);

        var listeners = new List<Task>();
        foreach (var map in settings.Maps)
        {
            var cred = map.Credentials ?? settings.Credentials;
            var allow = map.Allow ?? settings.Allow;
            logger.InfoMap(
                settings.Listen,
                map.ListenPort,
                map.Host,
                map.Port,
                map.Source ?? settings.Source ?? "(default)",
                map.ClientAddress ?? settings.ClientAddress,
                cred.Domain,
                cred.User,
                allow.Length == 0 ? "(all)" : String.Join(",", allow));
            listeners.Add(RunListenerAsync(map, cert, stoppingToken));
        }

        try
        {
            await Task.WhenAll(listeners).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // stopping
        }
    }

    private static void ConfigureSocket(Socket s)
    {
        try
        {
            s.NoDelay = true;
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 30);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 10);
            s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 5);
        }
        catch (SocketException)
        {
            // プラットフォーム差は無視
            // Ignore platform differences.
        }
    }

    private static bool IsExpectedConnectionError(Exception ex) =>
        ex is IOException or SocketException or AuthenticationException or InvalidDataException
            or FormatException or ObjectDisposedException or NotSupportedException;

    private async Task RunListenerAsync(MapSetting map, X509Certificate2 cert, CancellationToken ct)
    {
        IpAcl acl;
        try
        {
            acl = IpAcl.Parse(map.Allow ?? settings.Allow);
        }
        catch (ArgumentException e)
        {
            logger.ErrorAllowConfig(map.ListenPort, e);
            return;
        }

        using var listener = new TcpListener(IPAddress.Parse(settings.Listen), map.ListenPort);
        try
        {
            listener.Start();
        }
        catch (SocketException e)
        {
            logger.ErrorListenFailed(map.ListenPort, e);
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            _ = HandleConnectionAsync(client, map, cert, acl, ct);
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, MapSetting map, X509Certificate2 cert, IpAcl acl, CancellationToken ct)
    {
        var peer = client.Client.RemoteEndPoint?.ToString() ?? "?";
        var dest = $"{map.Host}:{map.Port}";
        var clientIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address;

        var source = map.Source ?? settings.Source;
        var clientAddress = map.ClientAddress ?? settings.ClientAddress;
        var clientName = map.ClientName ?? settings.ClientName;
        var maskClientInfo = map.MaskClientInfo ?? settings.MaskClientInfo;
        var cred = map.Credentials ?? settings.Credentials;
        var useCredSsp = !String.IsNullOrEmpty(cred.Password) || !String.IsNullOrEmpty(cred.NtHash);

        using (client)
        {
            if (!acl.IsAllowed(clientIp))
            {
                logger.InfoConnectionRejected(peer);
                return;
            }

            ConfigureSocket(client.Client);
            TcpClient? backend = null;
            try
            {
                var cs = client.GetStream();

                var cr = await StreamHelper.ReadTpktAsync(cs, ct).ConfigureAwait(false);
                if (cr is null)
                {
                    return;
                }

                var requested = RdpNegotiation.ParseRequestedProtocols(cr);
                logger.DebugConnectionRequest(peer, requested);

                backend = new TcpClient(AddressFamily.InterNetwork);
                ConfigureSocket(backend.Client);
                if (source is not null)
                {
                    backend.Client.Bind(new IPEndPoint(IPAddress.Parse(source), 0));
                }

                using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    connectCts.CancelAfter(TimeSpan.FromSeconds(10));
                    await backend.Client.ConnectAsync(IPAddress.Parse(map.Host), map.Port, connectCts.Token).ConfigureAwait(false);
                }

                var bs = backend.GetStream();

                var backendReq = useCredSsp ? (RdpConstants.ProtocolHybrid | RdpConstants.ProtocolSsl) : RdpConstants.ProtocolSsl;
                await bs.WriteAsync(RdpNegotiation.BuildConnectionRequest(backendReq), ct).ConfigureAwait(false);

                var cc = await StreamHelper.ReadTpktAsync(bs, ct).ConfigureAwait(false);
                if (cc is null)
                {
                    logger.WarnNoConnectionConfirm(peer, dest);
                    return;
                }

                uint selected;
                try
                {
                    (selected, _) = RdpNegotiation.ParseConnectionConfirm(cc);
                }
                catch (RdpNegFailureException nf)
                {
                    logger.WarnTargetRejected(peer, dest, nf.Message);
                    return;
                }

                if (selected is not (RdpConstants.ProtocolSsl or RdpConstants.ProtocolHybrid))
                {
                    logger.WarnUnsupportedProtocol(peer, dest, selected);
                    return;
                }

                if ((selected == RdpConstants.ProtocolHybrid) && !useCredSsp)
                {
                    logger.WarnNlaRequiredNoCredentials(peer, dest);
                    return;
                }

                await cs.WriteAsync(RdpNegotiation.BuildConnectionConfirm(RdpConstants.ProtocolSsl, 0), ct).ConfigureAwait(false);

                await using var sslClient = new SslStream(cs, leaveInnerStreamOpen: false);
                await using var sslBackend = new SslStream(bs, leaveInnerStreamOpen: false, userCertificateValidationCallback: static (_, _, _, _) => true);
                var serverOpts = new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.None
                };
                var clientOpts = new SslClientAuthenticationOptions
                {
                    TargetHost = map.Host,
                    EnabledSslProtocols = SslProtocols.None
                };
                await Task.WhenAll(
                    sslClient.AuthenticateAsServerAsync(serverOpts, ct),
                    sslBackend.AuthenticateAsClientAsync(clientOpts, ct)).ConfigureAwait(false);
                logger.DebugTlsEstablished(peer, sslClient.SslProtocol, sslBackend.SslProtocol);

                if (selected == RdpConstants.ProtocolHybrid)
                {
                    if (sslBackend.RemoteCertificate is not X509Certificate2 srvCert)
                    {
                        logger.WarnBackendCertificateMissing(peer);
                        return;
                    }

                    var spki = CredSspKey.FromCertificate(srvCert);
                    var spn = $"TERMSRV/{map.Host}";
                    var auth = CredSspAuthFactory.Create(settings.CredsspImpl, cred.Domain, cred.User, cred.Password, cred.NtHash, spn);
                    try
                    {
                        var credssp = new CredSspClient(auth, spki, spn, cred.Domain, cred.User, cred.Password);
                        await credssp.RunAsync(sslBackend, m => logger.DebugCredSspStep(peer, m), ct).ConfigureAwait(false);
                    }
                    catch (Exception e) when (IsExpectedConnectionError(e))
                    {
                        logger.WarnCredSspFailed(peer, dest, settings.CredsspImpl, ExceptionHelper.FullMessage(e));
                        return;
                    }
                    finally
                    {
                        (auth as IDisposable)?.Dispose();
                    }

                    logger.DebugCredSspAuthenticated(peer, cred.Domain, cred.User, settings.CredsspImpl);
                }

                await RelayAsync(peer, sslClient, sslBackend, clientAddress, clientName, maskClientInfo, selected, requested, backendReq, ct).ConfigureAwait(false);
                logger.DebugDisconnected(peer, dest);
            }
            catch (OperationCanceledException)
            {
                // stopping / peer closed
            }
            catch (Exception e) when (IsExpectedConnectionError(e))
            {
                logger.WarnConnectionError(peer, dest, ExceptionHelper.FullMessage(e));
            }
            finally
            {
                backend?.Dispose();
            }
        }
    }

    private async Task RelayAsync(
        string peer,
        SslStream client,
        SslStream backend,
        string clientAddress,
        string? clientName,
        bool maskClientInfo,
        uint backendSelected,
        uint clientRequested,
        uint backendRequested,
        CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var ctob = PumpClientToBackendAsync(peer, client, backend, clientAddress, clientName, maskClientInfo, backendSelected, linked.Token);
        var btoc = PumpBackendToClientAsync(peer, backend, client, clientRequested, backendRequested, linked.Token);
        await Task.WhenAny(ctob, btoc).ConfigureAwait(false);
        await linked.CancelAsync().ConfigureAwait(false);
        try
        {
            await Task.WhenAll(ctob, btoc).ConfigureAwait(false);
        }
        catch (Exception e) when (IsExpectedConnectionError(e) || (e is OperationCanceledException))
        {
            // 相手側の切断は無視
            // Ignore a disconnect on the peer side.
        }
    }

    // backend -> client: 最初の PDU(MCS Connect Response) の clientRequestedProtocols を書き換え、以降は生転送。
    // backend -> client: rewrite clientRequestedProtocols in the first PDU (MCS Connect Response), then relay raw.
    private async Task PumpBackendToClientAsync(string peer, SslStream backend, SslStream client, uint clientRequested, uint backendRequested, CancellationToken ct)
    {
        var hdr = new byte[4];
        if (!await StreamHelper.ReadFullAsync(backend, hdr, 0, 4, ct).ConfigureAwait(false))
        {
            return;
        }

        var len = (hdr[2] << 8) | hdr[3];
        if ((hdr[0] != 0x03) || (len < 4) || (len > MaxFrame))
        {
            await client.WriteAsync(hdr.AsMemory(0, 4), ct).ConfigureAwait(false);
        }
        else
        {
            var buf = ArrayPool<byte>.Shared.Rent(len);
            try
            {
                hdr.AsSpan(0, 4).CopyTo(buf);
                if (!await StreamHelper.ReadFullAsync(backend, buf, 4, len - 4, ct).ConfigureAwait(false))
                {
                    await client.WriteAsync(buf.AsMemory(0, 4), ct).ConfigureAwait(false);
                    return;
                }

                if ((backendRequested != clientRequested) &&
                    McsConnectResponse.PatchClientRequestedProtocols(buf.AsSpan(0, len), backendRequested, clientRequested))
                {
                    logger.DebugClientRequestedProtocolsRewritten(peer, backendRequested, clientRequested);
                }

                await client.WriteAsync(buf.AsMemory(0, len), ct).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        await CopyAsync(backend, client, ct).ConfigureAwait(false);
    }

    // client -> backend: Client Info PDU を見つけるまでフレーミングし、書き換え後は生転送に降格。
    // client -> backend: keep framing until the Client Info PDU is found, then fall back to raw relay after rewriting.
    private async Task PumpClientToBackendAsync(string peer, SslStream client, SslStream backend, string clientAddress, string? clientName, bool maskClientInfo, uint backendProto, CancellationToken ct)
    {
        var hdr = new byte[4];
        var handled = false;
        var mcsPatched = false;
        while (!handled && !ct.IsCancellationRequested)
        {
            if (!await StreamHelper.ReadFullAsync(client, hdr, 0, 4, ct).ConfigureAwait(false))
            {
                return;
            }

            var len = (hdr[2] << 8) | hdr[3];
            if ((hdr[0] != 0x03) || (len < 4) || (len > MaxFrame))
            {
                await backend.WriteAsync(hdr.AsMemory(0, 4), ct).ConfigureAwait(false);
                break;
            }

            var buf = ArrayPool<byte>.Shared.Rent(len);
            try
            {
                hdr.AsSpan(0, 4).CopyTo(buf);
                if (!await StreamHelper.ReadFullAsync(client, buf, 4, len - 4, ct).ConfigureAwait(false))
                {
                    await backend.WriteAsync(buf.AsMemory(0, 4), ct).ConfigureAwait(false);
                    return;
                }

                byte[]? mod = null;
                try
                {
                    mod = ClientInfoRewriter.TryRewrite(buf.AsSpan(0, len), clientAddress, maskClientInfo, out var old);
                    if (mod is not null)
                    {
                        handled = true;
                        logger.DebugClientAddressRewritten(peer, old ?? "(empty)", clientAddress, maskClientInfo);
                    }
                }
                catch (InvalidDataException e)
                {
                    handled = true; // Info PDU だが解析失敗 → 原文転送して以降は生転送 / Info PDU but parsing failed -> forward as-is and relay raw from here on
                    logger.WarnClientInfoParseFailed(peer, e.Message);
                }

                if (mod is not null)
                {
                    await backend.WriteAsync(mod, ct).ConfigureAwait(false);
                }
                else
                {
                    if (!mcsPatched)
                    {
                        mcsPatched = TryPatchMcsConnectInitial(peer, buf.AsSpan(0, len), backendProto, clientName, maskClientInfo);
                    }

                    await backend.WriteAsync(buf.AsMemory(0, len), ct).ConfigureAwait(false);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        await CopyAsync(client, backend, ct).ConfigureAwait(false);
    }

    private bool TryPatchMcsConnectInitial(string peer, Span<byte> pdu, uint backendProto, string? clientName, bool maskClientInfo)
    {
        var did = false;
        if ((backendProto != RdpConstants.ProtocolSsl) &&
            McsConnectInitial.PatchServerSelectedProtocol(pdu, RdpConstants.ProtocolSsl, backendProto))
        {
            did = true;
            logger.DebugServerSelectedProtocolRewritten(peer, backendProto);
        }

        if (((clientName is not null) || maskClientInfo) &&
            McsConnectInitial.PatchClientIdentity(pdu, clientName, maskClientInfo))
        {
            did = true;
            var detail = clientName is not null
                ? (maskClientInfo ? $"clientName=\"{clientName}\"+productId" : $"clientName=\"{clientName}\"")
                : "productId";
            logger.DebugClientIdentityRewritten(peer, detail);
        }

        return did;
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buf = ArrayPool<byte>.Shared.Rent(1 << 16); // 64KiB
        try
        {
            int n;
            while ((n = await from.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
            {
                await to.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (IsExpectedConnectionError(e) || (e is OperationCanceledException))
        {
            // 相手側の切断
            // Disconnect on the peer side.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }
}
