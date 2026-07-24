namespace Raccoon.RdpProxy;

using System.Runtime;

internal static partial class Log
{
    // Startup

    [LoggerMessage(Level = LogLevel.Information, Message = "Service start.")]
    public static partial void InfoServiceStart(this ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Environment: version=[{version}], runtime=[{runtime}], directory=[{directory}]")]
    public static partial void InfoServiceEnvironment(this ILogger logger, Version? version, Version runtime, string directory);

    [LoggerMessage(Level = LogLevel.Information, Message = "GCSettings: serverGC=[{isServerGC}], latencyMode=[{latencyMode}], largeObjectHeapCompactionMode=[{largeObjectHeapCompactionMode}]")]
    public static partial void InfoServiceGC(this ILogger logger, bool isServerGC, GCLatencyMode latencyMode, GCLargeObjectHeapCompactionMode largeObjectHeapCompactionMode);

    [LoggerMessage(Level = LogLevel.Information, Message = "Certificate loaded: {path}")]
    public static partial void InfoCertificateLoaded(this ILogger logger, string path);

    [LoggerMessage(Level = LogLevel.Information, Message = "Certificate created (10y): {path}")]
    public static partial void InfoCertificateCreated(this ILogger logger, string path);

    [LoggerMessage(Level = LogLevel.Information, Message = "Certificate: subject=[{subject}], notAfter=[{notAfter:yyyy-MM-dd}]")]
    public static partial void InfoCertificate(this ILogger logger, string subject, DateTime notAfter);

    [LoggerMessage(Level = LogLevel.Information, Message = "Map {listen}:{listenPort} -> {host}:{port} src={source} clientAddr={clientAddress} domain={domain} user={user} allow={allow}")]
    public static partial void InfoMap(this ILogger logger, string listen, int listenPort, string host, int port, string source, string clientAddress, string domain, string user, string allow);

    // Listener / connection

    [LoggerMessage(Level = LogLevel.Error, Message = "Listen failed on port {port}.")]
    public static partial void ErrorListenFailed(this ILogger logger, int port, Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "Invalid allow configuration for port {port}; the map is not started.")]
    public static partial void ErrorAllowConfig(this ILogger logger, int port, Exception ex);

    [LoggerMessage(Level = LogLevel.Information, Message = "[{peer}] connection rejected (not in allow list).")]
    public static partial void InfoConnectionRejected(this ILogger logger, string peer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] CR requestedProtocols=0x{requested:X}")]
    public static partial void DebugConnectionRequest(this ILogger logger, string peer, uint requested);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] TLS established (client={clientProtocol}, backend={backendProtocol})")]
    public static partial void DebugTlsEstablished(this ILogger logger, string peer, object clientProtocol, object backendProtocol);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] target {dest} returned no CC.")]
    public static partial void WarnNoConnectionConfirm(this ILogger logger, string peer, string dest);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] target {dest} rejected the connection: {reason}")]
    public static partial void WarnTargetRejected(this ILogger logger, string peer, string dest, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] target {dest} selected an unsupported protocol (0x{selected:X}).")]
    public static partial void WarnUnsupportedProtocol(this ILogger logger, string peer, string dest, uint selected);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] target {dest} requires NLA but no credentials are configured.")]
    public static partial void WarnNlaRequiredNoCredentials(this ILogger logger, string peer, string dest);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] backend certificate unavailable; CredSSP is not possible.")]
    public static partial void WarnBackendCertificateMissing(this ILogger logger, string peer);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] CredSSP failed ({dest}, impl={impl}): {error}")]
    public static partial void WarnCredSspFailed(this ILogger logger, string peer, string dest, string impl, string error);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] CredSSP authenticated (domain={domain} user={user}, impl={impl}).")]
    public static partial void DebugCredSspAuthenticated(this ILogger logger, string peer, string domain, string user, string impl);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] CredSSP: {message}")]
    public static partial void DebugCredSspStep(this ILogger logger, string peer, string message);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] serverSelectedProtocol rewritten SSL -> 0x{backendProtocol:X} (MCS Connect Initial).")]
    public static partial void DebugServerSelectedProtocolRewritten(this ILogger logger, string peer, uint backendProtocol);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] clientRequestedProtocols rewritten 0x{from:X} -> 0x{to:X} (MCS Connect Response).")]
    public static partial void DebugClientRequestedProtocolsRewritten(this ILogger logger, string peer, uint from, uint to);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] clientAddress rewritten {from} -> {to} (maskClientInfo={mask}).")]
    public static partial void DebugClientAddressRewritten(this ILogger logger, string peer, string from, string to, bool mask);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] client identity rewritten in MCS Connect Initial ({detail}).")]
    public static partial void DebugClientIdentityRewritten(this ILogger logger, string peer, string detail);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] Client Info PDU parse failed; forwarding as-is: {error}")]
    public static partial void WarnClientInfoParseFailed(this ILogger logger, string peer, string error);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{peer}] disconnected ({dest}).")]
    public static partial void DebugDisconnected(this ILogger logger, string peer, string dest);

    [LoggerMessage(Level = LogLevel.Warning, Message = "[{peer}] error ({dest}): {error}")]
    public static partial void WarnConnectionError(this ILogger logger, string peer, string dest, string error);
}
