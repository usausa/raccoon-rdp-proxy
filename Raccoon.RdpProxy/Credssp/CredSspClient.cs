namespace Raccoon.RdpProxy.Credssp;

using System.Security.Cryptography;
using System.Text;

// ハンドロール CredSSP クライアント (MS-CSSP)。NLA 必須ターゲットへ資格情報を提示する。
internal sealed class CredSspClient
{
    private const int CredSspVersion = 6;

    private readonly ICredSspAuth auth;
    private readonly byte[] serverPublicKey; // サーバ TLS 証明書の PKCS#1 RSAPublicKey
    private readonly string spn;
    private readonly string domain;
    private readonly string user;
    private readonly string password;

    public CredSspClient(ICredSspAuth auth, byte[] serverPublicKey, string spn, string domain, string user, string password)
    {
        this.auth = auth;
        this.serverPublicKey = serverPublicKey;
        this.spn = spn;
        this.domain = domain;
        this.user = user;
        this.password = password;
    }

    public async Task RunAsync(Stream tls, Action<string>? log, CancellationToken ct)
    {
        // 1) NEGOTIATE
        var negotiate = auth.BuildInitialToken();
        await WriteAsync(tls, BuildTsRequest(negoToken: negotiate), ct).ConfigureAwait(false);
        log?.Invoke("CredSSP: NEGOTIATE sent");

        // 2) CHALLENGE
        var t2 = await ReadAsync(tls, ct).ConfigureAwait(false);
        var errEarly = ExtractErrorCode(t2);
        if (errEarly != 0)
        {
            throw new IOException($"CredSSP: server rejected NEGOTIATE errorCode=0x{errEarly:X8}");
        }

        var challenge = ExtractNegoToken(t2)
            ?? throw new IOException(
                $"CredSSP: CHALLENGE missing (response {t2.Length}B: {Convert.ToHexString(t2.AsSpan(0, Math.Min(64, t2.Length)))})");
        log?.Invoke($"CredSSP: CHALLENGE received ({challenge.Length}B)");

        // 3) AUTHENTICATE + pubKeyAuth(client) + clientNonce
        var authenticate = auth.ProcessChallenge(challenge, spn);
        var nonce = RandomNumberGenerator.GetBytes(32);
        var clientHash = BindingHash("CredSSP Client-To-Server Binding Hash\0", nonce, serverPublicKey);
        var pubKeyAuth = auth.Seal(clientHash);
        log?.Invoke($"CredSSP: spki={serverPublicKey.Length}B nonce={Short(nonce)} bindHash={Short(clientHash)} authN={authenticate.Length}B pubKeyAuth={pubKeyAuth.Length}B");
        await WriteAsync(tls, BuildTsRequest(negoToken: authenticate, pubKeyAuth: pubKeyAuth, clientNonce: nonce), ct).ConfigureAwait(false);
        log?.Invoke("CredSSP: AUTHENTICATE + pubKeyAuth sent");

        // 4) サーバ pubKeyAuth 応答
        byte[] t4;
        try
        {
            t4 = await ReadAsync(tls, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or InvalidOperationException)
        {
            throw new IOException(
                "Server closed the connection after AUTHENTICATE. Likely wrong credentials (user/password/domain) or NTLM verification failure: " + e.Message,
                e);
        }

        var err = ExtractErrorCode(t4);
        if (err != 0)
        {
            throw new IOException($"CredSSP: server errorCode=0x{err:X8} (check credentials/settings)");
        }

        var serverPub = ExtractPubKeyAuth(t4);
        if (serverPub is not null)
        {
            var got = auth.Unseal(serverPub);
            var expect = BindingHash("CredSSP Server-To-Client Binding Hash\0", nonce, serverPublicKey);
            log?.Invoke(got.AsSpan().SequenceEqual(expect)
                ? "CredSSP: server pubKeyAuth verified"
                : "CredSSP: warning server pubKeyAuth mismatch (continuing)");
        }

        // 5) TSCredentials(authInfo)
        var creds = BuildTsCredentials(domain, user, password);
        var authInfo = auth.Seal(creds);
        await WriteAsync(tls, BuildTsRequest(authInfo: authInfo), ct).ConfigureAwait(false);
        log?.Invoke("CredSSP: TSCredentials sent");
    }

    // TSRequest 構築
    internal static byte[] BuildTsRequest(
        byte[]? negoToken = null,
        byte[]? authInfo = null,
        byte[]? pubKeyAuth = null,
        byte[]? clientNonce = null)
    {
        var parts = new List<byte[]> { Der.Context(0, Der.Integer(CredSspVersion)) };
        if (negoToken is not null)
        {
            // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
            var item = Der.Sequence(Der.Context(0, Der.OctetString(negoToken)));
            var negoData = Der.Sequence(item);
            parts.Add(Der.Context(1, negoData));
        }

        if (authInfo is not null)
        {
            parts.Add(Der.Context(2, Der.OctetString(authInfo)));
        }

        if (pubKeyAuth is not null)
        {
            parts.Add(Der.Context(3, Der.OctetString(pubKeyAuth)));
        }

        if (clientNonce is not null)
        {
            parts.Add(Der.Context(5, Der.OctetString(clientNonce)));
        }

        return Der.Sequence([.. parts]);
    }

    internal static byte[]? ExtractNegoToken(byte[] tsRequest)
    {
        var (_, cs, cl, _) = Der.ReadTlv(tsRequest, 0); // 外側 SEQUENCE
        var seq = tsRequest.AsSpan(cs, cl);
        var negoData = Der.FindContext(seq, 1); // [1] NegoData
        if (negoData.IsEmpty)
        {
            return null;
        }

        var (_, s1, l1, _) = Der.ReadTlv(negoData, 0); // SEQUENCE OF
        var inner = negoData.Slice(s1, l1);
        var (_, s2, l2, _) = Der.ReadTlv(inner, 0); // NegoDataItem SEQUENCE
        var item = inner.Slice(s2, l2);
        var tok = Der.FindContext(item, 0); // [0] OCTET STRING
        if (tok.IsEmpty)
        {
            return null;
        }

        var (_, s3, l3, _) = Der.ReadTlv(tok, 0);
        return tok.Slice(s3, l3).ToArray();
    }

    internal static byte[]? ExtractPubKeyAuth(byte[] tsRequest)
    {
        var (_, cs, cl, _) = Der.ReadTlv(tsRequest, 0);
        var seq = tsRequest.AsSpan(cs, cl);
        var ctx = Der.FindContext(seq, 3);
        if (ctx.IsEmpty)
        {
            return null;
        }

        var (_, s, l, _) = Der.ReadTlv(ctx, 0); // OCTET STRING
        return ctx.Slice(s, l).ToArray();
    }

    internal static byte[]? ExtractAuthInfo(byte[] tsRequest)
    {
        var (_, cs, cl, _) = Der.ReadTlv(tsRequest, 0);
        var seq = tsRequest.AsSpan(cs, cl);
        var ctx = Der.FindContext(seq, 2);
        if (ctx.IsEmpty)
        {
            return null;
        }

        var (_, s, l, _) = Der.ReadTlv(ctx, 0);
        return ctx.Slice(s, l).ToArray();
    }

    internal static int ExtractErrorCode(byte[] tsRequest)
    {
        var (_, cs, cl, _) = Der.ReadTlv(tsRequest, 0);
        var seq = tsRequest.AsSpan(cs, cl);
        var ctx = Der.FindContext(seq, 4);
        if (ctx.IsEmpty)
        {
            return 0;
        }

        var (_, s, l, _) = Der.ReadTlv(ctx, 0); // INTEGER
        var v = 0;
        for (var k = 0; k < l; k++)
        {
            v = (v << 8) | ctx[s + k];
        }

        return v;
    }

    // TSCredentials{ credType=1, credentials=DER(TSPasswordCreds{domain,user,password}) }
    internal static byte[] BuildTsCredentials(string domain, string user, string password)
    {
        var pw = Der.Sequence(
            Der.Context(0, Der.OctetString(Encoding.Unicode.GetBytes(domain))),
            Der.Context(1, Der.OctetString(Encoding.Unicode.GetBytes(user))),
            Der.Context(2, Der.OctetString(Encoding.Unicode.GetBytes(password))));
        return Der.Sequence(
            Der.Context(0, Der.Integer(1)),
            Der.Context(1, Der.OctetString(pw)));
    }

    private static string Short(byte[] b) =>
        Convert.ToHexString(b.AsSpan(0, Math.Min(8, b.Length))).ToLowerInvariant();

    private static byte[] BindingHash(string magicWithNul, byte[] nonce, byte[] publicKey)
    {
        var magic = Encoding.ASCII.GetBytes(magicWithNul);
        var buf = new byte[magic.Length + nonce.Length + publicKey.Length];
        magic.CopyTo(buf, 0);
        nonce.CopyTo(buf, magic.Length);
        publicKey.CopyTo(buf, magic.Length + nonce.Length);
        return SHA256.HashData(buf);
    }

    private static Task<byte[]> ReadAsync(Stream s, CancellationToken ct) => Der.ReadObjectAsync(s, ct);

    private static Task WriteAsync(Stream s, byte[] data, CancellationToken ct) => s.WriteAsync(data, ct).AsTask();
}
