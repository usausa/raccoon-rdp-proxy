namespace Raccoon.RdpProxy.Ntlm;

using System.Security.Cryptography;
using System.Text;

using Raccoon.RdpProxy.Credssp;

// NTLMv2 / NTLM2 session security をハンドロール実装 (MS-NLMP)。外部依存なし。
// NEGOTIATE→CHALLENGE→AUTHENTICATE を生成し、確立後は Seal/Unseal を提供する。
// Hand-rolled implementation of NTLMv2 / NTLM2 session security (MS-NLMP). No external dependencies.
// Builds NEGOTIATE -> CHALLENGE -> AUTHENTICATE, and provides Seal/Unseal once established.
internal sealed class NtlmClientAuth : ICredSspAuth
{
    private readonly string domain;
    private readonly string user;
    private readonly string password;
    private readonly string workstation;
    private readonly byte[]? ntHash; // 事前計算した NT ハッシュ(MD4(pw)) を使う場合 / used when a pre-computed NT hash (MD4(pw)) is supplied

    private byte[] negotiateMsg = [];
    private Rc4? clientSeal;
    private Rc4? serverSeal;
    private byte[] clientSignKey = [];
    private uint clientSeq;
    private int micOffset;

    public NtlmClientAuth(string domain, string user, string password, string workstation = "RDPPROXY", byte[]? ntHash = null)
    {
        this.domain = domain;
        this.user = user;
        this.password = password;
        this.workstation = workstation;
        this.ntHash = ntHash;
    }

    public byte[] ExportedSessionKey { get; private set; } = [];

    public byte[] BuildInitialToken() => BuildNegotiate();

    public byte[] ProcessChallenge(byte[] challenge, string spn) => ProcessChallengeAndBuildAuthenticate(challenge, spn);

    // Type 1: NEGOTIATE_MESSAGE。Signature(8)+Type(4)+Flags(4)+DomainFields(8)+WorkstationFields(8)+Version(8)=40。
    public byte[] BuildNegotiate()
    {
        var flags = NtlmFlags.Unicode | NtlmFlags.RequestTarget | NtlmFlags.Ntlm |
                    NtlmFlags.AlwaysSign | NtlmFlags.ExtendedSessionSecurity |
                    NtlmFlags.Sign | NtlmFlags.Seal | NtlmFlags.KeyExchange |
                    NtlmFlags.Negotiate128 | NtlmFlags.Negotiate56 | NtlmFlags.Version;
        var m = new byte[40];
        "NTLMSSP\0"u8.ToArray().CopyTo(m, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(8), 1); // MessageType = 1
        BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(12), (uint)flags);

        // DomainNameFields(16-23)=0, WorkstationFields(24-31)=0
        WriteVersion(m.AsSpan(32)); // Version は offset 32 / Version is at offset 32
        negotiateMsg = m;
        return m;
    }

    // Type 3: AUTHENTICATE を生成 (spn は例 "TERMSRV/192.168.50.31")。
    // Type 3: build AUTHENTICATE (spn example: "TERMSRV/192.168.50.31").
    public byte[] ProcessChallengeAndBuildAuthenticate(byte[] challengeMsg, string spn)
    {
        var ch = ParseChallenge(challengeMsg);
        var ntowf = NtowfV2();

        var clientChallenge = RandomNumberGenerator.GetBytes(8);
        var ts = ExtractTimestamp(ch.TargetInfo); // サーバ提示の時刻があれば使う / use the timestamp the server supplied, if any

        // AUTHENTICATE 用 target info = サーバの AV pairs をコピーし、MIC フラグ(0x02)と SPN を付与
        // target info for AUTHENTICATE = copy of the server AV pairs plus the MIC flag (0x02) and the SPN.
        var targetInfo = AugmentTargetInfo(ch.TargetInfo, spn);

        // temp blob
        var temp = new List<byte> { 0x01, 0x01, 0, 0, 0, 0, 0, 0 };
        var t8 = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(t8, ts);
        temp.AddRange(t8);
        temp.AddRange(clientChallenge);
        temp.AddRange([0, 0, 0, 0]);
        temp.AddRange(targetInfo);
        temp.AddRange([0, 0, 0, 0]);

        // NTProofStr
        byte[] proof;
        using (var h = new HMACMD5(ntowf))
        {
            var buf = new byte[8 + temp.Count];
            ch.ServerChallenge.CopyTo(buf, 0);
            temp.CopyTo(buf, 8);
            proof = h.ComputeHash(buf);
        }

        var ntResponse = new byte[proof.Length + temp.Count];
        proof.CopyTo(ntResponse, 0);
        temp.CopyTo(ntResponse, proof.Length);

        // SessionBaseKey / ExportedSessionKey
        byte[] sessionBaseKey;
        using (var h = new HMACMD5(ntowf))
        {
            sessionBaseKey = h.ComputeHash(proof);
        }

        var keyExchangeKey = sessionBaseKey; // NTLMv2
        var keyExch = (ch.Flags & NtlmFlags.KeyExchange) != 0;
        byte[] encryptedRandomSessionKey;
        if (keyExch)
        {
            ExportedSessionKey = RandomNumberGenerator.GetBytes(16);
            encryptedRandomSessionKey = Rc4.Encrypt(keyExchangeKey, ExportedSessionKey);
        }
        else
        {
            ExportedSessionKey = keyExchangeKey;
            encryptedRandomSessionKey = [];
        }

        // 使用フラグ (challenge をベースに必要ビットを立てる)
        // Flags in use (start from the challenge and set the required bits).
        var useFlags = NtlmFlags.Unicode | NtlmFlags.Ntlm | NtlmFlags.ExtendedSessionSecurity |
                       NtlmFlags.Sign | NtlmFlags.Seal | NtlmFlags.AlwaysSign |
                       NtlmFlags.Negotiate128 | NtlmFlags.Negotiate56 | NtlmFlags.Version | NtlmFlags.TargetInfo;
        if (keyExch)
        {
            useFlags |= NtlmFlags.KeyExchange;
        }

        var auth = AssembleAuthenticate(domain, user, workstation, new byte[24], ntResponse, encryptedRandomSessionKey, useFlags);

        // MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE(MIC=0))
        byte[] mic;
        using (var h = new HMACMD5(ExportedSessionKey))
        {
            var all = new byte[negotiateMsg.Length + challengeMsg.Length + auth.Length];
            negotiateMsg.CopyTo(all, 0);
            challengeMsg.CopyTo(all, negotiateMsg.Length);
            auth.CopyTo(all, negotiateMsg.Length + challengeMsg.Length);
            mic = h.ComputeHash(all);
        }

        mic.CopyTo(auth, micOffset); // プレースホルダ(0)を実 MIC で上書き / overwrite the placeholder (0) with the real MIC

        DeriveSessionSecurity(ExportedSessionKey);
        return auth;
    }

    // CredSSP 用 EncryptMessage (封印 + 署名)。出力 = signature(16) || sealed。
    // EncryptMessage for CredSSP (seal + sign). Output = signature(16) || sealed.
    public byte[] Seal(ReadOnlySpan<byte> plaintext)
    {
        var sealedData = new byte[plaintext.Length];
        clientSeal!.Process(plaintext, sealedData);
        var sig = Mac(clientSignKey, clientSeal!, clientSeq, plaintext);
        clientSeq++;
        var outp = new byte[16 + sealedData.Length];
        sig.CopyTo(outp, 0);
        sealedData.CopyTo(outp, 16);
        return outp;
    }

    // CredSSP 用 DecryptMessage。入力 = signature(16) || sealed。署名検証は省略(復号のみ)。
    // DecryptMessage for CredSSP. Input = signature(16) || sealed. Signature verification is skipped (decrypt only).
    public byte[] Unseal(ReadOnlySpan<byte> token)
    {
        var sealedData = token[16..];
        var plain = new byte[sealedData.Length];
        serverSeal!.Process(sealedData, plain);
        return plain;
    }

    internal static byte[] SignKey(byte[] key, string dir)
    {
        var s = $"session key to {dir} signing key magic constant\0";
        var buf = new byte[key.Length + s.Length];
        key.CopyTo(buf, 0);
        Encoding.ASCII.GetBytes(s).CopyTo(buf, key.Length);
        return MD5.HashData(buf);
    }

    internal static byte[] SealKey(byte[] key, string dir)
    {
        var s = $"session key to {dir} sealing key magic constant\0";
        var buf = new byte[key.Length + s.Length];
        key.CopyTo(buf, 0);
        Encoding.ASCII.GetBytes(s).CopyTo(buf, key.Length);
        return MD5.HashData(buf);
    }

    internal void DeriveSessionSecurity(byte[] key)
    {
        clientSignKey = SignKey(key, "client-to-server");
        clientSeal = new Rc4(SealKey(key, "client-to-server"));
        serverSeal = new Rc4(SealKey(key, "server-to-client"));
        clientSeq = 0;
    }

    private static byte[] U16(string s) => Encoding.Unicode.GetBytes(s);

    // NTLM2 セッションセキュリティ署名 (MS-NLMP 3.4.4.1)。
    // NTLM2 session security signature (MS-NLMP 3.4.4.1).
    private static byte[] Mac(byte[] signKey, Rc4 sealHandle, uint seq, ReadOnlySpan<byte> message)
    {
        Span<byte> seqBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(seqBytes, seq);
        byte[] checksum;
        using (var h = new HMACMD5(signKey))
        {
            var buf = new byte[4 + message.Length];
            seqBytes.CopyTo(buf);
            message.CopyTo(buf.AsSpan(4));
            checksum = h.ComputeHash(buf);
        }

        Span<byte> enc = stackalloc byte[8];
        sealHandle.Process(checksum.AsSpan(0, 8), enc); // checksum を同じ RC4 ハンドルで封印 / seal the checksum with the same RC4 handle
        var sig = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(sig.AsSpan(0), 1); // Version
        enc.CopyTo(sig.AsSpan(4)); // Checksum(8)
        BinaryPrimitives.WriteUInt32LittleEndian(sig.AsSpan(12), seq);
        return sig;
    }

    private static long ExtractTimestamp(byte[] targetInfo)
    {
        // AV_PAIR を走査し MsvAvTimestamp(0x07) を探す。無ければ現在時刻(FILETIME)。
        // Scan the AV_PAIRs for MsvAvTimestamp(0x07). Fall back to the current time (FILETIME) if absent.
        var p = 0;
        while ((p + 4) <= targetInfo.Length)
        {
            var id = BinaryPrimitives.ReadUInt16LittleEndian(targetInfo.AsSpan(p));
            var len = BinaryPrimitives.ReadUInt16LittleEndian(targetInfo.AsSpan(p + 2));
            if (id == 0x0000)
            {
                break;
            }

            if ((id == 0x0007) && (len == 8))
            {
                return BinaryPrimitives.ReadInt64LittleEndian(targetInfo.AsSpan(p + 4));
            }

            p += 4 + len;
        }

        return DateTime.UtcNow.ToFileTimeUtc();
    }

    // サーバの target info をコピーし、MsvAvFlags に MIC ビット(0x02)を、MsvAvTargetName に SPN を付与。
    // Copy the server target info, set the MIC bit (0x02) in MsvAvFlags, and add the SPN as MsvAvTargetName.
    private static byte[] AugmentTargetInfo(byte[] serverInfo, string spn)
    {
        var pairs = new List<(ushort Id, byte[] Val)>();
        var p = 0;
        while ((p + 4) <= serverInfo.Length)
        {
            var id = BinaryPrimitives.ReadUInt16LittleEndian(serverInfo.AsSpan(p));
            var len = BinaryPrimitives.ReadUInt16LittleEndian(serverInfo.AsSpan(p + 2));
            if (id == 0x0000)
            {
                break;
            }

            pairs.Add((id, serverInfo.AsSpan(p + 4, len).ToArray()));
            p += 4 + len;
        }

        // MsvAvFlags(0x06) に 0x00000002 (MIC present)
        // Set 0x00000002 (MIC present) in MsvAvFlags(0x06).
        var fi = pairs.FindIndex(static x => x.Id == 0x0006);
        var flagVal = fi >= 0 ? pairs[fi].Val : new byte[4];
        var fv = flagVal.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(flagVal) : 0;
        fv |= 0x00000002;
        var nf = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(nf, fv);
        if (fi >= 0)
        {
            pairs[fi] = (0x0006, nf);
        }
        else
        {
            pairs.Add((0x0006, nf));
        }

        // MsvAvTargetName(0x09) = SPN
        pairs.Add((0x0009, Encoding.Unicode.GetBytes(spn)));

        var outp = new List<byte>();
        foreach (var (id, val) in pairs)
        {
            var h = new byte[4];
            BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(0), id);
            BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(2), (ushort)val.Length);
            outp.AddRange(h);
            outp.AddRange(val);
        }

        outp.AddRange([0, 0, 0, 0]); // MsvAvEOL
        return [.. outp];
    }

    private static void WriteVersion(Span<byte> dst)
    {
        // ProductMajor=10, Minor=0, Build=19041, Revision=15 (NTLMSSP_REVISION_W2K3)
        dst[0] = 10;
        dst[1] = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(dst[2..], 19041);
        dst[4] = 0;
        dst[5] = 0;
        dst[6] = 0;
        dst[7] = 0x0f;
    }

    private static Challenge ParseChallenge(byte[] msg)
    {
        var c = new Challenge
        {
            Flags = (NtlmFlags)BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(20))
        };
        msg.AsSpan(24, 8).CopyTo(c.ServerChallenge);

        // TargetInfoFields at offset 40: Len(2), MaxLen(2), Offset(4)
        var tiLen = BinaryPrimitives.ReadUInt16LittleEndian(msg.AsSpan(40));
        var tiOff = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg.AsSpan(44));
        c.TargetInfo = tiLen > 0 ? msg.AsSpan(tiOff, tiLen).ToArray() : [];
        return c;
    }

    private byte[] NtowfV2()
    {
        // NTOWFv2 = HMAC_MD5(MD4(UNICODE(pw)), UNICODE(UPPER(user)+domain))
        var hash = ntHash ?? Md4.Hash(U16(password));
        using var h = new HMACMD5(hash);
        return h.ComputeHash(U16(user.ToUpperInvariant() + domain));
    }

    private byte[] AssembleAuthenticate(
        string domainName,
        string userName,
        string workstationName,
        byte[] lmResponse,
        byte[] ntResponse,
        byte[] encryptedRandomSessionKey,
        NtlmFlags flags)
    {
        var dU = U16(domainName);
        var uU = U16(userName);
        var wU = U16(workstationName);

        // レイアウト: header(8) type(4) 6xField(8) flags(4) version(8) MIC(16) then payload
        // Layout: header(8) type(4) 6xField(8) flags(4) version(8) MIC(16) then payload.
        var fixedLen = 8 + 4 + (6 * 8) + 4 + 8 + 16;
        var off = fixedLen;

        var lmOff = off;
        off += lmResponse.Length;
        var ntOff = off;
        off += ntResponse.Length;
        var domOff = off;
        off += dU.Length;
        var userOff = off;
        off += uU.Length;
        var wsOff = off;
        off += wU.Length;
        var sessOff = off;
        off += encryptedRandomSessionKey.Length;

        var m = new byte[off];
        "NTLMSSP\0"u8.ToArray().CopyTo(m, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(8), 3); // MessageType

        Field(12, lmResponse, lmOff);
        Field(20, ntResponse, ntOff);
        Field(28, dU, domOff);
        Field(36, uU, userOff);
        Field(44, wU, wsOff);
        Field(52, encryptedRandomSessionKey, sessOff);
        BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(60), (uint)flags);
        WriteVersion(m.AsSpan(64));
        micOffset = 72; // MIC(16) は version(8) の直後 (プレースホルダ 0) / MIC(16) sits right after version(8) (placeholder 0)

        lmResponse.CopyTo(m, lmOff);
        ntResponse.CopyTo(m, ntOff);
        dU.CopyTo(m, domOff);
        uU.CopyTo(m, userOff);
        wU.CopyTo(m, wsOff);
        encryptedRandomSessionKey.CopyTo(m, sessOff);
        return m;

        void Field(int at, byte[] data, int dataOff)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(m.AsSpan(at), (ushort)data.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(m.AsSpan(at + 2), (ushort)data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(m.AsSpan(at + 4), (uint)dataOff);
        }
    }

    private sealed class Challenge
    {
        public byte[] ServerChallenge { get; } = new byte[8];

        public NtlmFlags Flags { get; set; }

        public byte[] TargetInfo { get; set; } = [];
    }
}
