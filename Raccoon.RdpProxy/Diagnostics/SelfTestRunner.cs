namespace Raccoon.RdpProxy.Diagnostics;

using System.Security.Cryptography;
using System.Text;

using Raccoon.RdpProxy.Credssp;
using Raccoon.RdpProxy.Ntlm;
using Raccoon.RdpProxy.Protocol;
using Raccoon.RdpProxy.Security;

// ネットワーク不要の自己テスト。移植で暗号/書き換えが壊れていないかを検証する。
internal static class SelfTestRunner
{
    public static int RunAll()
    {
        var fail = 0;
        fail += Check("clientAddress rewrite", TestRewrite);
        fail += Check("MCS serverSelectedProtocol patch", TestServerSelectedProtocol);
        fail += Check("MCS clientRequestedProtocols patch", TestClientRequestedProtocols);
        fail += Check("MCS clientName/productId mask", TestClientIdentityMask);
        fail += Check("Client Info clientDir mask", TestClientDirMask);
        fail += Check("IP ACL (CIDR)", TestIpAcl);
        fail += Check("NTLM vectors (MS-NLMP 4.2.4)", TestNtlmVectors);
        fail += Check("CredSSP DER round-trip", TestCredSspDer);

        Console.WriteLine();
        Console.WriteLine(fail == 0 ? "SELFTEST: ALL PASSED" : $"SELFTEST: {fail} FAILED");
        return fail == 0 ? 0 : 1;
    }

    private static int Check(string name, Action test)
    {
        try
        {
            test();
            Console.WriteLine($"  [PASS] {name}");
            return 0;
        }
        catch (Exception e) when (e is InvalidOperationException or InvalidDataException or ArgumentException)
        {
            Console.WriteLine($"  [FAIL] {name}: {e.Message}");
            return 1;
        }
    }

    private static void TestRewrite()
    {
        var tail = BuildTail();
        var pdu = BuildClientInfoPdu("192.168.10.11", tail);

        var outp = ClientInfoRewriter.TryRewrite(pdu, "10.13.8.100", false, out var old);
        Assert(outp is not null, "rewrite returned null");
        Assert(old == "192.168.10.11", $"old address mismatch: {old}");

        ClientInfoRewriter.TryRewrite(outp!, "X", false, out var now);
        Assert(now == "10.13.8.100", $"new address not applied: {now}");

        var tpktLen = (outp![2] << 8) | outp[3];
        Assert(tpktLen == outp!.Length, $"TPKT length mismatch {tpktLen} != {outp.Length}");
    }

    private static void TestServerSelectedProtocol()
    {
        var arr = BuildMcsConnectInitial(0);
        Assert(McsConnectInitial.PatchServerSelectedProtocol(arr, RdpConstants.ProtocolSsl, RdpConstants.ProtocolHybrid), "not patched");
        var v = (uint)(arr[9 + 212] | (arr[9 + 213] << 8) | (arr[9 + 214] << 16) | (arr[9 + 215] << 24));
        Assert(v == RdpConstants.ProtocolHybrid, $"serverSelectedProtocol not HYBRID: 0x{v:X}");
    }

    private static void TestClientRequestedProtocols()
    {
        var pdu = new List<byte> { 0x03, 0x00, 0, 0, 0x02, 0xF0, 0x80, 0x7F, 0x66 };
        var blockStart = pdu.Count;
        pdu.AddRange([0x01, 0x0C, 0x0C, 0x00]); // SC_CORE len=12
        pdu.AddRange([0x00, 0x00, 0x08, 0x00]); // version
        pdu.AddRange([0x03, 0x00, 0x00, 0x00]); // clientRequestedProtocols = 0x03
        var arr = pdu.ToArray();
        arr[2] = (byte)(arr.Length >> 8);
        arr[3] = (byte)(arr.Length & 0xFF);

        Assert(McsConnectResponse.PatchClientRequestedProtocols(arr, 0x03, 0x0B), "not patched");
        var pos = blockStart + 8;
        var v = (uint)(arr[pos] | (arr[pos + 1] << 8) | (arr[pos + 2] << 16) | (arr[pos + 3] << 24));
        Assert(v == 0x0B, $"clientRequestedProtocols not 0xB: 0x{v:X}");
    }

    private static void TestClientIdentityMask()
    {
        // name のみ (productId 保持)
        var a1 = BuildMcsConnectInitial(0xAA);
        Assert(McsConnectInitial.PatchClientIdentity(a1, "RELAY01", false), "name-only not patched");
        Assert(Encoding.Unicode.GetString(a1, 9 + 24, 32).TrimEnd('\0') == "RELAY01", "clientName mismatch");
        Assert(a1[9 + 146] == 0xAA, "productId should be preserved for name-only");

        // 追加マスク (productId ゼロ)
        var a2 = BuildMcsConnectInitial(0xAA);
        Assert(McsConnectInitial.PatchClientIdentity(a2, "RELAY01", true), "full not patched");
        for (var i = 0; i < 64; i++)
        {
            Assert(a2[9 + 146 + i] == 0, "productId not cleared");
        }
    }

    private static void TestClientDirMask()
    {
        var tail = BuildTail();
        var pdu = BuildClientInfoPdu("192.168.10.11", tail);
        var outp = ClientInfoRewriter.TryRewrite(pdu, "10.13.8.100", true, out _);
        Assert(outp is not null, "null");

        var got = ExtractTail(outp!);
        var cbDir = got[0] | (got[1] << 8);
        Assert(cbDir == 2, $"cbClientDir not 2: {cbDir}");
        Assert((got[2] == 0) && (got[3] == 0), "clientDir not empty");

        var origCb = tail[0] | (tail[1] << 8);
        Assert(got.AsSpan(4).SequenceEqual(tail.AsSpan(2 + origCb)), "post-clientDir tail corrupted");
    }

    // 出力 PDU から clientAddress 直後の tail を取り出す。
    private static byte[] ExtractTail(byte[] tpkt)
    {
        ReadOnlySpan<byte> s = tpkt;
        var m = 7 + 1 + 2 + 2 + 1; // 0x64 + init + chan + prio
        _ = ByteOpsReadPerLength(s, ref m);
        var i = m + 4 + 4 + 4; // secHdr(4) + CodePage(4) + flags(4)
        var cbDomain = U16(s, i);
        var cbUser = U16(s, i + 2);
        var cbPass = U16(s, i + 4);
        var cbShell = U16(s, i + 6);
        var cbWork = U16(s, i + 8);
        i += 10;
        const int term = 2;
        i += cbDomain + term + cbUser + term + cbPass + term + cbShell + term + cbWork + term;
        i += 2; // family
        var cbAddr = U16(s, i);
        i += 2 + cbAddr;
        return tpkt[i..];

        static int U16(ReadOnlySpan<byte> s, int o) => s[o] | (s[o + 1] << 8);

        static int ByteOpsReadPerLength(ReadOnlySpan<byte> s, ref int pos)
        {
            var first = s[pos++];
            return (first & 0x80) == 0 ? first : (((first & 0x7F) << 8) | s[pos++]);
        }
    }

    private static void TestIpAcl()
    {
        Assert(IpAcl.Parse([]).IsAllowed(IPAddress.Parse("8.8.8.8")), "empty ACL should allow all");
        var acl = IpAcl.Parse(["192.168.100.0/24", "10.13.8.5", "172.16.0.0/12"]);
        Assert(acl.IsAllowed(IPAddress.Parse("192.168.100.9")), "192.168.100.9 should be allowed");
        Assert(!acl.IsAllowed(IPAddress.Parse("192.168.101.9")), "192.168.101.9 should be denied");
        Assert(acl.IsAllowed(IPAddress.Parse("10.13.8.5")), "10.13.8.5/32 should be allowed");
        Assert(!acl.IsAllowed(IPAddress.Parse("10.13.8.6")), "10.13.8.6 should be denied");
        Assert(acl.IsAllowed(IPAddress.Parse("172.20.1.1")), "172.20.1.1/12 should be allowed");
        Assert(!acl.IsAllowed(null), "null should be denied");
        Assert(acl.IsAllowed(IPAddress.Parse("::ffff:192.168.100.9")), "IPv4-mapped should be allowed");
    }

    private static void TestNtlmVectors()
    {
        Eq("MD4('')", Md4.Hash([]), "31d6cfe0d16ae931b73c59d7e0c089c0");

        byte[] ntowf;
        using (var h = new HMACMD5(Md4.Hash(Encoding.Unicode.GetBytes("Password"))))
        {
            ntowf = h.ComputeHash(Encoding.Unicode.GetBytes("USERDomain"));
        }

        Eq("NTOWFv2", ntowf, "0c868a403bfd7a93a3001ef22ef02e3f");

        var serverChallenge = Convert.FromHexString("0123456789abcdef");
        var targetInfo = Convert.FromHexString("02000c0044006f006d00610069006e0001000c00530065007200760065007200" + "00000000");
        var temp = new List<byte> { 0x01, 0x01, 0, 0, 0, 0, 0, 0 };
        temp.AddRange(new byte[8]);
        temp.AddRange(Convert.FromHexString("aaaaaaaaaaaaaaaa"));
        temp.AddRange([0, 0, 0, 0]);
        temp.AddRange(targetInfo);
        temp.AddRange([0, 0, 0, 0]);

        byte[] proof;
        using (var h = new HMACMD5(ntowf))
        {
            var b = new byte[8 + temp.Count];
            serverChallenge.CopyTo(b, 0);
            temp.CopyTo(b, 8);
            proof = h.ComputeHash(b);
        }

        Eq("NTProofStr", proof, "68cd0ab851e51c96aabc927bebef6a1c");

        byte[] sbk;
        using (var h = new HMACMD5(ntowf))
        {
            sbk = h.ComputeHash(proof);
        }

        Eq("SessionBaseKey", sbk, "8de40ccadbc14a82f15cb0ad0de95ca3");
        Eq("EncryptedRandomSessionKey", Rc4.Encrypt(sbk, Convert.FromHexString("55555555555555555555555555555555")), "c5dad2544fc9799094ce1ce90bc9d03e");

        // Seal -> server 側鍵で復号できること
        var esk = Convert.FromHexString("55555555555555555555555555555555");
        var a = new NtlmClientAuth("D", "U", "P");
        a.DeriveSessionSecurity(esk);
        var msg = "hello-credssp"u8.ToArray();
        var token = a.Seal(msg);
        var srvSeal = new Rc4(NtlmClientAuth.SealKey(esk, "client-to-server"));
        var dec = new byte[token.Length - 16];
        srvSeal.Process(token.AsSpan(16), dec);
        Eq("Seal/Unseal roundtrip", dec, Convert.ToHexString(msg).ToLowerInvariant());
    }

    private static void TestCredSspDer()
    {
        var token = "NTLMSSP\0test-token"u8.ToArray();
        var back = CredSspClient.ExtractNegoToken(CredSspClient.BuildTsRequest(negoToken: token));
        Assert((back is not null) && back.AsSpan().SequenceEqual(token), "TSRequest negoToken round-trip failed");

        var req2 = CredSspClient.BuildTsRequest(pubKeyAuth: [1, 2, 3, 4]);
        Assert(CredSspClient.ExtractPubKeyAuth(req2) is { Length: 4 } p && (p[0] == 1) && (p[3] == 4), "pubKeyAuth extraction failed");

        var reqErr = Der.Sequence(Der.Context(0, Der.Integer(6)), Der.Context(4, Der.Integer(0xC000006D)));
        Assert((uint)CredSspClient.ExtractErrorCode(reqErr) == 0xC000006D, "errorCode extraction failed");
    }

    private static void Eq(string name, byte[] got, string exp)
    {
        var g = Convert.ToHexString(got).ToLowerInvariant();
        if (g != exp)
        {
            throw new InvalidOperationException($"{name}: got {g}, exp {exp}");
        }
    }

    private static void Assert(bool cond, string message)
    {
        if (!cond)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static byte[] BuildMcsConnectInitial(byte productIdFill)
    {
        var pdu = new List<byte> { 0x03, 0x00, 0, 0, 0x02, 0xF0, 0x80, 0x7F, 0x65 };
        var block = new byte[216];
        block[0] = 0x01;
        block[1] = 0xC0;
        block[2] = 0xD8;
        block[3] = 0x00;
        Encoding.Unicode.GetBytes("OLD-PC").CopyTo(block, 24);
        for (var i = 146; i < (146 + 64); i++)
        {
            block[i] = productIdFill;
        }

        block[212] = 0x01; // serverSelectedProtocol = SSL
        pdu.AddRange(block);
        var arr = pdu.ToArray();
        arr[2] = (byte)(arr.Length >> 8);
        arr[3] = (byte)(arr.Length & 0xFF);
        return arr;
    }

    internal static byte[] BuildClientInfoPduForTest(string clientAddress) => BuildClientInfoPdu(clientAddress, BuildTail());

    private static byte[] BuildClientInfoPdu(string clientAddress, byte[] tail)
    {
        var domain = Encoding.Unicode.GetBytes("WORKGROUP");
        var userName = Encoding.Unicode.GetBytes("administrator");

        var info = new List<byte>();
        AddU32(info, 0x0409);
        AddU32(info, RdpConstants.InfoUnicode | 0x00000008u);
        AddU16(info, (ushort)domain.Length);
        AddU16(info, (ushort)userName.Length);
        AddU16(info, 0);
        AddU16(info, 0);
        AddU16(info, 0);
        info.AddRange(domain);
        info.AddRange([0, 0]);
        info.AddRange(userName);
        info.AddRange([0, 0]);
        info.AddRange([0, 0]); // pass
        info.AddRange([0, 0]); // shell
        info.AddRange([0, 0]); // work
        AddU16(info, 0x0002); // clientAddressFamily
        var addr = Encoding.Unicode.GetBytes(clientAddress);
        AddU16(info, (ushort)(addr.Length + 2));
        info.AddRange(addr);
        info.AddRange([0, 0]);
        info.AddRange(tail);

        var userData = new List<byte>();
        AddU16(userData, RdpConstants.SecInfoPkt);
        AddU16(userData, 0x0000);
        userData.AddRange(info);

        var mcs = new List<byte> { RdpConstants.McsSendDataRequest, 0x03, 0xEA, 0x03, 0xEB, 0x70 };
        AddPerLen(mcs, userData.Count);
        mcs.AddRange(userData);

        var total = 4 + 3 + mcs.Count;
        var pdu = new List<byte> { 0x03, 0x00, (byte)(total >> 8), (byte)(total & 0xFF), 0x02, 0xF0, 0x80 };
        pdu.AddRange(mcs);
        return [.. pdu];
    }

    private static byte[] BuildTail()
    {
        var t = new List<byte>();
        var dir = Encoding.Unicode.GetBytes("C:\\WINDOWS");
        AddU16(t, (ushort)(dir.Length + 2));
        t.AddRange(dir);
        t.AddRange([0, 0]);
        for (var k = 0; k < 172; k++)
        {
            t.Add((byte)(k & 0xFF));
        }

        AddU32(t, 0x00000000);
        AddU32(t, 0x0000000F);
        return [.. t];
    }

    private static void AddU16(List<byte> l, ushort v)
    {
        l.Add((byte)v);
        l.Add((byte)(v >> 8));
    }

    private static void AddU32(List<byte> l, uint v)
    {
        l.Add((byte)v);
        l.Add((byte)(v >> 8));
        l.Add((byte)(v >> 16));
        l.Add((byte)(v >> 24));
    }

    private static void AddPerLen(List<byte> l, int n)
    {
        if (n < 0x80)
        {
            l.Add((byte)n);
        }
        else
        {
            l.Add((byte)(0x80 | (n >> 8)));
            l.Add((byte)n);
        }
    }
}
