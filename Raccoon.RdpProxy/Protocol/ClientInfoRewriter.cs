namespace Raccoon.RdpProxy.Protocol;

using System.Text;

// Core logic that rewrites the clientAddress inside the Client Info PDU
internal static class ClientInfoRewriter
{
    private const int MaxCredentialField = 512;

    // Takes one slow-path TPKT and, if it is a Client Info PDU, returns a new TPKT with clientAddress rewritten to newAddress
    // Returns null if it is not a Client Info PDU (the caller forwards as-is)
    // If it is a Client Info PDU but parsing fails, throws InvalidDataException
    public static byte[]? TryRewrite(
        ReadOnlySpan<byte> t,
        string newAddress,
        bool maskClientDir,
        AutoLogonCredential? autoLogon,
        out string? oldAddress)
    {
        oldAddress = null;
        var len = t.Length;

        // Detect TPKT / X.224 Data / MCS SendDataRequest
        if ((len < 8) || (t[0] != 0x03))
        {
            return null;
        }

        if (!ByteOps.Match3(t, 4, 0x02, 0xF0, 0x80))
        {
            return null;
        }

        if (t[7] != RdpConstants.McsSendDataRequest)
        {
            return null;
        }

        var mcsFixedEnd = 7 + 1 + 2 + 2 + 1; // 0x64 + initiator + channelId + priority
        if ((mcsFixedEnd + 2) > len)
        {
            return null;
        }

        var m = mcsFixedEnd;
        _ = ByteOps.ReadPerLength(t, ref m);
        var userDataStart = m;
        if ((userDataStart + 4) > len)
        {
            return null;
        }

        // Basic Security Header
        var secFlags = ByteOps.U16Le(t, userDataStart);
        if ((secFlags & RdpConstants.SecInfoPkt) == 0)
        {
            return null;
        }

        if ((secFlags & RdpConstants.SecEncrypt) != 0)
        {
            throw new InvalidDataException(
                "Client Info PDU is encrypted with SEC_ENCRYPT (standard RDP security); not decrypted at the TLS layer.");
        }

        // From here it is definitely a Client Info PDU; any inconsistency below throws
        var infoStart = userDataStart + 4;
        var i = infoStart;

        if ((i + 8) > len)
        {
            throw Truncated();
        }

        var infoFlags = ByteOps.U32Le(t, i + 4); // flags(4) / flags(4) follows CodePage(4)
        i += 8;
        var term = (infoFlags & RdpConstants.InfoUnicode) != 0 ? 2 : 1; // Byte count of a string's trailing NUL

        if ((i + 10) > len)
        {
            throw Truncated();
        }

        var cbDomain = ByteOps.U16Le(t, i);
        var cbUser = ByteOps.U16Le(t, i + 2);
        var cbPass = ByteOps.U16Le(t, i + 4);
        var cbShell = ByteOps.U16Le(t, i + 6);
        var cbWork = ByteOps.U16Le(t, i + 8);
        i += 10;

        // Five variable-length strings. cb excludes the NUL, so each field is cb + term
        var domainAt = i;
        var userAt = domainAt + cbDomain + term;
        var passAt = userAt + cbUser + term;
        var shellAt = passAt + cbPass + term;
        var workAt = shellAt + cbShell + term;
        i = workAt + cbWork + term;

        // TS_EXTENDED_INFO_PACKET
        if ((i + 4) > len)
        {
            throw new InvalidDataException("TS_EXTENDED_INFO_PACKET is missing (old client?).");
        }

        var addrFamilyPos = i;
        var cbClientAddress = ByteOps.U16Le(t, i + 2); // This length includes the NUL
        var addrStart = i + 4;
        var addrEnd = addrStart + cbClientAddress;
        if (addrEnd > len)
        {
            throw new InvalidDataException("clientAddress length is invalid.");
        }

        oldAddress = DecodeUtf16(t.Slice(addrStart, cbClientAddress));

        // clientDir mask: replace cbClientDir + clientDir right after clientAddress with empty (NUL only)
        //   tail = [cbClientDir(2)][clientDir(cb)][clientTimeZone onward...]
        var doMaskDir = false;
        var clientDirEnd = addrEnd;
        if (maskClientDir && ((addrEnd + 2) <= len))
        {
            var cbClientDir = ByteOps.U16Le(t, addrEnd);
            var dirEnd = (long)addrEnd + 2 + cbClientDir;
            if (dirEnd <= len)
            {
                doMaskDir = true;
                clientDirEnd = (int)dirEnd;
            }
        }

        // CodePage..the 5 strings, with infoFlags and the credential strings replaced when auto-logon is requested
        var newFlags = infoFlags;
        byte[]? domainBytes = null;
        byte[]? userBytes = null;
        byte[]? passBytes = null;
        if (autoLogon is { } credential)
        {
            if (term != 2)
            {
                throw new InvalidDataException("Auto-logon needs a Unicode (INFO_UNICODE) Client Info PDU.");
            }

            domainBytes = Encoding.Unicode.GetBytes(credential.Domain);
            userBytes = Encoding.Unicode.GetBytes(credential.User);
            passBytes = Encoding.Unicode.GetBytes(credential.Password);
            if ((domainBytes.Length > MaxCredentialField) ||
                (userBytes.Length > MaxCredentialField) ||
                (passBytes.Length > MaxCredentialField))
            {
                throw new InvalidDataException("Auto-logon credential exceeds the Client Info PDU field limit.");
            }

            newFlags |= RdpConstants.InfoAutoLogon;
        }

        var head = new List<byte>((addrFamilyPos - infoStart) + (3 * (MaxCredentialField + 2)));
        head.AddRange(t.Slice(infoStart, 4)); // CodePage
        var flagBytes = new byte[4];
        ByteOps.W32Le(flagBytes, 0, newFlags);
        head.AddRange(flagBytes);
        if (domainBytes is null)
        {
            head.AddRange(t[(infoStart + 8)..addrFamilyPos]);
        }
        else
        {
            var cbFields = new byte[10];
            ByteOps.W16Le(cbFields, 0, (ushort)domainBytes.Length);
            ByteOps.W16Le(cbFields, 2, (ushort)userBytes!.Length);
            ByteOps.W16Le(cbFields, 4, (ushort)passBytes!.Length);
            ByteOps.W16Le(cbFields, 6, cbShell);
            ByteOps.W16Le(cbFields, 8, cbWork);
            head.AddRange(cbFields);
            AddWithNul(head, domainBytes);
            AddWithNul(head, userBytes);
            AddWithNul(head, passBytes);
            head.AddRange(t.Slice(shellAt, cbShell + term));
            head.AddRange(t.Slice(workAt, cbWork + term));
        }

        // Determine the output size first, then write straight into a single buffer
        var newAddrChars = Encoding.Unicode.GetByteCount(newAddress);
        var newCb = newAddrChars + 2; // + 2byte NUL

        // tail body: when masking, cbClientDir=2 + NUL(2) + [clientDirEnd..len]; otherwise [addrEnd..len]
        var tailBodyLen = doMaskDir ? (4 + (len - clientDirEnd)) : (len - addrEnd);
        var newInfoLen = head.Count + 2 + 2 + newCb + tailBodyLen;
        var newUserDataLen = 4 + newInfoLen;
        var mcsFixed = mcsFixedEnd - 7; // 6
        var perSize = ByteOps.PerLengthSize(newUserDataLen);
        var total = 4 + 3 + mcsFixed + perSize + newUserDataLen;

        var outArr = new byte[total];
        Span<byte> o = outArr;

        o[0] = 0x03;
        o[1] = 0x00;
        ByteOps.W16Be(o, 2, (ushort)total); // TPKT
        o[4] = 0x02;
        o[5] = 0xF0;
        o[6] = 0x80; // X.224 Data

        var w = 7;
        t.Slice(7, mcsFixed).CopyTo(o[w..]);
        w += mcsFixed; // MCS fixed part
        w += ByteOps.WritePerLength(o, w, newUserDataLen); // PER length
        t.Slice(userDataStart, 4).CopyTo(o[w..]);
        w += 4; // Security Header
        head.CopyTo(outArr, w);
        w += head.Count; // CodePage..the 5 strings
        t.Slice(addrFamilyPos, 2).CopyTo(o[w..]);
        w += 2; // clientAddressFamily
        ByteOps.W16Le(o, w, (ushort)newCb);
        w += 2; // New cbClientAddress
        Encoding.Unicode.GetBytes(newAddress, o.Slice(w, newAddrChars));
        w += newAddrChars;
        o[w] = 0;
        o[w + 1] = 0;
        w += 2; // clientAddress NUL

        if (doMaskDir)
        {
            ByteOps.W16Le(o, w, 2);
            w += 2; // cbClientDir = 2 (NUL only) / cbClientDir = 2 (NUL only)
            o[w] = 0;
            o[w + 1] = 0;
            w += 2; // clientDir NUL
            t[clientDirEnd..].CopyTo(o[w..]); // clientTimeZone onward
        }
        else
        {
            t[addrEnd..].CopyTo(o[w..]); // tail
        }

        return outArr;
    }

    private static void AddWithNul(List<byte> dst, byte[] value)
    {
        dst.AddRange(value);
        dst.Add(0);
        dst.Add(0);
    }

    private static InvalidDataException Truncated() =>
        new("Client Info PDU is truncated.");

    private static string DecodeUtf16(ReadOnlySpan<byte> s)
    {
        var n = s.Length;
        while ((n >= 2) && (s[n - 1] == 0) && (s[n - 2] == 0))
        {
            n -= 2; // Strip the trailing NUL
        }

        return Encoding.Unicode.GetString(s[..n]);
    }
}
