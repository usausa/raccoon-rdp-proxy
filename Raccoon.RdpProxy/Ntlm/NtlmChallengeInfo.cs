namespace Raccoon.RdpProxy.Ntlm;

using System.Text;

internal static class NtlmChallengeInfo
{
    public static string? Describe(ReadOnlySpan<byte> token)
    {
        var at = token.IndexOf("NTLMSSP\0"u8);
        if (at < 0)
        {
            return null;
        }

        var msg = token[at..];
        if (msg.Length < 48)
        {
            return null;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(msg[8..]) != 2)
        {
            return null;
        }

        var sb = new StringBuilder();
        var targetName = ReadString(msg, 12);
        if (targetName.Length > 0)
        {
            Append(sb, "target", targetName);
        }

        Append(sb, "flags", $"0x{BinaryPrimitives.ReadUInt32LittleEndian(msg[20..]):X8}");

        var tiLen = BinaryPrimitives.ReadUInt16LittleEndian(msg[40..]);
        var tiOff = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg[44..]);
        if ((tiLen > 0) && (tiOff >= 0) && (tiOff <= (msg.Length - tiLen)))
        {
            AppendTargetInfo(sb, msg.Slice(tiOff, tiLen));
        }

        return sb.ToString();
    }

    private static void AppendTargetInfo(StringBuilder sb, ReadOnlySpan<byte> info)
    {
        var p = 0;
        while ((p + 4) <= info.Length)
        {
            var id = BinaryPrimitives.ReadUInt16LittleEndian(info[p..]);
            var len = BinaryPrimitives.ReadUInt16LittleEndian(info[(p + 2)..]);
            if (id == 0x0000)
            {
                break;
            }

            if ((p + 4 + len) > info.Length)
            {
                break;
            }

            var name = AvName(id);
            if (name is not null)
            {
                Append(sb, name, AvValue(id, info.Slice(p + 4, len)));
            }

            p += 4 + len;
        }
    }

    private static string? AvName(ushort id) => id switch
    {
        0x0001 => "nbComputer",
        0x0002 => "nbDomain",
        0x0003 => "dnsComputer",
        0x0004 => "dnsDomain",
        0x0005 => "dnsTree",
        0x0006 => "avFlags",
        0x0007 => "timestamp",
        0x0009 => "avTargetName",
        0x000A => "channelBindings",
        _ => null
    };

    private static string AvValue(ushort id, ReadOnlySpan<byte> value) => id switch
    {
        0x0006 => value.Length >= 4 ? $"0x{BinaryPrimitives.ReadUInt32LittleEndian(value):X8}" : "?",
        0x0007 => value.Length >= 8 ? FileTime(BinaryPrimitives.ReadInt64LittleEndian(value)) : "?",
        0x000A => $"{value.Length}B",
        _ => Encoding.Unicode.GetString(value)
    };

    private static string FileTime(long value)
    {
        try
        {
            return DateTime.FromFileTimeUtc(value).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        }
        catch (ArgumentOutOfRangeException)
        {
            return "?";
        }
    }

    private static string ReadString(ReadOnlySpan<byte> msg, int fieldAt)
    {
        var len = BinaryPrimitives.ReadUInt16LittleEndian(msg[fieldAt..]);
        var off = (int)BinaryPrimitives.ReadUInt32LittleEndian(msg[(fieldAt + 4)..]);
        if ((len == 0) || (off < 0) || (off > (msg.Length - len)))
        {
            return String.Empty;
        }

        return Encoding.Unicode.GetString(msg.Slice(off, len));
    }

    private static void Append(StringBuilder sb, string name, string value)
    {
        if (sb.Length > 0)
        {
            sb.Append(' ');
        }

        sb.Append(name).Append('=').Append(value);
    }
}
