namespace Raccoon.RdpProxy.Credssp;

using Raccoon.RdpProxy.Helpers;

// 最小限の DER エンコード/デコード (CredSSP TSRequest 用)。
internal static class Der
{
    public static byte[] Length(int n)
    {
        if (n < 0x80)
        {
            return [(byte)n];
        }

        if (n < 0x100)
        {
            return [0x81, (byte)n];
        }

        if (n < 0x10000)
        {
            return [0x82, (byte)(n >> 8), (byte)n];
        }

        return [0x83, (byte)(n >> 16), (byte)(n >> 8), (byte)n];
    }

    public static byte[] Tlv(byte tag, ReadOnlySpan<byte> content)
    {
        var len = Length(content.Length);
        var o = new byte[1 + len.Length + content.Length];
        o[0] = tag;
        len.CopyTo(o, 1);
        content.CopyTo(o.AsSpan(1 + len.Length));
        return o;
    }

    public static byte[] Integer(long v)
    {
        Span<byte> t = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(t, v);
        var i = 0;
        while ((i < 7) && (t[i] == 0) && ((t[i + 1] & 0x80) == 0))
        {
            i++;
        }

        return Tlv(0x02, t[i..]);
    }

    public static byte[] OctetString(ReadOnlySpan<byte> b) => Tlv(0x04, b);

    public static byte[] Context(int n, ReadOnlySpan<byte> content) => Tlv((byte)(0xA0 | n), content); // constructed

    public static byte[] Sequence(params byte[][] items) => Tlv(0x30, Concat(items));

    public static byte[] Concat(params byte[][] items)
    {
        var total = 0;
        foreach (var it in items)
        {
            total += it.Length;
        }

        var c = new byte[total];
        var p = 0;
        foreach (var it in items)
        {
            it.CopyTo(c, p);
            p += it.Length;
        }

        return c;
    }

    // pos 位置の TLV を読み、(tag, 内容の開始, 内容長, 次の位置) を返す。
    public static (byte Tag, int ContentStart, int ContentLen, int Next) ReadTlv(ReadOnlySpan<byte> b, int pos)
    {
        var tag = b[pos];
        var p = pos + 1;
        int len = b[p++];
        if ((len & 0x80) != 0)
        {
            var n = len & 0x7f;
            len = 0;
            for (var k = 0; k < n; k++)
            {
                len = (len << 8) | b[p++];
            }
        }

        return (tag, p, len, p + len);
    }

    // SEQUENCE の内容内から context タグ [n] の内容 span を探す。
    public static ReadOnlySpan<byte> FindContext(ReadOnlySpan<byte> seqContent, int n)
    {
        var want = (byte)(0xA0 | n);
        var pos = 0;
        while (pos < seqContent.Length)
        {
            var (tag, cs, cl, next) = ReadTlv(seqContent, pos);
            if (tag == want)
            {
                return seqContent.Slice(cs, cl);
            }

            pos = next;
        }

        return default;
    }

    // ストリームから DER オブジェクト1個(tag+length+content)を読み取る。
    public static async Task<byte[]> ReadObjectAsync(Stream s, CancellationToken ct)
    {
        var tl = new byte[2];
        if (!await StreamHelper.ReadFullAsync(s, tl, 0, 2, ct).ConfigureAwait(false))
        {
            throw new IOException("DER: EOF");
        }

        int first = tl[1];
        int contentLen;
        var lenExtra = Array.Empty<byte>();
        if ((first & 0x80) == 0)
        {
            contentLen = first;
        }
        else
        {
            var n = first & 0x7f;
            lenExtra = new byte[n];
            if (!await StreamHelper.ReadFullAsync(s, lenExtra, 0, n, ct).ConfigureAwait(false))
            {
                throw new IOException("DER: EOF(len)");
            }

            contentLen = 0;
            foreach (var b in lenExtra)
            {
                contentLen = (contentLen << 8) | b;
            }
        }

        var full = new byte[2 + lenExtra.Length + contentLen];
        full[0] = tl[0];
        full[1] = tl[1];
        lenExtra.CopyTo(full, 2);
        if (!await StreamHelper.ReadFullAsync(s, full, 2 + lenExtra.Length, contentLen, ct).ConfigureAwait(false))
        {
            throw new IOException("DER: EOF(body)");
        }

        return full;
    }
}
