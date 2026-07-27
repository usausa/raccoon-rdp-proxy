namespace Raccoon.RdpProxy.Ntlm;

// MD4 (RFC 1320) Implemented here because .NET does not provide it, Used to generate the NTLM NT hash
internal static class Md4
{
    public static byte[] Hash(ReadOnlySpan<byte> msg)
    {
        var a = 0x67452301u;
        var b = 0xefcdab89u;
        var c = 0x98badcfeu;
        var d = 0x10325476u;

        var bitLen = (long)msg.Length * 8;
        var pad = (msg.Length % 64) < 56 ? (56 - (msg.Length % 64)) : (120 - (msg.Length % 64));
        var buf = new byte[msg.Length + pad + 8];
        msg.CopyTo(buf);
        buf[msg.Length] = 0x80;
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(buf.Length - 8), bitLen);

        var x = new uint[16];
        for (var off = 0; off < buf.Length; off += 64)
        {
            for (var k = 0; k < 16; k++)
            {
                x[k] = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(off + (k * 4)));
            }

            var aa = a;
            var bb = b;
            var cc = c;
            var dd = d;

            // Round 1
            foreach (var k in Round1)
            {
                a = Rol(a + F(b, c, d) + x[k + 0], 3);
                d = Rol(d + F(a, b, c) + x[k + 1], 7);
                c = Rol(c + F(d, a, b) + x[k + 2], 11);
                b = Rol(b + F(c, d, a) + x[k + 3], 19);
            }

            // Round 2
            foreach (var k in Round2)
            {
                a = Rol(a + G(b, c, d) + x[k + 0] + 0x5a827999u, 3);
                d = Rol(d + G(a, b, c) + x[k + 4] + 0x5a827999u, 5);
                c = Rol(c + G(d, a, b) + x[k + 8] + 0x5a827999u, 9);
                b = Rol(b + G(c, d, a) + x[k + 12] + 0x5a827999u, 13);
            }

            // Round 3
            foreach (var k in Round3)
            {
                a = Rol(a + H(b, c, d) + x[k + 0] + 0x6ed9eba1u, 3);
                d = Rol(d + H(a, b, c) + x[k + 8] + 0x6ed9eba1u, 9);
                c = Rol(c + H(d, a, b) + x[k + 4] + 0x6ed9eba1u, 11);
                b = Rol(b + H(c, d, a) + x[k + 12] + 0x6ed9eba1u, 15);
            }

            a += aa;
            b += bb;
            c += cc;
            d += dd;
        }

        var outp = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(outp.AsSpan(0), a);
        BinaryPrimitives.WriteUInt32LittleEndian(outp.AsSpan(4), b);
        BinaryPrimitives.WriteUInt32LittleEndian(outp.AsSpan(8), c);
        BinaryPrimitives.WriteUInt32LittleEndian(outp.AsSpan(12), d);
        return outp;

        static uint F(uint xx, uint yy, uint zz) => (xx & yy) | (~xx & zz);
        static uint G(uint xx, uint yy, uint zz) => (xx & yy) | (xx & zz) | (yy & zz);
        static uint H(uint xx, uint yy, uint zz) => xx ^ yy ^ zz;
    }

    private static ReadOnlySpan<int> Round1 => [0, 4, 8, 12];

    private static ReadOnlySpan<int> Round2 => [0, 1, 2, 3];

    private static ReadOnlySpan<int> Round3 => [0, 2, 1, 3];

    private static uint Rol(uint v, int s) => (v << s) | (v >> (32 - s));
}
