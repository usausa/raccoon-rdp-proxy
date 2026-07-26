namespace Raccoon.RdpProxy.Ntlm;

// RC4 ストリーム暗号 (状態を保持)。
// RC4 stream cipher (keeps its state).
internal sealed class Rc4
{
    private readonly byte[] state = new byte[256];
    private int i;
    private int j;

    public Rc4(ReadOnlySpan<byte> key)
    {
        for (var k = 0; k < 256; k++)
        {
            state[k] = (byte)k;
        }

        var s = 0;
        for (var k = 0; k < 256; k++)
        {
            s = (s + state[k] + key[k % key.Length]) & 0xff;
            (state[k], state[s]) = (state[s], state[k]);
        }
    }

    public void Process(ReadOnlySpan<byte> input, Span<byte> output)
    {
        for (var n = 0; n < input.Length; n++)
        {
            i = (i + 1) & 0xff;
            j = (j + state[i]) & 0xff;
            (state[i], state[j]) = (state[j], state[i]);
            output[n] = (byte)(input[n] ^ state[(state[i] + state[j]) & 0xff]);
        }
    }

    public static byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var r = new Rc4(key);
        var o = new byte[data.Length];
        r.Process(data, o);
        return o;
    }
}
