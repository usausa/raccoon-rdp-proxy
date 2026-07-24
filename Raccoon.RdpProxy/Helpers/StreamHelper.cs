namespace Raccoon.RdpProxy.Helpers;

// ストリーム読み取りの共有ヘルパ。
internal static class StreamHelper
{
    // count バイトを確実に読む。EOF で false。
    public static async Task<bool> ReadFullAsync(Stream s, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        var read = 0;
        while (read < count)
        {
            var n = await s.ReadAsync(buffer.AsMemory(offset + read, count - read), ct).ConfigureAwait(false);
            if (n == 0)
            {
                return false;
            }

            read += n;
        }

        return true;
    }

    // TPKT (03 00 <len:2 BE> ...) を 1 つ読む。EOF/不正なら null。
    public static async Task<byte[]?> ReadTpktAsync(Stream s, CancellationToken ct)
    {
        var header = new byte[4];
        if (!await ReadFullAsync(s, header, 0, 4, ct).ConfigureAwait(false))
        {
            return null;
        }

        if (header[0] != 0x03)
        {
            return null;
        }

        var length = (header[2] << 8) | header[3];
        if ((length < 4) || (length > (64 * 1024)))
        {
            return null;
        }

        var buffer = new byte[length];
        header.AsSpan(0, 4).CopyTo(buffer);
        return await ReadFullAsync(s, buffer, 4, length - 4, ct).ConfigureAwait(false) ? buffer : null;
    }
}
