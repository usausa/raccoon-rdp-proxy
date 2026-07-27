namespace Raccoon.RdpProxy.Helpers;

// Shared helpers for reading from streams
internal static class StreamHelper
{
    // Read exactly count bytes, Returns false on EOF
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

    // Read a single TPKT (03 00 <len:2 BE> ...), Returns null on EOF or on a malformed packet
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
