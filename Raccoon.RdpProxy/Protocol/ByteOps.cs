namespace Raccoon.RdpProxy.Protocol;

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// Span ベースのバイト操作。読み書きは BinaryPrimitives に委譲し、
// 署名一致など境界が保証済みの箇所のみ Unsafe で高速化する。
// Span-based byte operations. Reads/writes delegate to BinaryPrimitives, and only
// bounds-guaranteed spots such as signature matching are sped up with Unsafe.
internal static class ByteOps
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ushort U16Le(ReadOnlySpan<byte> s, int o) => BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(o, 2));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint U32Le(ReadOnlySpan<byte> s, int o) => BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(o, 4));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void W16Le(Span<byte> s, int o, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(o, 2), v);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void W16Be(Span<byte> s, int o, ushort v) => BinaryPrimitives.WriteUInt16BigEndian(s.Slice(o, 2), v);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void W32Le(Span<byte> s, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(o, 4), v);

    // ASN.1 PER の length determinant を読む (最大 16383)。
    // Read an ASN.1 PER length determinant (max 16383).
    public static int ReadPerLength(ReadOnlySpan<byte> s, ref int pos)
    {
        var first = s[pos++];
        if ((first & 0x80) == 0)
        {
            return first;
        }

        return ((first & 0x7F) << 8) | s[pos++];
    }

    // PER length を書き、書いたバイト数を返す。
    // Write a PER length and return the number of bytes written.
    public static int WritePerLength(Span<byte> dst, int at, int n)
    {
        if ((uint)n < 0x80)
        {
            dst[at] = (byte)n;
            return 1;
        }

        if ((uint)n < 0x4000)
        {
            dst[at] = (byte)(0x80 | (n >> 8));
            dst[at + 1] = (byte)n;
            return 2;
        }

        throw new ArgumentOutOfRangeException(nameof(n), "PER length > 16383 is not supported.");
    }

    public static int PerLengthSize(int n) =>
        (uint)n < 0x80 ? 1 : ((uint)n < 0x4000 ? 2 : throw new ArgumentOutOfRangeException(nameof(n)));

    // 3 バイト署名 (例: X.224 Data 02 F0 80) の高速一致判定。
    // 呼び出し側で o+3 <= s.Length を保証すること。境界チェックを省くため Unsafe を使用。
    // Fast match of a 3-byte signature (e.g. X.224 Data 02 F0 80).
    // The caller must guarantee o+3 <= s.Length; Unsafe is used to skip bounds checks.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Match3(ReadOnlySpan<byte> s, int o, byte a, byte b, byte c)
    {
        ref var p = ref Unsafe.Add(ref MemoryMarshal.GetReference(s), o);
        return (p == a) && (Unsafe.Add(ref p, 1) == b) && (Unsafe.Add(ref p, 2) == c);
    }
}
