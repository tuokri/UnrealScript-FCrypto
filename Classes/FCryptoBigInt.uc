/*
 * Copyright (c) 2024 Tuomo Kriikkula <tuokri@tuta.io>
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * UnrealScript arbitrary precision integer implementation
 * based on BearSSL "i15" implementation.
 *
 * BearSSL uses uint16_t, but UScript only has 32-bit signed
 * integers, so some adaptations have been made here.
 *
 * See: https://www.bearssl.org/bigint.html.
 *
 * TODO: Implement OOP style BigInt in addition to C-style version?
 */
class FCryptoBigInt extends Object
    abstract
    notplaceable;

// TODO: interesting discussion on converting big integers to
// decimal strings. It's about C#, but could be relevant.
// https://stackoverflow.com/questions/13154304/fastest-way-to-convert-a-biginteger-to-a-decimal-base-10-string

// TODO: rewrite documentation to be more UScript-like.
// TODO: remove the parts of documentation only relevant in C.
// TODO: do all these constant time compiler tricks work in UScript?

// TODO: need to double-check porting of functions that work on uint16_t
// values in BearSSL. Some operations like sizeof, shifts and hard-coded
// constants (0x7FFF) may not work as expected when directly replacing
// uint16_t variables with UScript 32-bit integers!

// TODO: there are a few places where dynamic array resizing is used.
// We should remove all of these if possible, to keep BearSSL CT guarantees
// as intact as possible. This is only a best effort CT guarantee, though.

`include(FCrypto\Classes\FCryptoMacros.uci);

/*
 * Negate a boolean.
 */
static final function int NOT(int Ctl)
{
    return Ctl ^ 1;
}

/*
 * Multiplexer: returns X if ctl == 1, y if ctl == 0.
 */
static final function int MUX(int Ctl, int X, Int Y)
{
    return Y ^ ((-Ctl) & (X ^ Y));
}

/*
 * Equality check: returns 1 if X == y, 0 otherwise.
 */
static final function int EQ(int X, int Y)
{
    local int Q;

    Q = X ^ Y;
    return NOT((Q | (-Q)) >>> 31);
}

/*
 * Inequality check: returns 1 if x != y, 0 otherwise.
 */
static final function int NEQ(int X, int Y)
{
    local int Q;

    Q = X ^ Y;
    return (Q | (-Q)) >>> 31;
}

static final function int GT(int X, int Y)
{
    /*
     * If both x < 2^31 and x < 2^31, then y-x will have its high
     * bit set if x > y, cleared otherwise.
     *
     * If either x >= 2^31 or y >= 2^31 (but not both), then the
     * result is the high bit of x.
     *
     * If both x >= 2^31 and y >= 2^31, then we can virtually
     * subtract 2^31 from both, and we are back to the first case.
     * Since (y-2^31)-(x-2^31) = y-x, the subtraction is already
     * fine.
     */
    local int Z;

    Z = Y - X;
    return (Z ^ ((X ^ Y) & (X ^ Z))) >>> 31;
}

/*
 * Compute the bit length of a 32-bit integer. Returned value is between 0
 * and 32 (inclusive).
 */
static final function int BIT_LENGTH(int X)
{
    local int K;
    local int C;

    K = NEQ(X, 0);
    C = GT(X, 0xFFFF); X = MUX(C, X >>> 16, X); K += C << 4;
    C = GT(X, 0x00FF); X = MUX(C, X >>>  8, X); K += C << 3;
    C = GT(X, 0x000F); X = MUX(C, X >>>  4, X); K += C << 2;
    C = GT(X, 0x0003); X = MUX(C, X >>>  2, X); K += C << 1;
    K += GT(X, 0x0001);
    return K;
}

/*
 * General comparison: returned value is -1, 0 or 1, depending on
 * whether x is lower than, equal to, or greater than y.
 */
static final function int CMP(int X, int Y)
{
    return GT(X, Y) | (-GT(Y, X));
}

/*
 * Returns 1 if x == 0, 0 otherwise. Take care that the operand is signed.
 */
static final function int EQ0(int X)
{
    return (~(X | -X)) >>> 31;
}

`define GE(X, Y) (NOT(GT(`Y, `X)))
`define LT(X, Y) (GT(`Y, `X))
`define LE(X, Y) (NOT(GT(`X, `Y)))

/**
 * C-style memcmp operation.
 * Offset is the number of bytes values
 * to ignore from the beginning of S1.
 */
static final function int MemCmp_Bytes(
    const out array<byte> S1,
    const out array<byte> S2,
    int N,
    optional int Offset = 0
)
{
    local int I;
    local int S2Idx;

    S2Idx = 0;
    for (I = Offset; I < N; ++I)
    {
        if (S1[I] != S2[S2Idx++])
        {
            return I + 1;
        }
    }

    return 0;
}

/**
 * C-style memmove operation.
 * Offsets are the number of uint16_t values
 * to ignore from the beginning of each array.
 */
static final function MemMove(
    out array<int> Dst,
    const out array<int> Src,
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    local int IntIndex;
    local int ByteIndex;
    local int Shift;
    local int Mask;
    local array<byte> DstBytes;
    local int DstTmp;
    local int MaxIntIndex;

    DstBytes.Length = NumBytes;

    /*
     * Take all 16-bit integers from Src and put them
     * into DstBytes byte array, taking SrcOffset into account.
     */
    IntIndex = SrcOffset;
    ByteIndex = 0;
    Shift = 8;
    while (ByteIndex < NumBytes)
    {
        DstBytes[ByteIndex] = (Src[IntIndex] >>> Shift) & 0xff;
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        ++ByteIndex;
    }

    /*
     * Write DstBytes into Dst, taking DstOffset into account.
     */
    Shift = 8;
    Mask = 0xff << Shift;
    IntIndex = DstOffset;

    MaxIntIndex = FFloor(DstOffset + (NumBytes / 2));
    if (MaxIntIndex >= Dst.Length)
    {
        Dst.Length = MaxIntIndex + 1;
    }

    for (ByteIndex = 0; ByteIndex < NumBytes; ++ByteIndex)
    {
        // `fcsdebug("IntIndex=" $ IntIndex);

        // TODO: is DstTmp needed? (Also check other memory functions).
        DstTmp = (Dst[IntIndex] & ~Mask) | ((DstBytes[ByteIndex] & 0xff) << Shift);
        Dst[IntIndex] = DstTmp;

        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        Mask = 0xff << Shift;
    }
}

static final function MemMove_Byte(
    out array<byte> Dst,
    const out array<byte> Src,
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    local int ByteIndex;
    local int I;
    local array<byte> DstBytes;

    DstBytes.Length = NumBytes;

    ByteIndex = 0;
    I = SrcOffset;

    while (ByteIndex < NumBytes)
    {
        DstBytes[ByteIndex++] = Src[I++];
    }

    ByteIndex = DstOffset;
    for (I = 0; I < NumBytes; ++I)
    {
        Dst[ByteIndex++] = DstBytes[I];
    }
}

/**
 * C-style memset operation.
 * Offset is the number of uint16_t values
 * to ignore from the beginning of S.
 */
static final function MemSet_UInt16(
    out array<int> S,
    byte C,
    int NumBytes,
    optional int Offset = 0
)
{
    local int IntIndex;
    local int ByteIndex;
    local int Shift;
    local int Mask;

    Shift = 8;
    Mask = 0xff << Shift;
    IntIndex = Offset;
    for (ByteIndex = 0; ByteIndex < NumBytes; ++ByteIndex)
    {
        S[IntIndex] = (S[IntIndex] & ~Mask) | ((C & 0xff) << Shift);
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        Mask = 0xff << Shift;
    }
}

// See MemSet_UInt16.
// TODO: move to dedicated memory class.
static final function MemSet_UInt16_Static37(
    out int S[37],
    byte C,
    int NumBytes,
    optional int Offset = 0
)
{
    local int IntIndex;
    local int ByteIndex;
    local int Shift;
    local int Mask;

    Shift = 8;
    Mask = 0xff << Shift;
    IntIndex = Offset;
    for (ByteIndex = 0; ByteIndex < NumBytes; ++ByteIndex)
    {
        S[IntIndex] = (S[IntIndex] & ~Mask) | ((C & 0xff) << Shift);
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        Mask = 0xff << Shift;
    }
}

/**
 * C-style memset operation.
 * Offset is the number of byte values
 * to ignore from the beginning of S.
 */
static final function MemSet_Byte(
    out array<byte> S,
    byte C,
    int NumBytes,
    optional int Offset = 0
)
{
    local int ByteIndex;

    for (ByteIndex = Offset; ByteIndex < NumBytes; ++ByteIndex)
    {
        S[ByteIndex] = C;
    }
}

// See MemSet_Byte.
static final function MemSet_Byte_Static66(
    out byte S[66],
    byte C,
    int NumBytes,
    optional int Offset = 0
)
{
    local int ByteIndex;

    for (ByteIndex = Offset; ByteIndex < NumBytes; ++ByteIndex)
    {
        S[ByteIndex] = C;
    }
}

/**
 * C-style memcpy operation.
 * Offsets are the number of uint16_t values
 * to ignore from the beginning of each array.
 */
static final function MemCpy(
    out array<int> Dst,
    const out array<int> Src,
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    // TODO: implement optimized MemCpy for
    // non-overlapping arrays.
    // TODO: check which parts originally used memcpy in BearSSL.

    MemMove(Dst, Src, NumBytes, DstOffset, SrcOffset);
}

/*
 * Conditional copy: src[] is copied into dst[] if and only if ctl is 1.
 * dst[] and src[] may overlap completely (but not partially).
 */
private static final function CCOPY(
    int Ctl,
    out array<int> Dst,
    const out array<int> Src,
    int Len
)
{
    local array<byte> DstBytes;
    local array<byte> SrcBytes;
    local int X;
    local int Y;
    local int I;
    local int J;
    local int IntIndex;
    local int ByteIndex;
    local int Shift;
    local int Mask;

    IntIndex = 0;
    ByteIndex = 0;
    Shift = 8;
    while (ByteIndex < Len)
    {
        SrcBytes[ByteIndex++] = (Src[IntIndex] >>> Shift) & 0xff;
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
    }

    IntIndex = 0;
    ByteIndex = 0;
    Shift = 8;
    while (ByteIndex < Len)
    {
        DstBytes[ByteIndex++] = (Dst[IntIndex] >>> Shift) & 0xff;
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
    }

    I = 0;
    J = 0;
    while (Len-- > 0)
    {
        // x = *s ++;
        // y = *d;
        // *d = MUX(ctl, x, y);
        // d ++;

        X = SrcBytes[I++];
        Y = DstBytes[J];
        DstBytes[J] = MUX(Ctl, X, Y);
        ++J;
    }

    Shift = 8;
    Mask = 0xff << Shift;
    IntIndex = 0;
    for (ByteIndex = 0; ByteIndex < Len; ++ByteIndex)
    {
        Dst[IntIndex] = (
            (Dst[IntIndex] & ~Mask) | ((DstBytes[ByteIndex] & 0xff) << Shift)
        );
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        Mask = 0xff << Shift;
    }
}

/*
 * Zeroize an integer. The announced bit length is set to the provided
 * value, and the corresponding words are set to 0.
 */
static final function Zero(
    out array<int> X,
    int BitLen
)
{
    // *x ++ = bit_len;
    // memset(x, 0, ((bit_len + 15) >> 4) * sizeof *x);
    X[0] = BitLen & 0xFFFF; // @ALIGN-32-16.
    MemSet_UInt16(X, 0, ((BitLen + 15) >>> 4) * SIZEOF_UINT16_T, 1);
}

// See Zero.
static final function Zero_Static37(
    out int X[37],
    int BitLen
)
{
    // *x ++ = bit_len;
    // memset(x, 0, ((bit_len + 15) >> 4) * sizeof *x);
    X[0] = BitLen & 0xFFFF; // @ALIGN-32-16.
    MemSet_UInt16_Static37(X, 0, ((BitLen + 15) >>> 4) * SIZEOF_UINT16_T, 1);
}

/*
 * Add b[] to a[] and return the carry (0 or 1). If ctl is 0, then a[]
 * is unmodified, but the carry is still computed and returned. The
 * arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
static final function int Add(
    out array<int> A,
    const out array<int> B,
    int Ctl
)
{
    local int Cc;
    local int U;
    local int M;
    local int Aw;
    local int Bw;
    local int Naw;

    Cc = 0;
    M = (A[0] + 31) >>> 4;

    for (U = 1; U < M; ++U)
    {
        Aw = A[U];
        Bw = B[U];
        Naw = Aw + Bw + Cc;
        Cc = Naw >>> 15;
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw) & 0xFFFF; // @ALIGN-32-16.
    }

    return Cc;
}

// See Add.
static final function int Add_Static37(
    out int A[37],
    const out int B[37],
    int Ctl
)
{
    local int Cc;
    local int U;
    local int M;
    local int Aw;
    local int Bw;
    local int Naw;

    Cc = 0;
    M = (A[0] + 31) >>> 4;

    for (U = 1; U < M; ++U)
    {
        Aw = A[U];
        Bw = B[U];
        Naw = Aw + Bw + Cc;
        Cc = Naw >>> 15;
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw) & 0xFFFF; // @ALIGN-32-16.
    }

    return Cc;
}

// See Add.
static final function int Add_Static37_DynB(
    out int A[37],
    const out array<int> B,
    int Ctl
)
{
    local int Cc;
    local int U;
    local int M;
    local int Aw;
    local int Bw;
    local int Naw;

    Cc = 0;
    M = (A[0] + 31) >>> 4;

    for (U = 1; U < M; ++U)
    {
        Aw = A[U];
        Bw = B[U];
        Naw = Aw + Bw + Cc;
        Cc = Naw >>> 15;
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw) & 0xFFFF; // @ALIGN-32-16.
    }

    return Cc;
}

/*
 * Subtract b[] from a[] and return the carry (0 or 1). If ctl is 0,
 * then a[] is unmodified, but the carry is still computed and returned.
 * The arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
static final function int Sub(
    out array<int> A,
    const out array<int> B,
    int Ctl
)
{
    local int Cc;
    local int U;
    local int M;
    local int Aw;
    local int Bw;
    local int Naw;

    Cc = 0;
    M = (A[0] + 31) >>> 4;

    if (M > A.Length)
    {
        A.Length = M;
    }

    for (U = 1; U < M; ++U)
    {
        Aw = A[U];
        Bw = B[U];
        Naw = Aw - Bw - Cc;
        CC = Naw >>> 31;
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw) & 0xFFFF; // @ALIGN-32-16.
    }

    return Cc;
}

// See Sub.
static final function int Sub_Static37_DynB(
    out int A[37],
    const out array<int> B,
    int Ctl
)
{
    local int Cc;
    local int U;
    local int M;
    local int Aw;
    local int Bw;
    local int Naw;

    Cc = 0;
    M = (A[0] + 31) >>> 4;

    for (U = 1; U < M; ++U)
    {
        Aw = A[U];
        Bw = B[U];
        Naw = Aw - Bw - Cc;
        CC = Naw >>> 31;
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw) & 0xFFFF; // @ALIGN-32-16.
    }

    return Cc;
}

// See Sub.
static final function int Sub_Static37(
    out int A[37],
    const out int B[37],
    int Ctl
)
{
    local int Cc;
    local int U;
    local int M;
    local int Aw;
    local int Bw;
    local int Naw;

    Cc = 0;
    M = (A[0] + 31) >>> 4;

    for (U = 1; U < M; ++U)
    {
        Aw = A[U];
        Bw = B[U];
        Naw = Aw - Bw - Cc;
        CC = Naw >>> 31;
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw) & 0xFFFF; // @ALIGN-32-16.
    }

    return Cc;
}


/*
 * Compute the actual bit length of an integer. The argument X should
 * point to the first (least significant) value word of the integer.
 * The len 'xlen' contains the number of 32-bit words to access.
 *
 * CT: value or length of X does not leak.
 */
static final function int BitLength(
    const out array<int> X,
    int XLen
)
{
    local int Tw;
    local int Twk;
    local int W;
    local int C;

    Tw = 0;
    Twk = 0;

    while (XLen-- > 0)
    {
        C = EQ(Tw, 0);
        W = X[XLen];
        Tw = MUX(C, W, Tw);
        Twk = MUX(C, XLen, Twk);
    }

    return (Twk << 4) + BIT_LENGTH(Tw);
}

static final function int BitLength_NonConst(
    array<int> X,
    int XLen
)
{
    local int Tw;
    local int Twk;
    local int W;
    local int C;

    Tw = 0;
    Twk = 0;

    while (XLen-- > 0)
    {
        C = EQ(Tw, 0);
        W = X[XLen];
        Tw = MUX(C, W, Tw);
        Twk = MUX(C, XLen, Twk);
    }

    return (Twk << 4) + BIT_LENGTH(Tw);
}

/*
 * Decode an integer from its big-endian unsigned representation. The
 * integer MUST be lower than m[]; the announced bit length written in
 * x[] will be equal to that of m[]. All 'len' bytes from the source are
 * read.
 *
 * Returned value is 1 if the decode value fits within the modulus, 0
 * otherwise. In the latter case, the x[] buffer will be set to 0 (but
 * still with the announced bit length of m[]).
 *
 * CT: value or length of x does not leak. Memory access pattern depends
 * only of 'len' and the announced bit length of m. Whether x fits or
 * not does not leak either.
 */
static final function int DecodeMod(
    out array<int> X,
    const out array<byte> Src,
    int Len,
    const out array<int> M
)
{
    /*
     * Two-pass algorithm: in the first pass, we determine whether the
     * value fits; in the second pass, we do the actual write.
     *
     * During the first pass, 'r' contains the comparison result so
     * far:
     *  0x00000000   value is equal to the modulus
     *  0x00000001   value is greater than the modulus
     *  0xFFFFFFFF   value is lower than the modulus
     *
     * Since we iterate starting with the least significant bytes (at
     * the end of src[]), each new comparison overrides the previous
     * except when the comparison yields 0 (equal).
     *
     * During the second pass, 'r' is either 0xFFFFFFFF (value fits)
     * or 0x00000000 (value does not fit).
     *
     * We must iterate over all bytes of the source, _and_ possibly
     * some extra virtual bytes (with value 0) so as to cover the
     * complete modulus as well. We also add 4 such extra bytes beyond
     * the modulus length because it then guarantees that no accumulated
     * partial word remains to be processed.
     */
    local int MLen;
    local int TLen;
    local int Pass;
    local int R;
    local int U;
    local int V;
    local int Acc;
    local int AccLen;
    local int B;
    local int Xw;
    local int Cc;

    MLen = (M[0] + 15) >>> 4;
    TLen = (MLen << 1);
    if (TLen < Len)
    {
        TLen = Len;
    }
    TLen += 4;
    R = 0;
    for (Pass = 0; Pass < 2; ++Pass)
    {
        V = 1;
        Acc = 0;
        AccLen = 0;

        for (U = 0; U < TLen; ++U)
        {
            if (U < Len)
            {
                B = Src[Len - 1 - U];
            }
            else
            {
                B = 0;
            }
            Acc = Acc | ((B << AccLen) & 0xFFFF); // @ALIGN-32-16. // TODO: not needed?
            AccLen += 8;
            if (AccLen >= 15)
            {
                Xw = Acc & 0x7FFF;
                AccLen -= 15;
                Acc = B >>> (8 - AccLen);
                if (V <= MLen)
                {
                    if (bool(Pass))
                    {
                        X[V] = (R & Xw) & 0xFFFF; // @ALIGN-32-16.
                    }
                    else
                    {
                        Cc = CMP(Xw, M[V]);
                        R = MUX(EQ(Cc, 0), R, Cc);
                    }
                }
                else
                {
                    if (!bool(Pass))
                    {
                        R = MUX(EQ(Xw, 0), R, 1);
                    }
                }
                ++V;
            }
        }

        /*
         * When we reach this point at the end of the first pass:
         * r is either 0, 1 or -1; we want to set r to 0 if it
         * is equal to 0 or 1, and leave it to -1 otherwise.
         *
         * When we reach this point at the end of the second pass:
         * r is either 0 or -1; we want to leave that value
         * untouched. This is a subcase of the previous.
         */
        R = R >>> 1;
        R = R | (R << 1);
    }

    X[0] = M[0];
    return R & 1;
}

/*
 * Decode an integer from its big-endian unsigned representation. The
 * "true" bit length of the integer is computed, but all words of x[]
 * corresponding to the full 'len' bytes of the source are set.
 *
 * CT: value or length of x does not leak.
 *
 * TODO: SHOULD CHECK FOR Src.Length == 0?
 * TODO: SHOULD CHECK FOR X.Length == 0?
 */
static final function Decode(
    out array<int> X,
    const out array<byte> Src,
    int Len
)
{
    local int V;
    local int Acc;
    local int AccLen;
    local int B;
    local array<int> XArr;

    V = 1;
    Acc = 0;
    AccLen = 0;
    while (Len-- > 0)
    {
        B = Src[Len];
        // Acc = Acc | ((B << AccLen) & 0xFFFF); // @ALIGN-32-16.
        Acc = Acc | (B << AccLen);
        AccLen += 8;
        if (AccLen >= 15)
        {
            X[V++] = Acc & 0x7FFF;
            AccLen -= 15;
            Acc = Acc >>> 15;
        }
    }
    if (AccLen != 0)
    {
        X[V++] = Acc & 0xFFFF; // @ALIGN-32-16.
    }

    // X[0] = BitLength(X + 1, V - 1);
    // TODO: is there a faster way of doing this in UScript?
    XArr = X;
    XArr.Remove(0, 1);
    X[0] = BitLength(XArr, V - 1);
}

static final function Decode_NonConst(
    out array<int> X,
    array<byte> Src,
    int Len
)
{
    local int V;
    local int Acc;
    local int AccLen;
    local int B;
    local array<int> XArr;

    V = 1;
    Acc = 0;
    AccLen = 0;
    while (Len-- > 0)
    {
        B = Src[Len];
        // Acc = Acc | ((B << AccLen) & 0xFFFF); // @ALIGN-32-16.
        Acc = Acc | (B << AccLen);
        AccLen += 8;
        if (AccLen >= 15)
        {
            X[V++] = Acc & 0x7FFF;
            AccLen -= 15;
            Acc = Acc >>> 15;
        }
    }
    if (AccLen != 0)
    {
        X[V++] = Acc & 0xFFFF; // @ALIGN-32-16.
    }

    // X[0] = BitLength(X + 1, V - 1);
    // TODO: is there a faster way of doing this in UScript?
    XArr = X;
    XArr.Remove(0, 1);
    X[0] = BitLength_NonConst(XArr, V - 1);
}

/*
 * Decode an integer from its big-endian unsigned representation, and
 * reduce it modulo the provided modulus m[]. The announced bit length
 * of the result is set to be equal to that of the modulus.
 *
 * x[] MUST be distinct from m[].
 */
static final function DecodeReduce(
    out array<int> X,
    const out array<byte> Src,
    int Len,
    const out array<int> M
)
{
    local int M_EBitLen;
    local int M_RBitLen;
    local int MBLen;
    local int K;
    local int Acc;
    local int AccLen;
    local int V;

    /*
     * Get the encoded bit length.
     */
    M_EBitLen = M[0];

    /*
     * Special case for an invalid (null) modulus.
     */
    if (M_EBitLen == 0)
    {
        X[0] = 0;
        return;
    }

    /*
     * Clear the destination.
     */
    Zero(X, M_EBitLen);

    /*
     * First decode directly as many bytes as possible. This requires
     * computing the actual bit length.
     */
    M_RBitLen = M_EBitLen >>> 4;
    M_RBitLen = (M_EBitLen & 15) + (M_RBitLen << 4) - M_RBitLen;
    MBLen = (M_RBitLen + 7) >>> 3;
    K = MBLen - 1;
    if (K >= Len)
    {
        Decode(X, Src, Len);
        X[0] = M_EBitLen & 0xFFFF; // @ALIGN-32-16.
        return;
    }

    Decode(X, Src, K);
    X[0] = M_EBitLen & 0xFFFF; // @ALIGN-32-16.

    /*
     * Input remaining bytes, using 15-bit words.
     */
    Acc = 0;
    AccLen = 0;
    while (K < Len)
    {
        V = Src[K++];
        Acc = (Acc << 8) | V;
        AccLen += 8;
        if (AccLen >= 15)
        {
            MulAddSmall(X, Acc >>> (AccLen - 15), M);
            AccLen -= 15;
            // Acc = Acc & (~(-1 << AccLen));
            Acc = Acc & (~(0xffffffff << AccLen));
        }
    }

    /*
     * We may have some bits accumulated. We then perform a shift to
     * be able to inject these bits as a full 15-bit word.
     */
    if (AccLen != 0)
    {
        Acc = (Acc | (X[1] << AccLen)) & 0x7FFF;
        RShift(X, 15 - AccLen);
        MulAddSmall(X, Acc, M);
    }
}

/*
 * Multiply x[] by 2^15 and then add integer z, modulo m[]. This
 * function assumes that x[] and m[] have the same announced bit
 * length, the announced bit length of m[] matches its true
 * bit length.
 *
 * x[] and m[] MUST be distinct arrays. z MUST fit in 15 bits (upper
 * bit set to 0).
 *
 * CT: only the common announced bit length of x and m leaks, not
 * the values of x, z or m.
 */
static final function MulAddSmall(
    out array<int> X,
    int Z,
    const out array<int> M
)
{
    /*
     * Constant-time: we accept to leak the exact bit length of the
     * modulus m.
     */
    local int M_BitLen;
    local int MBlr;
    local int U;
    local int MLen;
    local int Hi;
    local int A0;
    local int A;
    local int B;
    local int Q;
    local int Cc;
    local int Tb;
    local int Over;
    local int Under;
    local int Rem;
    local int Mw;
    local int Zl;
    local int Xw;
    local int Nxw;

    /*
     * Simple case: the modulus fits on one word.
     */
    M_BitLen = M[0];
    if (M_BitLen == 0)
    {
        return;
    }
    if (M_BitLen <= 15)
    {
        DivRem16((X[1] << 15) | Z, M[1], Rem);
        X[1] = Rem;
        return;
    }
    MLen = (M_BitLen + 15) >>> 4;
    MBlr = M_BitLen & 15;

`if(`isdefined(FCDEBUG_MONTY))
        `fcslog("MLen:" @ MLen);
        `fcslog("MBlr:" @ MBlr);
`endif

    /*
     * Principle: we estimate the quotient (x*2^15+z)/m by
     * doing a 30/15 division with the high words.
     *
     * Let:
     *   w = 2^15
     *   a = (w*a0 + a1) * w^N + a2
     *   b = b0 * w^N + b2
     * such that:
     *   0 <= a0 < w
     *   0 <= a1 < w
     *   0 <= a2 < w^N
     *   w/2 <= b0 < w
     *   0 <= b2 < w^N
     *   a < w*b
     * I.e. the two top words of a are a0:a1, the top word of b is
     * b0, we ensured that b0 is "full" (high bit set), and a is
     * such that the quotient q = a/b fits on one word (0 <= q < w).
     *
     * If a = b*q + r (with 0 <= r < q), then we can estimate q by
     * using a division on the top words:
     *   a0*w + a1 = b0*u + v (with 0 <= v < b0)
     * Then the following holds:
     *   0 <= u <= w
     *   u-2 <= q <= u
     */
    Hi = X[MLen];
    if (MBlr == 0)
    {
        A0 = X[MLen];
        // memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
        MemMove(X, X, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);
        X[1] = Z & 0xFFFF; // @ALIGN-32-16.
        A = (A0 << 15) + X[MLen];
        B = M[MLen];
    }
    else
    {
        A0 = (X[MLen] << (15 - MBlr)) | (X[MLen - 1] >>> MBlr);

`if(`isdefined(FCDEBUG_MONTY))
        `fcslog("A0:" @ A0);
`endif

        // memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
        MemMove(X, X, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);
        X[1] = Z & 0xFFFF; // @ALIGN-32-16.
        A = (A0 << 15) | (((X[MLen] << (15 - MBlr))
            | (X[MLen - 1] >>> MBlr)) & 0x7FFF);
        B = (M[MLen] << (15 - MBlr)) | (M[MLen - 1] >>> MBlr);
    }
    Q = DivRem16(A, B,);

`if(`isdefined(FCDEBUG_MONTY))
    `fcslog("---------");
    `fcslog("A:" @ A);
    `fcslog("B:" @ B);
    `fcslog("Q:" @ Q);
`endif

    /*
     * We computed an estimate for q, but the real one may be q,
     * q-1 or q-2; moreover, the division may have returned a value
     * 8000 or even 8001 if the two high words were identical, and
     * we want to avoid values beyond 7FFF. We thus adjust q so
     * that the "true" multiplier will be q+1, q or q-1, and q is
     * in the 0000..7FFF range.
     */
    Q = MUX(EQ(B, A0), 0x7FFF, Q - 1 + ((Q - 1) >>> 31));

    /*
     * We subtract q*m from x (x has an extra high word of value 'hi').
     * Since q may be off by 1 (in either direction), we may have to
     * add or subtract m afterwards.
     *
     * The 'tb' flag will be true (1) at the end of the loop if the
     * result is greater than or equal to the modulus (not counting
     * 'hi' or the carry).
     */
    Cc = 0;
    Tb = 1;
    for (U = 1; U <= MLen; ++U)
    {
        Mw = M[U];
        // Zl = MUL15(Mw, Q) + Cc;
        Zl = (Mw * Q) + Cc;
        Cc = Zl >>> 15;
        Zl = Zl & 0x7FFF;
        Xw = X[U];
        Nxw = Xw - Zl;
        Cc += Nxw >>> 31;
        Nxw = Nxw & 0x7FFF;
        X[U] = Nxw & 0xFFFF; // @ALIGN-32-16.
        Tb = MUX(EQ(Nxw, Mw), Tb, GT(Nxw, Mw));
    }

    /*
     * If we underestimated q, then either cc < hi (one extra bit
     * beyond the top array word), or cc == hi and tb is true (no
     * extra bit, but the result is not lower than the modulus).
     *
     * If we overestimated q, then cc > hi.
     */
    Over = GT(Cc, Hi);
    Under = (~Over) & (Tb | (`LT(Cc, Hi)));
    Add(X, M, Over);
    Sub(X, M, Under);
}

/*
 * Constant-time division. The divisor must not be larger than 16 bits,
 * and the quotient must fit on 17 bits.
 */
static final function int DivRem16(
    int X,
    int D,
    optional out int R
)
{
    local int I;
    local int Q;
    local int Ctl;

    Q = 0;
    D = D << 16;
    for (I = 16; I >= 0; --I)
    {
        Ctl = `LE(D, X);
        Q = Q | (Ctl << I);
        X -= (-Ctl) & D;
        D = D >>> 1;
    }
    R = X;

    return Q;
}

/*
 * Right-shift an integer. The shift amount must be lower than 15
 * bits.
 */
static final function RShift(
    out array<int> X,
    int Count
)
{
    local int U;
    local int Len;
    local int R;
    local int W;

    Len = (X[0] + 15) >>> 4;
    if (Len == 0)
    {
        return;
    }
    R = X[1] >>> Count;
    for (U = 2; U <= Len; ++U)
    {
        W = X[U];
        X[U - 1] = ((W << (15 - Count)) | R) & 0x7FFF;
        R = W >>> Count;
    }
    X[Len] = R & 0xFFFF; // @ALIGN-32-16.
}

/*
 * Encode an integer into its big-endian unsigned representation. The
 * output length in bytes is provided (parameter 'len'); if the length
 * is too short then the integer is appropriately truncated; if it is
 * too long then the extra bytes are set to 0.
 */
static final function Encode(
    out array<byte> Dst,
    int Len,
    const out array<int> X
)
{
    local int U;
    local int XLen;
    local int Acc;
    local int AccLen;

    XLen = (X[0] + 15) >>> 4;
    if (XLen == 0)
    {
        // NOTE: BearSSL assumes all parameters are user-allocated.
        // In UnrealScript we'll make an exception here to avoid a bug
        // where MemSet is called with Len == 0. TODO: SHOULD WE DO THIS?
        // Probably no way to avoid this since we are not dealing with
        // pointers in UScript like original BearSSL code does.
        if (Len == 0)
        {
            Len = 1;
        }

        // memset(dst, 0, len);
        MemSet_Byte(Dst, 0, Len);
        return;
    }
    U = 1;
    Acc = 0;
    AccLen = 0;
    while (Len-- > 0)
    {
        if (AccLen < 8)
        {
            if (U <= XLen)
            {
                Acc += X[U++] << AccLen;
            }
            AccLen += 15;
        }
        Dst[Len] = Acc;
        Acc = Acc >>> 8;
        AccLen -= 8;
    }
}

// See Encode.
static final function Encode_Static66(
    out byte Dst[66],
    int Len,
    const out array<int> X
)
{
    local int U;
    local int XLen;
    local int Acc;
    local int AccLen;

    XLen = (X[0] + 15) >>> 4;
    if (XLen == 0)
    {
        // NOTE: BearSSL assumes all parameters are user-allocated.
        // In UnrealScript we'll make an exception here to avoid a bug
        // where MemSet is called with Len == 0. TODO: SHOULD WE DO THIS?
        // Probably no way to avoid this since we are not dealing with
        // pointers in UScript like original BearSSL code does.
        if (Len == 0)
        {
            Len = 1;
        }

        // memset(dst, 0, len);
        MemSet_Byte_Static66(Dst, 0, Len);
        return;
    }
    U = 1;
    Acc = 0;
    AccLen = 0;
    while (Len-- > 0)
    {
        if (AccLen < 8)
        {
            if (U <= XLen)
            {
                Acc += X[U++] << AccLen;
            }
            AccLen += 15;
        }
        Dst[Len] = Acc;
        Acc = Acc >>> 8;
        AccLen -= 8;
    }
}

/*
 * Convert a modular integer back from Montgomery representation. The
 * integer x[] MUST be lower than m[], but with the same announced bit
 * length. The "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is
 * the least significant value word of m[] (this works only if m[] is
 * an odd integer).
 */
static final function FromMonty(
    out array<int> X,
    const out array<int> M,
    int M0I
)
{
    local int Len;
    local int U;
    local int V;
    local int F;
    local int Cc;
    local int Z;

    Len = (M[0] + 15) >>> 4;
    for (U = 0; U < Len; ++U)
    {
        // F = MUL15(X[1], M0I) & 0x7FFF;
        F = (X[1] * M0I) & 0x7FFF;
        Cc = 0;
        for (V = 0; V < Len; ++V)
        {
            // z = (uint32_t)x[v + 1] + MUL15(f, m[v + 1]) + cc;
            Z = X[V + 1] + (F * M[V + 1]) + Cc;
            Cc = Z >>> 15;
            if (V != 0)
            {
                X[V] = Z & 0x7FFF;
            }
        }
        X[Len] = Cc;
    }

    /*
     * We may have to do an extra subtraction, but only if the
     * value in x[] is indeed greater than or equal to that of m[],
     * which is why we must do two calls (first call computes the
     * carry, second call performs the subtraction only if the carry
     * is 0).
     */
    Sub(X, M, NOT(Sub(X, M, 0)));
}

/*
 * Convert a modular integer to Montgomery representation. The integer x[]
 * MUST be lower than m[], but with the same announced bit length.
 */
static final function ToMonty(
    out array<int> X,
    const out array<int> M
)
{
    local int K;

`if(`isdefined(FCDEBUG_MONTY))
    `fcslog("-----------ToMonty-----------------");
    `fcslog("M:" @ class'FCryptoBigInt'.static.WordsToString(M));
`endif

    for (K = (M[0] + 15) >>> 4; K > 0; --K)
    {

`if(`isdefined(FCDEBUG_MONTY))
        `fcslog("Before MulAddSmall");
        `fcslog("K:" @ K);
        `fcslog("X:" @ class'FCryptoBigInt'.static.WordsToString(X));
`endif

        MulAddSmall(X, 0, M);

`if(`isdefined(FCDEBUG_MONTY))
        `fcslog("After MulAddSmall");
        `fcslog("K:" @ K);
        `fcslog("X:" @ class'FCryptoBigInt'.static.WordsToString(X));
`endif

    }

`if(`isdefined(FCDEBUG_MONTY))
    `fcslog("-----------------------------------");
`endif
}

/*
 * Test whether an integer is zero.
 *
 * This function is called "BIsZero" because
 * "IsZero" would clash with Object::IsZero.
 */
static final function int BIsZero(const out array<int> X)
{
    local int Z;
    local int U;

    Z = 0;
    for (U = (X[0] + 15) >>> 4; U > 0; --U)
    {
        Z = Z | X[U];
    }
    return ~(Z | -Z) >>> 31;
}

// See IsZero.
static final function int BIsZero_Static37(const out int X[37])
{
    local int Z;
    local int U;

    Z = 0;
    for (U = (X[0] + 15) >>> 4; U > 0; --U)
    {
        Z = Z | X[U];
    }
    return ~(Z | -Z) >>> 31;
}

/*
 * Negate big integer conditionally. The value consists of 'len' words,
 * with 15 bits in each word (the top bit of each word should be 0,
 * except possibly for the last word). If 'ctl' is 1, the negation is
 * computed; otherwise, if 'ctl' is 0, then the value is unchanged.
 */
static final function CondNegate(
    out array<int> A,
    int Len,
    int Ctl
)
{
    local int K;
    local int Cc;
    local int Xm;
    local int Aw;

    Cc = Ctl;
    Xm = 0x7FFF & ~Ctl;
    for (K = 0; K < Len; ++K)
    {
        Aw = A[K];
        Aw = (Aw ^ Xm) + Cc;
        A[K] = Aw & 0x7FFF;
        Cc = (Aw >>> 15) & 1;
    }
}

/*
 * Finish modular reduction. Rules on input parameters:
 *
 *   if neg = 1, then -m <= a < 0
 *   if neg = 0, then 0 <= a < 2*m
 *
 * If neg = 0, then the top word of a[] may use 16 bits.
 *
 * Also, modulus m must be odd.
 */
static final function FinishMod(
    out array<int> A,
    int Len,
    const out array<int> M,
    int Neg
)
{
    local int K;
    local int Cc;
    local int Xm;
    local int Ym;
    local int Aw;
    local int Mw;

    /*
     * First pass: compare a (assumed nonnegative) with m.
     */
    Cc = 0;
    for (K = 0; K < Len; ++K)
    {
        Aw = A[K];
        Mw = M[K];
        Cc = (Aw - Mw - Cc) >>> 31;
    }

    /*
    * At this point:
     *   if neg = 1, then we must add m (regardless of cc)
     *   if neg = 0 and cc = 0, then we must subtract m
     *   if neg = 0 and cc = 1, then we must do nothing
     */
    Xm = 0x7FFF & -Neg;
    Ym = -(Neg | (1 - Cc));
    Cc = Neg;
    for (K = 0; K < Len; ++K)
    {
        Aw = A[K];
        Mw = (M[K] ^ Xm) & Ym;
        Aw = Aw - Mw - Cc;
        A[K] = Aw & 0x7FFF;
        Cc = Aw >>> 31;
    }
}

/*
 * Compute:
 *   a <- (a*pa+b*pb)/(2^15)
 *   b <- (a*qa+b*qb)/(2^15)
 * The division is assumed to be exact (i.e. the low word is dropped).
 * If the final a is negative, then it is negated. Similarly for b.
 * Returned value is the combination of two bits:
 *   bit 0: 1 if a had to be negated, 0 otherwise
 *   bit 1: 1 if b had to be negated, 0 otherwise
 *
 * Factors pa, pb, qa and qb must be at most 2^15 in absolute value.
 * Source integers a and b must be nonnegative; top word is not allowed
 * to contain an extra 16th bit.
 */
static final function int CoReduce(
    out array<int> A,
    out array<int> B,
    int Len,
    int Pa,
    int Pb,
    int Qa,
    int Qb
)
{
    local int K;
    local int Cca;
    local int Ccb;
    local int NegA;
    local int NegB;
    local int Wa;
    local int Wb;
    local int Za;
    local int Zb;
    local int Tta;
    local int Ttb;

    Cca = 0;
    Ccb = 0;
    for (K = 0; K < Len; ++K)
    {
        /*
         * Since:
         *   |pa| <= 2^15
         *   |pb| <= 2^15
         *   0 <= wa <= 2^15 - 1
         *   0 <= wb <= 2^15 - 1
         *   |Cca| <= 2^16 - 1
         * Then:
         *   |za| <= (2^15-1)*(2^16) + (2^16-1) = 2^31 - 1
         *
         * Thus, the new value of Cca is such that |Cca| <= 2^16 - 1.
         * The same applies to Ccb.
         */
        Wa = A[K];
        Wb = B[K];
        Za = Wa * Pa + Wb * Pb + Cca;
        Zb = Wa * Qa + Wb * Qb + Ccb;
        if (K > 0)
        {
            A[K - 1] = Za & 0x7FFF;
            B[K - 1] = Zb & 0x7FFF;
        }
        Tta = Za >>> 15;
        Ttb = Zb >>> 15;
        Cca = Tta; // cca = *(int16_t *)&tta;
        Ccb = Ttb; // ccb = *(int16_t *)&ttb;
    }
    A[Len - 1] = Cca;
    B[Len - 1] = Ccb;
    NegA = Cca >>> 31;
    NegB = Ccb >>> 31;
    CondNegate(A, Len, NegA);
    CondNegate(B, Len, NegB);
    return NegA | (NegB << 1);
}

/*
 * Compute:
 *   a <- (a*pa+b*pb)/(2^15) mod m
 *   b <- (a*qa+b*qb)/(2^15) mod m
 *
 * m0i is equal to -1/m[0] mod 2^15.
 *
 * Factors pa, pb, qa and qb must be at most 2^15 in absolute value.
 * Source integers a and b must be nonnegative; top word is not allowed
 * to contain an extra 16th bit.
 */
static final function CoReduceMod(
    out array<int> A,
    out array<int> B,
    int Len,
    int Pa,
    int Pb,
    int Qa,
    int Qb,
    const out array<int> M,
    int M0I
)
{
    local int K;
    local int Cca;
    local int Ccb;
    local int Fa;
    local int Fb;
    local int Wa;
    local int Wb;
    local int Za;
    local int Zb;
    local int Tta;
    local int Ttb;

    Cca = 0;
    Ccb = 0;
    Fa = (A[0] * Pa + B[0] * Pb * M0I) & 0x7FFF;
    Fb = (A[0] * Qa + B[0] * Qb * M0I) & 0x7FFF;
    for (K = 0; K < Len; ++K)
    {
        /*
         * In this loop, carries 'cca' and 'ccb' always fit on
         * 17 bits (in absolute value).
         */
        Wa = A[K];
        Wb = B[K];
        Za = Wa * Pa + Wb * Pb + M[K] * Fa + Cca;
        Zb = Wa * Qa + Wb * Qb + M[K] * Fb + Ccb;
        if (K > 0)
        {
            A[K - 1] = Za & 0x7FFF;
            B[K - 1] = Zb & 0x7FFF;
        }

        /*
         * The XOR-and-sub construction below does an arithmetic
         * right shift in a portable way (technically, right-shifting
         * a negative signed value is implementation-defined in C).
         */
        Tta = Za >>> 15;
        Ttb = Zb >>> 15;
        Tta = (Tta ^ (1 << 16)) - (1 << 16);
        Ttb = (TTb ^ (1 << 16)) - (1 << 16);
        Cca = Tta;
        Ccb = CCb;
    }
    A[Len - 1] = Cca;
    B[Len - 1] = Ccb;

    /*
     * At this point:
     *   -m <= a < 2*m
     *   -m <= b < 2*m
     * (this is a case of Montgomery reduction)
     * The top word of 'a' and 'b' may have a 16-th bit set.
     * We may have to add or subtract the modulus.
     */
    FinishMod(A, Len, M, Cca >>> 31);
    FinishMod(B, Len, M, Ccb >>> 31);
}

/*
 * Compute x/y mod m, result in x. Values x and y must be between 0 and
 * m-1, and have the same announced bit length as m. Modulus m must be
 * odd. The "m0i" parameter is equal to -1/m mod 2^31. The array 't'
 * must point to a temporary area that can hold at least three integers
 * of the size of m.
 *
 * m may not overlap x and y. x and y may overlap each other (this can
 * be useful to test whether a value is invertible modulo m). t must be
 * disjoint from all other arrays.
 *
 * Returned value is 1 on success, 0 otherwise. Success is attained if
 * y is invertible modulo m.
 */
static final function int ModDiv(
    out array<int> X,
    const out array<int> Y,
    const out array<int> M,
    int M0I,
    out array<int> T
)
{
    /*
     * Algorithm is an extended binary GCD. We maintain four values
     * a, b, u and v, with the following invariants:
     *
     *   a * x = y * u mod m
     *   b * x = y * v mod m
     *
     * Starting values are:
     *
     *   a = y
     *   b = m
     *   u = x
     *   v = 0
     *
     * The formal definition of the algorithm is a sequence of steps:
     *
     *   - If a is even, then a <- a/2 and u <- u/2 mod m.
     *   - Otherwise, if b is even, then b <- b/2 and v <- v/2 mod m.
     *   - Otherwise, if a > b, then a <- (a-b)/2 and u <- (u-v)/2 mod m.
     *   - Otherwise, b <- (b-a)/2 and v <- (v-u)/2 mod m.
     *
     * Algorithm stops when a = b. At that point, they both are equal
     * to GCD(y,m); the modular division succeeds if that value is 1.
     * The result of the modular division is then u (or v: both are
     * equal at that point).
     *
     * Each step makes either a or b shrink by at least one bit; hence,
     * if m has bit length k bits, then 2k-2 steps are sufficient.
     *
     *
     * Though complexity is quadratic in the size of m, the bit-by-bit
     * processing is not very efficient. We can speed up processing by
     * remarking that the decisions are taken based only on observation
     * of the top and low bits of a and b.
     *
     * In the loop below, at each iteration, we use the two top words
     * of a and b, and the low words of a and b, to compute reduction
     * parameters pa, pb, qa and qb such that the new values for a
     * and b are:
     *
     *   a' = (a*pa + b*pb) / (2^15)
     *   b' = (a*qa + b*qb) / (2^15)
     *
     * the division being exact.
     *
     * Since the choices are based on the top words, they may be slightly
     * off, requiring an optional correction: if a' < 0, then we replace
     * pa with -pa, and pb with -pb. The total length of a and b is
     * thus reduced by at least 14 bits at each iteration.
     *
     * The stopping conditions are still the same, though: when a
     * and b become equal, they must be both odd (since m is odd,
     * the GCD cannot be even), therefore the next operation is a
     * subtraction, and one of the values becomes 0. At that point,
     * nothing else happens, i.e. one value is stuck at 0, and the
     * other one is the GCD.
     */
    local int Len;
    local int K;
    local array<int> A;
    local array<int> B;
    local array<int> U;
    local array<int> V;
    local array<int> MCopy;
    local int Num;
    local int R;
    local int J;
    local int C0;
    local int C1;
    local int A0;
    local int A1;
    local int B0;
    local int B1;
    local int A_Hi;
    local int B_Hi;
    local int A_Lo;
    local int B_Lo;
    local int Pa;
    local int Pb;
    local int Qa;
    local int Qb;
    local int I;
    local int Aw;
    local int Bw;
    local int Oa;
    local int Ob;
    local int CAB;
    local int CBA;
    local int CA;

    Len = (M[0] + 15) >>> 4;
    A = T;

    // B = A + Len;
    B = A;
    B.Remove(0, Len);

    // U = X + 1;
    U = X;
    U.Remove(0, 1);

    // V = B + Len;
    V = B;
    V.Remove(0, Len);

    // TODO: Potential issues in UScript with
    // memset when Len == 0.

    // memcpy(a, y + 1, len * sizeof *y);
    // memcpy(b, m + 1, len * sizeof *m);
    // memset(v, 0, len * sizeof *v);
    MemCpy(A, Y, Len * SIZEOF_UINT16_T, 0, 1);
    MemCpy(B, M, Len * SIZEOF_UINT16_T, 0, 1);
    MemSet_UInt16(V, 0, Len * SIZEOF_UINT16_T);

    /*
     * Loop below ensures that a and b are reduced by some bits each,
     * for a total of at least 14 bits.
     */
    for (Num = ((M[0] - (M[0] >>> 4)) << 1) + 14; Num >= 14; Num -= 14)
    {
        /*
         * Extract top words of a and b. If j is the highest
         * index >= 1 such that a[j] != 0 or b[j] != 0, then we want
         * (a[j] << 15) + a[j - 1], and (b[j] << 15) + b[j - 1].
         * If a and b are down to one word each, then we use a[0]
         * and b[0].
         */
        // c0 = (uint32_t)-1;
        // c1 = (uint32_t)-1;
        c0 = -1;
        c1 = -1;
        A0 = 0;
        A1 = 0;
        B0 = 0;
        B1 = 0;
        J = Len;
        while (J-- > 0)
        {
            Aw = A[J];
            Bw = B[J];
            A0 = A0 ^ ((A0 ^ Aw) & C0);
            A1 = A1 ^ ((A1 ^ Aw) & C1);
            B0 = B0 ^ ((A1 ^ Bw) & C0);
            B1 = B1 ^ ((A1 ^ Bw) & C1);
            C1 = C0;
            C0 = C0 & ((((Aw | Bw) + 0xFFFF) >>> 16) - 1);
        }

        /*
         * If c1 = 0, then we grabbed two words for a and b.
         * If c1 != 0 but c0 = 0, then we grabbed one word. It
         * is not possible that c1 != 0 and c0 != 0, because that
         * would mean that both integers are zero.
         */
        A1 = A1 | (A0 & C1);
        A0 = A0 & (~C1);
        B1 = B1 | (B0 & C1);
        B0 = B0 & (~C1);
        A_Hi = (A0 << 15) + A1;
        B_Hi = (B0 << 15) + B1;
        A_Lo = A[0];
        B_Lo = B[0];

        /*
         * Compute reduction factors:
         *
         *   a' = a*pa + b*pb
         *   b' = a*qa + b*qb
         *
         * such that a' and b' are both multiple of 2^15, but are
         * only marginally larger than a and b.
         */
        Pa = 1;
        Pb = 0;
        Qa = 0;
        Qb = 1;
        for (I = 0; I < 15; ++I) // TODO: can be unrolled.
        {
            /*
             * At each iteration:
             *
             *   a <- (a-b)/2 if: a is odd, b is odd, a_hi > b_hi
             *   b <- (b-a)/2 if: a is odd, b is odd, a_hi <= b_hi
             *   a <- a/2 if: a is even
             *   b <- b/2 if: a is odd, b is even
             *
             * We multiply a_lo and b_lo by 2 at each
             * iteration, thus a division by 2 really is a
             * non-multiplication by 2.
             */

            /*
             * cAB = 1 if b must be subtracted from a
             * cBA = 1 if a must be subtracted from b
             * cA = 1 if a is divided by 2, 0 otherwise
             *
             * Rules:
             *
             *   cAB and cBA cannot be both 1.
             *   if a is not divided by 2, b is.
             */
            R = GT(A_Hi, A_Lo);
            Oa = (A_Lo >>> I) & 1;
            Ob = (B_Lo >>> I) & 1;
            CAB = Oa & Ob & R;
            CBA = Oa & Ob & NOT(R);
            CA = CAB | NOT(Oa);

            /*
             * Conditional subtractions.
             */
            A_Lo -= B_Lo & -CAB;
            A_Hi -= B_Hi & -CAB;
            Pa -= Qa & -CAB;
            Pb -= Qb & -CAB;
            B_Lo -= A_Lo & -CBA;
            B_Hi -= A_Hi & -CBA;
            Qa -= Pa & -CBA;
            Qb -= Pb & -CBA;

            /*
             * Shifting.
             */
            A_Lo += A_Lo & (Ca - 1);
            Pa += Pa & (CA - 1);
            Pb += Pb & (CA - 1);
            A_Hi = A_Hi ^ ((A_Hi ^ (A_Hi >>> 1)) & -CA);
            B_Lo += B_Lo - CA;
            Qa += Qb & -CA;
            Qb += Qb & -CA;
            B_Hi = B_Hi ^ ((B_Hi ^ (B_Hi >>> 1)) & (CA - 1));
        }

        /*
         * Replace a and b with new values a' and b'.
         */
        R = CoReduce(A, B, Len, Pa, Pb, Qa, Qb);
        Pa -= Pa * ((R & 1) << 1);
        Pb -= Pb * ((R & 1) << 1);
        Qa -= Qa * (R & 2);
        Qb -= Qb * (R & 2);
        // CoReduceMod(U, V, Len, Pa, Pb, Qa, Qb, M + 1, M0I);
        MCopy = M;
        MCopy.Remove(0, 1);
        CoReduceMod(U, V, Len, Pa, Pb, Qa, Qb, MCopy, M0I);
    }

    /*
     * Now one of the arrays should be 0, and the other contains
     * the GCD. If a is 0, then u is 0 as well, and v contains
     * the division result.
     * Result is correct if and only if GCD is 1.
     */
    R = (A[0] | B[0]) ^ 1;
    U[0] = U[0] | (V[0]);
    for (K = 1; K < Len; ++K)
    {
        R = R | (A[K] | B[K]);
        U[K] = U[K] | (V[K]);
    }
    return EQ0(R);
}

/*
 * Compute a modular exponentiation. x[] MUST be an integer modulo m[]
 * (same announced bit length, lower value). m[] MUST be odd. The
 * exponent is in big-endian unsigned notation, over 'elen' bytes. The
 * "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer). The t1[] and t2[] parameters must be temporary arrays,
 * each large enough to accommodate an integer with the same size as m[].
 */
static final function ModPow(
    out array<int> X,
    const out array<byte> E,
    int ELen,
    const out array<int> M,
    int M0I,
    out array<int> T1,
    out array<int> T2
)
{
    local int MLen;
    local int K;
    local int Ctl;

    MLen = ((M[0] + 31) >>> 4) * SIZEOF_UINT16_T;
    MemCpy(T1, X, MLen);
    ToMonty(T1, M);
    Zero(X, M[0]);
    X[1] = 1;
    for (K = 0; K < (ELen << 3); ++K)
    {
        Ctl = (E[ELen - 1 - (K >>> 3)] >>> (K & 7)) & 1;
        MontyMul(T2, X, T1, M, M0I);
        CCOPY(Ctl, X, T2, MLen);
        MontyMul(T2, T1, T1, M, M0I);
        MemCpy(T1, T2, MLen);
    }
}

// See ModPow.
static final function ModPow_S37_S66_Dyn_S37_S37(
    out int X[37],
    const out byte E[66],
    int ELen,
    const out array<int> M,
    int M0I,
    out int T1[37],
    out int T2[37]
)
{
    local int MLen;
    local int K;
    local int Ctl;

    // TODO: body for this func.

    MLen = ((M[0] + 31) >>> 4) * SIZEOF_UINT16_T;
    // MemCpy(T1, X, MLen);
    // ToMonty(T1, M);
    // Zero(X, M[0]);
    // X[1] = 1;
    // for (K = 0; K < (ELen << 3); ++K)
    // {
    //     Ctl = (E[ELen - 1 - (K >>> 3)] >>> (K & 7)) & 1;
    //     MontyMul_S37_S37_S37_DynM(T2, X, T1, M, M0I);
    //     CCOPY(Ctl, X, T2, MLen);
    //     MontyMul_S37_S37_S37_DynM(T2, T1, T1, M, M0I);
    //     MemCpy(T1, T2, MLen);
    // }
}

/*
 * Compute a modular Montgomery multiplication. d[] is filled with the
 * value of x*y/R modulo m[] (where R is the Montgomery factor). The
 * array d[] MUST be distinct from x[], y[] and m[]. x[] and y[] MUST be
 * numerically lower than m[]. x[] and y[] MAY be the same array. The
 * "m0i" parameter is equal to -(1/m0) mod 2^32, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer).
 */
static final function MontyMul(
    out array<int> D,
    const out array<int> X,
    const out array<int> Y,
    const out array<int> M,
    int M0I
)
{
    local int Len;
    local int Len4;
    local int U;
    local int V;
    local int Dh;
    local int F;
    local int Xu;
    local int R;
    local int Zh;
    local int Z;

    Len = (M[0] + 15) >>> 4;
    Len4 = Len & ~3;
    Zero(D, M[0]);
    Dh = 0;
    for (U = 0; U < Len; ++U)
    {
        Xu = X[U + 1];
        // f = MUL15((d[1] + MUL15(x[u + 1], y[1])) & 0x7FFF, m0i) & 0x7FFF;
        F = (((D[1] + (X[U + 1] * Y[1])) & 0x7FFF) * M0I) & 0x7FFF;
        R = 0;
        for (V = 0; V < Len4; V += 4)
        {
            Z = D[V + 1] + (Xu * Y[V + 1]) + (F * M[V + 1]) + R;
            R = Z >>> 15;
            D[V/*+0*/] = Z & 0x7FFF;
            Z = D[V + 2] + (Xu * Y[V + 2]) + (F * M[V + 2]) + R;
            R = Z >>> 15;
            D[V + 1] = Z & 0x7FFF;
            Z = D[V + 3] + (Xu * Y[V + 3]) + (F * M[V + 3]) + R;
            R = Z >>> 15;
            D[V + 2] = Z & 0x7FFF;
            Z = D[V + 4] + (Xu * Y[V + 4]) + (F * M[V + 4]) + R;
            R = Z >>> 15;
            D[V + 3] = Z & 0x7FFF;
        }

        for (Z = 0; V < Len; ++V)
        {
            Z = D[V + 1] + (Xu * Y[V + 1]) + (F * M[V + 1]) + R;
            R = Z >>> 15;
            D[V/*+0*/] = Z & 0x7FFF;
        }

        Zh = Dh + R;
        D[Len] = Zh & 0x7FFF;
        Dh = Zh >>> 15;
    }

    /*
     * Restore the bit length (it was overwritten in the loop above).
     */
    D[0] = M[0];

    /*
     * d[] may be greater than m[], but it is still lower than twice
     * the modulus.
     */
    Sub(D, M, NEQ(DH, 0) | NOT(Sub(D, M, 0)));
}

// See MontyMul.
static final function MontyMul_S37_S37_S37_DynM(
    out int D[37],
    const out int X[37],
    const out int Y[37],
    const out array<int> M,
    int M0I
)
{
    local int Len;
    local int Len4;
    local int U;
    local int V;
    local int Dh;
    local int F;
    local int Xu;
    local int R;
    local int Zh;
    local int Z;

    Len = (M[0] + 15) >>> 4;
    Len4 = Len & ~3;
    Zero_Static37(D, M[0]);
    Dh = 0;
    for (U = 0; U < Len; ++U)
    {
        Xu = X[U + 1];
        // f = MUL15((d[1] + MUL15(x[u + 1], y[1])) & 0x7FFF, m0i) & 0x7FFF;
        F = (((D[1] + (X[U + 1] * Y[1])) & 0x7FFF) * M0I) & 0x7FFF;
        R = 0;
        for (V = 0; V < Len4; V += 4)
        {
            Z = D[V + 1] + (Xu * Y[V + 1]) + (F * M[V + 1]) + R;
            R = Z >>> 15;
            D[V/*+0*/] = Z & 0x7FFF;
            Z = D[V + 2] + (Xu * Y[V + 2]) + (F * M[V + 2]) + R;
            R = Z >>> 15;
            D[V + 1] = Z & 0x7FFF;
            Z = D[V + 3] + (Xu * Y[V + 3]) + (F * M[V + 3]) + R;
            R = Z >>> 15;
            D[V + 2] = Z & 0x7FFF;
            Z = D[V + 4] + (Xu * Y[V + 4]) + (F * M[V + 4]) + R;
            R = Z >>> 15;
            D[V + 3] = Z & 0x7FFF;
        }

        for (Z = 0; V < Len; ++V)
        {
            Z = D[V + 1] + (Xu * Y[V + 1]) + (F * M[V + 1]) + R;
            R = Z >>> 15;
            D[V/*+0*/] = Z & 0x7FFF;
        }

        Zh = Dh + R;
        D[Len] = Zh & 0x7FFF;
        Dh = Zh >>> 15;
    }

    /*
     * Restore the bit length (it was overwritten in the loop above).
     */
    D[0] = M[0];

    /*
     * d[] may be greater than m[], but it is still lower than twice
     * the modulus.
     */
    Sub_Static37_DynB(D, M, NEQ(DH, 0) | NOT(Sub_Static37_DynB(D, M, 0)));
}

/*
 * Compute a modular exponentiation. x[] MUST be an integer modulo m[]
 * (same announced bit length, lower value). m[] MUST be odd. The
 * exponent is in big-endian unsigned notation, over 'elen' bytes. The
 * "m0i" parameter is equal to -(1/m0) mod 2^31, where m0 is the least
 * significant value word of m[] (this works only if m[] is an odd
 * integer). The tmp[] array is used for temporaries, and has size
 * 'twlen' words; it must be large enough to accommodate at least two
 * temporary values with the same size as m[] (including the leading
 * "bit length" word). If there is room for more temporaries, then this
 * function may use the extra room for window-based optimisation,
 * resulting in faster computations.
 *
 * Returned value is 1 on success, 0 on error. An error is reported if
 * the provided tmp[] array is too short.
 */
static final function int ModPowOpt(
    out array<int> X,
    const out array<byte> E,
    int ELen,
    const out array<int> M,
    int M0I,
    out array<int> Tmp,
    int TWLen
)
{
    local int MLen;
    local int MWLen;
    local array<int> T1;
    local array<int> T2;
    local array<int> Base;
    local array<int> BaseCopy;
    local int U;
    local int V;
    local int Acc;
    local int AccLen;
    local int WinLen;
    local int I;
    local int K;
    local int Bits;
    local int EIndex;
    local int Mask;

    /*
     * Get modulus size.
     */
    MWLen = (M[0] + 31) >>> 4;
    MLen = MWLen * SIZEOF_UINT16_T;
    MWLen += (MWLen & 1);
    T1 = Tmp;
    // t2 = tmp + mwlen;
    T2 = Tmp;
    T2.Remove(0, MWLen);

    /*
     * Compute possible window size, with a maximum of 5 bits.
     * When the window has size 1 bit, we use a specific code
     * that requires only two temporaries. Otherwise, for a
     * window of k bits, we need 2^k+1 temporaries.
     */
    if (TWLen < (MWLen << 1))
    {
        return 0;
    }
    for (WinLen = 5; WinLen > 1; --WinLen)
    {
        if (((1 << WinLen) + 1) * MWLen <= TWLen)
        {
            break;
        }
    }

    /*
     * Everything is done in Montgomery representation.
     */
    ToMonty(X, M);

    /*
     * Compute window contents. If the window has size one bit only,
     * then t2 is set to x; otherwise, t2[0] is left untouched, and
     * t2[k] is set to x^k (for k >= 1).
     */
    if (WinLen == 1)
    {
        MemCpy(T2, X, MLen);
    }
    else
    {
        // memcpy(t2 + mwlen, x, mlen);
        MemCpy(T2, X, MLen, MWLen);
        // base = t2 + mwlen;
        Base = T2;
        Base.Remove(0, MWLen);
        for (U = 2; U < (1 << WinLen); ++U)
        {
            // TODO: might need to double-check this!

            // br_i15_montymul(base + mwlen, base, x, m, m0i);
            BaseCopy = Base;
            BaseCopy.Remove(0, MWLen);
            MontyMul(BaseCopy, Base, X, M, M0I);
            Base = BaseCopy;

            // base += mwlen;
            Base.Remove(0, MWLen);
        }
    }

    /*
     * We need to set x to 1, in Montgomery representation. This can
     * be done efficiently by setting the high word to 1, then doing
     * one word-sized shift.
     */
    Zero(X, M[0]);
    X[(M[0] + 15) >>> 4] = 1;
    MulAddSmall(X, 0, M);

    /*
     * We process bits from most to least significant. At each
     * loop iteration, we have acc_len bits in acc.
     */
    Acc = 0;
    AccLen = 0;
    EIndex = 0;
    while (AccLen > 0 || ELen > 0)
    {
        /*
         * Get the next bits.
         */
        K = WinLen;
        if (AccLen < WinLen)
        {
            if (ELen > 0)
            {
                Acc = (Acc << 8) | E[EIndex++];
                --ELen;
                AccLen += 8;
            }
            else
            {
                K = AccLen;
            }
        }
        Bits = (Acc >>> (AccLen - K)) & ((1 << K) - 1);
        AccLen -= K;

        /*
         * We could get exactly k bits. Compute k squarings.
         */
        for (I = 0; I < K; ++I)
        {
            MontyMul(T1, X, X, M, M0I);
            MemCpy(X, T1, MLen);
        }

        /*
         * Window lookup: we want to set t2 to the window
         * lookup value, assuming the bits are non-zero. If
         * the window length is 1 bit only, then t2 is
         * already set; otherwise, we do a constant-time lookup.
         */
        if (WinLen > 1)
        {
            Zero(T2, M[0]);
            // Base = T2 + MWLen;
            Base = T2;
            Base.Remove(0, MWLen);
            for (U = 1; U < (1 << K); ++U)
            {
                Mask = -EQ(U, Bits);
                for (V = 1; V < MWLen; ++V)
                {
                    T2[V] = T2[V] | (Mask & Base[V]);
                }
                Base.Remove(0, MWLen);
            }
        }

        /*
         * Multiply with the looked-up value. We keep the
         * product only if the exponent bits are not all-zero.
         */
        MontyMul(T1, X, T2, M, M0I);
        CCOPY(NEQ(Bits, 0), X, T1, MLen);
    }

    /*
     * Convert back from Montgomery representation, and exit.
     */
    FromMonty(X, M, M0I);
    return 1;
}

/*
 * Compute d+a*b, result in d. The initial announced bit length of d[]
 * MUST match that of a[]. The d[] array MUST be large enough to
 * accommodate the full result, plus (possibly) an extra word. The
 * resulting announced bit length of d[] will be the sum of the announced
 * bit lengths of a[] and b[] (therefore, it may be larger than the actual
 * bit length of the numerical result).
 *
 * a[] and b[] may be the same array. d[] must be disjoint from both a[]
 * and b[].
 */
static final function MulAcc(
    out array<int> D,
    const out array<int> A,
    const out array<int> B
)
{
    local int ALen;
    local int BLen;
    local int U;
    local int Dl;
    local int Dh;
    local int F;
    local int V;
    local int Cc;
    local int Z;

    ALen = (A[0] + 15) >>> 4;
    BLen = (B[0] + 15) >>> 4;

    /*
     * Announced bit length of d[] will be the sum of the announced
     * bit lengths of a[] and b[]; but the lengths are encoded.
     */
    Dl = (A[0] & 15) + (B[0] & 15);
    Dh = (A[0] >>> 4) + (B[0] >>> 4);
    D[0] = (Dh << 4) + Dl + (~(Dl - 15) >>> 31);

    for (U = 0; U < BLen; ++U)
    {
        F = B[1 + U];
        Cc = 0;
        for (V = 0; V < ALen; ++V)
        {
            Z = D[1 + U + V] + (F * A[V + 1]) + Cc;
            Cc = Z >>> 15;
            D[1 + U + V] = Z & 0x7FFF;
        }
        D[1 + U + ALen] = Cc;
    }
}

/*
 * Compute -(1/x) mod 2^15. If x is even, then this function returns 0.
 */
static final function int NInv15(int X)
{
    local int Y;

    Y = 2 - X;
    Y = Y * (2 - (X * Y));
    Y = Y * (2 - (X * Y));
    Y = Y * (2 - (X * Y));
    return MUX(X & 1, -Y, 0) & 0x7FFF;
}

/*
 * Reduce an integer (a[]) modulo another (m[]). The result is written
 * in x[] and its announced bit length is set to be equal to that of m[].
 *
 * x[] MUST be distinct from a[] and m[].
 *
 * CT: only announced bit lengths leak, not values of x, a or m.
 */
static final function Reduce(
    out array<int> X,
    const out array<int> A,
    const out array<int> M
)
{
    local int M_BitLen;
    local int A_BitLen;
    local int MLen;
    local int ALen;
    local int U;

    M_BitLen = M[0];
    MLen = (M_BitLen + 15) >>> 4;

    X[0] = M_BitLen;
    if (M_BitLen == 0)
    {
        return;
    }

    /*
     * If the source is shorter, then simply copy all words from a[]
     * and zero out the upper words.
     */
    A_BitLen = A[0];
    ALen = (A_BitLen + 15) >>> 4;
    if (A_BitLen < M_BitLen)
    {
        MemCpy(X, A, ALen * SIZEOF_UINT16_T, 1, 1);
        for (U = ALen; U < MLen; ++U)
        {
            X[U + 1] = 0;
        }
        return;
    }

    /*
     * The source length is at least equal to that of the modulus.
     * We must thus copy N-1 words, and input the remaining words
     * one by one.
     */
    MemCpy(X, A, (MLen - 1) * SIZEOF_UINT16_T, 1, 2 + (ALen - MLen));
    X[MLen] = 0;
    for (U = 1 + ALen - MLen; U > 0; --U)
    {
        MulAddSmall(X, A[U], M);
    }
}

static final function string WordsToString(
    const out array<int> X
)
{
    local int K;
    local string Str;

    if (X[0] == 0)
    {
        return "00000000 (0, 0)";
    }

    Str = "";
    for (K = (X[0] + 15) >>> 4; K > 0; --K)
    {
        Str $= ToHex(X[K]);
        if (K > 1)
        {
            Str @= "";
        }
    }

    Str @= "(" $ (X[0] >>> 4) $ "," @ (X[0] & 15) $ ")";
    return Str;
}

static final function BytesFromHex(
    out array<byte> Dst,
    string HexString
)
{
    local int K;
    local int J;
    local int LenStr;
    local string ByteS;
    local bool bSuccess;
    local int Temp;

    LenStr = Len(HexString);
    if ((LenStr % 2) != 0)
    {
        HexString = "0" $ HexString;
        ++LenStr;
    }
    K = 0;
    J = 0;
    Dst.Length = LenStr / 2;
    while (J < LenStr)
    {
        ByteS = Mid(HexString, J, 2);
        bSuccess = class'FCryptoUtils'.static.FromHex(Bytes, Temp);
        if (!bSuccess)
        {
            `fcserror("failed to convert Bytes:" @ Bytes @ "to an integer");
        }
        Dst[K++] = Temp;
        J += 2;
    }
}
