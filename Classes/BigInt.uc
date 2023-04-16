/*
 * Copyright (c) 2023 Tuomo Kriikkula <tuokri@tuta.io>
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
 * See: https://www.bearssl.org/bigint.html.
 */
class BigInt extends Object
    abstract
    notplaceable;

// TODO: rewrite documentation to be more UScript-like.
// TODO: remove the parts of documentation only relevant in C.

// TODO: should not use small functions like this in UScript (perf).
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
    return Y ^ (-Ctl & (X ^ Y));
}

/*
 * Equality check: returns 1 if X == y, 0 otherwise.
 */
static final function int EQ(int X, int Y)
{
    local int Q;

    Q = X ^ Y;
    // return NOT((Q | -Q) >>> 31);
    return ((Q | -Q) >>> 31) ^ 1;
}

/*
 * Inequality check: returns 1 if x != y, 0 otherwise.
 */
static final function int NEQ(int X, int Y)
{
    local int Q;

    q = x ^ y;
    return (q | -q) >>> 31;
}

static final function int GT(int x, int y)
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
    local int z;

    z = y - x;
    return (z ^ ((x ^ y) & (x ^ z))) >>> 31;
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
    return GT(X, Y) | -GT(Y, X);
}

/*
 * Zeroize an integer. The announced bit length is set to the provided
 * value, and the corresponding words are set to 0.
 */
static final function BigInt_Zero(
    out array<int> X,
    int BitLen
)
{
    local int I;

    // *x ++ = bit_len;
    // memset(x, 0, ((bit_len + 15) >> 4) * sizeof *x);

    X[0] = BitLen;
    for (I = 1; I < BitLen; ++I)
    {
        X[I] = 0;
    }
}

/*
 * Add b[] to a[] and return the carry (0 or 1). If ctl is 0, then a[]
 * is unmodified, but the carry is still computed and returned. The
 * arrays a[] and b[] MUST have the same announced bit length.
 *
 * a[] and b[] MAY be the same array, but partial overlap is not allowed.
 */
static final function int BigInt_Add(
    out array<int> A,
    const out array<int> B,
    int Ctl)
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
        A[U] = MUX(Ctl, Naw & 0x7FFF, Aw);
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
static final function int BigInt_BitLength(
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
static final function int BigInt_DecodeMod(
    out array<int> X,
    const out array<byte> Src,
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
    if (TLen < Src.Length)
    {
        TLen = Src.Length;
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
            if (U < Src.Length)
            {
                B = Src[Src.Length - 1 - U];
            }
            else
            {
                B = 0;
            }
            Acc = Acc | (B << AccLen);
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
                        X[V] = R & Xw;
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

static final function BigInt_Decode(
    out array<int> X,
    const out array<byte> Src
)
{
    local int V;
    local int Acc;
    local int AccLen;
    local int B;
    local int SrcLen;
    local array<int> XArr;
    local int I;

    SrcLen = Src.Length;
    V = 1;
    Acc = 0;
    AccLen = 0;
    while (SrcLen-- > 0)
    {
        B = Src[SrcLen];
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
        X[V++] = Acc;
    }

    // X[0] = BigInt_BitLength(X + 1, V - 1);
    // TODO: is there a faster way of doing this in UScript?
    for (I = 1; I < X.Length; ++I)
    {
        XArr[I] = X[I];
    }
    X[0] = BigInt_BitLength(XArr, V - 1);
}

/*
 * Decode an integer from its big-endian unsigned representation, and
 * reduce it modulo the provided modulus m[]. The announced bit length
 * of the result is set to be equal to that of the modulus.
 *
 * x[] MUST be distinct from m[].
 */
static final function BigInt_DecodeReduce(
    out array<int> X,
    const out array<byte> Src,
    const out array<int> M
)
{
    local int M_EBitLen;
    local int M_RBitLen;
    local int MBLen;
    local int K;
    local int Acc;
    local int AccLen;

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
    BigInt_Zero(X, M_EBitLen);

    /*
     * First decode directly as many bytes as possible. This requires
     * computing the actual bit length.
     */
    M_RBitLen = M_EBitLen >>> 4;
    M_RBitLen = (M_EBitLen & 15) + (M_RBitLen << 4) - M_RBitLen;
    MBLen = (M_RBitLen + 7) >>> 3;
}
