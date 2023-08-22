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
class FCryptoEC_C25519 extends Object
    abstract
    notplaceable;

const SIZEOF_UINT16_T = 2;

var private const array<byte> GEN;
var private const array<byte> ORDER;

/*
 * Parameters for the field:
 *   - field modulus p = 2^255-19
 *   - R^2 mod p (R = 2^(15k) for the smallest k such that R >= p)
 */

const P0I = 0x4A1B;

var private const array<int> C255_P;
var private const array<int> C255_R2;
var private const array<int> C255_A24;

const ILEN = 32;

private static final function CSwap(
    out array<int> A,
    out array<int> B,
    int Ctl
)
{
    local int I;
    local int Aw;
    local int Bw;
    local int Tw;

    Ctl = -Ctl;
    for (I = 0; I < 28; ++I)
    {
        Aw = A[I];
        Bw = B[I];
        Tw = Ctl & (Aw ^ Bw);
        A[I] = Aw ^ Tw;
        B[I] = Bw ^ Tw;
    }
}

private static final function C255Add(
    out array<int> D,
    const out array<int> A,
    const out array<int> B
)
{
    local int Ctl;
    local array<int> T;

    T.Length = 18;

    class'FCryptoBigInt'.static.MemMove(T, A, SIZEOF_UINT16_T);
    Ctl = class'FCryptoBigInt'.static.Add(T, B, 1);
    Ctl = Ctl | class'FCryptoBigInt'.static.NOT(
        class'FCryptoBigInt'.static.Sub(T, default.C255_P, 0));
    class'FCryptoBigInt'.static.Sub(T, default.C255_P, Ctl);
    class'FCryptoBigInt'.static.MemMove(D, T, SIZEOF_UINT16_T);
}

private static final function C255Sub(
    out array<int> D,
    const out array<int> A,
    const out array<int> B
)
{
    local array<int> T;

    T.Length = 18;

    class'FCryptoBigInt'.static.MontyMul(T, A, B, default.C255_P, P0I);
    class'FCryptoBigInt'.static.MemMove(D, T, SIZEOF_UINT16_T);
}

private static final function ByteSwap(
    out array<byte> G
)
{
    local int I;
    local byte T;

    for (I = 0; I < 16; ++I)
    {
        T = G[I];
        G[I] = G[31 - I];
        G[31 - I] = T;
    }
}

static final function int Mul(
    out array<byte> G,
    int GLen,
    const out array<byte> KB,
    int KBLen
)
{
    /*
     * The a[] and b[] arrays have an extra word to allow for
     * decoding without using br_i15_decode_reduce().
     */
    local array<int> X1;
    local array<int> X2;
    local array<int> X3;
    local array<int> Z2;
    local array<int> Z3;
    local array<int> A;
    local array<int> Aa;
    local array<int> B;
    local array<int> Bb;
    local array<int> C;
    local array<int> D;
    local array<int> E;
    local array<int> Da;
    local array<int> Cb;
    local array<byte> K;
    local int Swap;
    local int I;

    X1.Length = 18;
    X2.Length = 18;
    X3.Length = 18;
    Z2.Length = 18;
    Z3.Length = 18;
    A.Length = 19;
    Aa.Length = 18;
    B.Length = 19;
    Bb.Length = 18;
    C.Length = 18;
    D.Length = 18;
    E.Length = 18;
    Da.Length = 18;
    Cb.Length = 18;
    K.Length = 32;

    /*
     * Points are encoded over exactly 32 bytes. Multipliers must fit
     * in 32 bytes as well.
     * RFC 7748 mandates that the high bit of the last point byte must
     * be ignored/cleared.
     */
    if (GLen != 32 || KBLen > 32)
    {
        return 0;
    }
    G[31] = G[31] & 127; // 0x7F.

    /*
     * Byteswap the point encoding, because it uses little-endian, and
     * the generic decoding routine uses big-endian.
     */
    ByteSwap(G);

    /*
     * Decode the point ('u' coordinate). This should be reduced
     * modulo p, but we prefer to avoid the dependency on
     * br_i15_decode_reduce(). Instead, we use br_i15_decode_mod()
     * with a synthetic modulus of value 2^255 (this must work
     * since G was truncated to 255 bits), then use a conditional
     * subtraction. We use br_i15_decode_mod() and not
     * br_i15_decode(), because the ec_prime_i15 implementation uses
     * the former but not the latter.
     *    br_i15_decode_reduce(a, G, 32, C255_P);
     */
    class'FCryptoBigInt'.static.Zero(B, 0x111);
    B[18] = 1;
    class'FCryptoBigInt'.static.DecodeMod(A, G, 32, B);
    A[0] = 0x110;
    class'FCryptoBigInt'.static.Sub(
        A,
        default.C255_P,
        class'FCryptoBigInt'.static.NOT(
            class'FCryptoBigInt'.static.Sub(A, default.C255_P, 0)
        )
    );

    /*
     * Initialise variables x1, x2, z2, x3 and z3. We set all of them
     * into Montgomery representation.
     */
    class'FCryptoBigInt'.static.MontyMul(X1, A, default.C255_R2, default.C255_P, P0I);
    class'FCryptoBigInt'.static.MemMove(X3, X1, ILEN);
    class'FCryptoBigInt'.static.Zero(Z2, default.C255_P[0]);
    class'FCryptoBigInt'.static.MemMove(X2, Z2, ILEN);
    X2[1] = 19;
    class'FCryptoBigInt'.static.MemMove(Z3, X2, ILEN);

    class'FCryptoBigInt'.static.MemSet_UInt16(K, 0, SIZEOF_UINT16_T - KBLen);
    class'FCryptoBigInt'.static.MemMove(K, Kb, KBLen, SIZEOF_UINT16_T - KBLen);
    K[31] = K[31] & 0xF8;
    K[0] = K[0] & 0x7F;
    K[0] = K[0] | 0x40;

    Swap = 0;
}

DefaultProperties
{
    // 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    GEN={(
        9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    )}

    // 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ORDER={(
        127, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255
    )}

    C255_P={(
        0x0110,
        0x7FED, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF
    )}

    C255_R2={(
        0x0110,
        0x0169, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000
    )}

    C255_A24={(
        0x0110,
        0x45D3, 0x0046, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000
    )}
}
