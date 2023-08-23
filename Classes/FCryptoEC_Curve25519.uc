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
class FCryptoEC_Curve25519 extends Object
    implements(FCryptoEllipticCurve)
    abstract
    notplaceable;

const SIZEOF_UINT16_T = 2;

var private const array<byte> _GEN;
var private const array<byte> _ORDER;

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

static function array<byte> Generator(EFCEllipticCurve Curve, out int Len)
{
    Len = 32;
    return default._GEN;
}

static function array<byte> Order(EFCEllipticCurve Curve, out int Len)
{
    Len = 32;
    return default._ORDER;
}

static function int XOff(EFCEllipticCurve Curve, out int Len)
{
    Len = 32;
    return 0;
}

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

    class'FCryptoBigInt'.static.MemMove(T, A, SIZEOF_UINT16_T);
    class'FCryptoBigInt'.static.Add(
        T,
        default.C255_P,
        class'FCryptoBigInt'.static.Sub(T, B, 1)
    );
    class'FCryptoBigInt'.static.MemMove(D, T, SIZEOF_UINT16_T);
}

private static final function C255Mul(
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
    const out array<byte> Kb,
    int KbLen,
    EFCEllipticCurve Curve
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
    local int Kt;
    local int J;

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

    class'FCryptoBigInt'.static.MemSet_Byte(K, 0, SIZEOF_UINT16_T - KBLen);
    class'FCryptoBigInt'.static.MemMove_Byte(K, Kb, KBLen, SIZEOF_UINT16_T - KBLen);
    K[31] = K[31] & 0xF8;
    K[0] = K[0] & 0x7F;
    K[0] = K[0] | 0x40;

    Swap = 0;
    for (I = 254; I >= 0; --I)
    {
        Kt = (K[31 - (I >>> 3)] >>> (I & 7)) & 1;
        Swap = Swap ^ Kt;
        CSwap(X2, X3, Swap);
        CSwap(Z2, Z3, Swap);
        Swap = Kt;

        C255Add(A, X2, Z2);
        C255Mul(Aa, A, A);
        C255Sub(B, X2, Z2);
        C255Mul(Bb, B, B);
        C255Sub(E, Aa, Bb);
        C255Add(C, X3, Z3);
        C255Sub(D, X3, Z3);
        C255Mul(Da, D, A);
        C255Mul(Cb, C, B);

        C255Add(X3, Da, Cb);
        C255Mul(X3, X3, X3);
        C255Sub(Z3, Da, Cb);
        C255Mul(Z3, Z3, Z3);
        C255Mul(Z3, Z3, X1);
        C255Mul(X2, Aa, Bb);
        C255Mul(Z2, default.C255_A24, E);
        C255Add(Z2, Z2, Aa);
        C255Mul(Z2, E, Z2);
    }

    CSwap(X2, X3, Swap);
    CSwap(Z2, Z3, Swap);

    /*
     * Inverse z2 with a modular exponentiation. This is a simple
     * square-and-multiply algorithm; we mutualise most non-squarings
     * since the exponent contains almost only ones.
     */
    class'FCryptoBigInt'.static.MemMove(A, Z2, ILEN);
    for (I = 0; I < 15; ++I)
    {
        C255Mul(A, A, A);
        C255Mul(A, A, Z2);
    }
    class'FCryptoBigInt'.static.MemMove(B, A, ILEN);
    for (I = 0; I < 14; ++I)
    {
        for (J = 0; J < 16; ++J)
        {
            C255Mul(B, B, B);
        }
        C255Mul(B, B, A);
    }
    for (I = 14; I >= 0; --I)
    {
        C255Mul(B, B, B);
        if (bool((0xFFEB >>> I) & 1))
        {
            C255Mul(B, Z2, B);
        }
    }
    C255Mul(B, X2, B);

    /*
     * To avoid a dependency on br_i15_from_monty(), we use a
     * Montgomery multiplication with 1.
     *    memcpy(x2, b, ILEN);
     *    br_i15_from_monty(x2, C255_P, P0I);
     */
    class'FCryptoBigInt'.static.Zero(A, default.C255_P[0]);
    A[1] = 1;
    class'FCryptoBigInt'.static.MontyMul(X2, A, B, default.C255_P, P0I);

    class'FCryptoBigInt'.static.Encode(G, 32, X2);
    ByteSwap(G);
    return 1;
}

static final function int MulGen(
    out array<byte> R,
    const out array<byte> X,
    int XLen,
    EFCEllipticCurve Curve
)
{
    local array<byte> G;
    local int GLen;

    G = Generator(Curve, GLen);
    class'FCryptoBigInt'.static.MemMove_Byte(R, G, GLen);
    Mul(R, GLen, X, XLen, Curve);
    return GLen;
}

static function int MulAdd(
    out array<byte> A,
    const out array<byte> B,
    int Len,
    const out array<byte> X,
    int XLen,
    const out array<byte> Y,
    int YLen,
    EFCEllipticCurve Curve
)
{
    /*
     * We don't implement this method, since it is used for ECDSA
     * only, and there is no ECDSA over Curve25519 (which instead
     * uses EdDSA).
     */
    return 0;
}

DefaultProperties
{
    // 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    _GEN={(
        9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    )}

    // 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    _ORDER={(
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
