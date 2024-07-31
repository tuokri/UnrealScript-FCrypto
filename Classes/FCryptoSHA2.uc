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
 * TODO: is it possible to implement sha2big.c in UScript?
 *       It uses 64-bit integer constants. Can we use QWORDs
 *       and "simulate" 64-bit arithmetic? Is it too much work
 *       for too little gain? There also exist implementations of
 *       SHA-512 for 8-bit microcontrollers, but translating those
 *       into UScript could be too difficult.
 */
class FCryptoSHA2 extends Object;

`include(FCrypto\Classes\FCryptoMacros.uci);

`define CH(X, Y, Z)     ((((`Y) ^ (`Z)) & (`X)) ^ (`Z))
`define MAJ(X, Y, Z)    (((`Y) & (`Z)) | (((`Y) | (`Z)) & (`X)))

`define ROTR(x, n)      ((`x << (32 - (`n))) | (`x >>> (`n)))

`define BSG2_0(x)       (`ROTR(`x, 2) ^ `ROTR(`x, 13) ^ `ROTR(`x, 22))
`define BSG2_1(x)       (`ROTR(`x, 6) ^ `ROTR(`x, 11) ^ `ROTR(`x, 25))
`define SSG2_0(x)       (`ROTR(`x, 7) ^ `ROTR(`x, 18) ^ ((`x) >>> 3))
`define SSG2_1(x)       (`ROTR(`x, 17) ^ `ROTR(`x, 19) ^ ((`x) >>> 10))

var const array<int> SHA224_IV;
var const array<int> SHA256_IV;
var const array<int> K;

`define SHA2_STEP(A, B, C, D, E, F, G, H, j)                            \
        T1 = `H + `BSG2_1(E) + `CH(`E, `F, `G) + default.K[`j] + w[`j]; \
        T2 = `BSG2_0(`A) + `MAJ(`A, `B, `C);                            \
        `D += T1;                                                       \
        `H = T1 + T2;                                                   \

static final function Sha2SmallRound(
    const out array<byte> Buf,
    out array<int> Val
)
{
    local int T1;
    local int T2;
    local int i;
    local int A;
    local int B;
    local int C;
    local int D;
    local int E;
    local int F;
    local int G;
    local int H;
    local array<int> W;

    W.Length = 64;

    RangeDec32BE(W, 16, Buf);

    // for (i = 16; i < 64; ++i)
    // {
    //     w[i] = `SSG2_1(w[i - 2]) + w[i - 7]
    //         + `SSG2_0(w[i - 15]) + w[i - 16];
    // }
    // TODO: do the math here manually.
    w[16] = `SSG2_1(w[16 - 2]) + w[16 - 7] + `SSG2_0(w[16 - 15]) + w[16 - 16];
    w[17] = `SSG2_1(w[17 - 2]) + w[17 - 7] + `SSG2_0(w[17 - 15]) + w[17 - 16];
    w[18] = `SSG2_1(w[18 - 2]) + w[18 - 7] + `SSG2_0(w[18 - 15]) + w[18 - 16];
    w[19] = `SSG2_1(w[19 - 2]) + w[19 - 7] + `SSG2_0(w[19 - 15]) + w[19 - 16];
    w[20] = `SSG2_1(w[20 - 2]) + w[20 - 7] + `SSG2_0(w[20 - 15]) + w[20 - 16];
    w[21] = `SSG2_1(w[21 - 2]) + w[21 - 7] + `SSG2_0(w[21 - 15]) + w[21 - 16];
    w[22] = `SSG2_1(w[22 - 2]) + w[22 - 7] + `SSG2_0(w[22 - 15]) + w[22 - 16];
    w[23] = `SSG2_1(w[23 - 2]) + w[23 - 7] + `SSG2_0(w[23 - 15]) + w[23 - 16];
    w[24] = `SSG2_1(w[24 - 2]) + w[24 - 7] + `SSG2_0(w[24 - 15]) + w[24 - 16];
    w[25] = `SSG2_1(w[25 - 2]) + w[25 - 7] + `SSG2_0(w[25 - 15]) + w[25 - 16];
    w[26] = `SSG2_1(w[26 - 2]) + w[26 - 7] + `SSG2_0(w[26 - 15]) + w[26 - 16];
    w[27] = `SSG2_1(w[27 - 2]) + w[27 - 7] + `SSG2_0(w[27 - 15]) + w[27 - 16];
    w[28] = `SSG2_1(w[28 - 2]) + w[28 - 7] + `SSG2_0(w[28 - 15]) + w[28 - 16];
    w[29] = `SSG2_1(w[29 - 2]) + w[29 - 7] + `SSG2_0(w[29 - 15]) + w[29 - 16];
    w[30] = `SSG2_1(w[30 - 2]) + w[30 - 7] + `SSG2_0(w[30 - 15]) + w[30 - 16];
    w[31] = `SSG2_1(w[31 - 2]) + w[31 - 7] + `SSG2_0(w[31 - 15]) + w[31 - 16];
    w[32] = `SSG2_1(w[32 - 2]) + w[32 - 7] + `SSG2_0(w[32 - 15]) + w[32 - 16];
    w[33] = `SSG2_1(w[33 - 2]) + w[33 - 7] + `SSG2_0(w[33 - 15]) + w[33 - 16];
    w[34] = `SSG2_1(w[34 - 2]) + w[34 - 7] + `SSG2_0(w[34 - 15]) + w[34 - 16];
    w[35] = `SSG2_1(w[35 - 2]) + w[35 - 7] + `SSG2_0(w[35 - 15]) + w[35 - 16];
    w[36] = `SSG2_1(w[36 - 2]) + w[36 - 7] + `SSG2_0(w[36 - 15]) + w[36 - 16];
    w[37] = `SSG2_1(w[37 - 2]) + w[37 - 7] + `SSG2_0(w[37 - 15]) + w[37 - 16];
    w[38] = `SSG2_1(w[38 - 2]) + w[38 - 7] + `SSG2_0(w[38 - 15]) + w[38 - 16];
    w[39] = `SSG2_1(w[39 - 2]) + w[39 - 7] + `SSG2_0(w[39 - 15]) + w[39 - 16];
    w[40] = `SSG2_1(w[40 - 2]) + w[40 - 7] + `SSG2_0(w[40 - 15]) + w[40 - 16];
    w[41] = `SSG2_1(w[41 - 2]) + w[41 - 7] + `SSG2_0(w[41 - 15]) + w[41 - 16];
    w[42] = `SSG2_1(w[42 - 2]) + w[42 - 7] + `SSG2_0(w[42 - 15]) + w[42 - 16];
    w[43] = `SSG2_1(w[43 - 2]) + w[43 - 7] + `SSG2_0(w[43 - 15]) + w[43 - 16];
    w[44] = `SSG2_1(w[44 - 2]) + w[44 - 7] + `SSG2_0(w[44 - 15]) + w[44 - 16];
    w[45] = `SSG2_1(w[45 - 2]) + w[45 - 7] + `SSG2_0(w[45 - 15]) + w[45 - 16];
    w[46] = `SSG2_1(w[46 - 2]) + w[46 - 7] + `SSG2_0(w[46 - 15]) + w[46 - 16];
    w[47] = `SSG2_1(w[47 - 2]) + w[47 - 7] + `SSG2_0(w[47 - 15]) + w[47 - 16];
    w[48] = `SSG2_1(w[48 - 2]) + w[48 - 7] + `SSG2_0(w[48 - 15]) + w[48 - 16];
    w[49] = `SSG2_1(w[49 - 2]) + w[49 - 7] + `SSG2_0(w[49 - 15]) + w[49 - 16];
    w[50] = `SSG2_1(w[50 - 2]) + w[50 - 7] + `SSG2_0(w[50 - 15]) + w[50 - 16];
    w[51] = `SSG2_1(w[51 - 2]) + w[51 - 7] + `SSG2_0(w[51 - 15]) + w[51 - 16];
    w[52] = `SSG2_1(w[52 - 2]) + w[52 - 7] + `SSG2_0(w[52 - 15]) + w[52 - 16];
    w[53] = `SSG2_1(w[53 - 2]) + w[53 - 7] + `SSG2_0(w[53 - 15]) + w[53 - 16];
    w[54] = `SSG2_1(w[54 - 2]) + w[54 - 7] + `SSG2_0(w[54 - 15]) + w[54 - 16];
    w[55] = `SSG2_1(w[55 - 2]) + w[55 - 7] + `SSG2_0(w[55 - 15]) + w[55 - 16];
    w[56] = `SSG2_1(w[56 - 2]) + w[56 - 7] + `SSG2_0(w[56 - 15]) + w[56 - 16];
    w[57] = `SSG2_1(w[57 - 2]) + w[57 - 7] + `SSG2_0(w[57 - 15]) + w[57 - 16];
    w[58] = `SSG2_1(w[58 - 2]) + w[58 - 7] + `SSG2_0(w[58 - 15]) + w[58 - 16];
    w[59] = `SSG2_1(w[59 - 2]) + w[59 - 7] + `SSG2_0(w[59 - 15]) + w[59 - 16];
    w[60] = `SSG2_1(w[60 - 2]) + w[60 - 7] + `SSG2_0(w[60 - 15]) + w[60 - 16];
    w[61] = `SSG2_1(w[61 - 2]) + w[61 - 7] + `SSG2_0(w[61 - 15]) + w[61 - 16];
    w[62] = `SSG2_1(w[62 - 2]) + w[62 - 7] + `SSG2_0(w[62 - 15]) + w[62 - 16];
    w[63] = `SSG2_1(w[63 - 2]) + w[63 - 7] + `SSG2_0(w[63 - 15]) + w[63 - 16];

    a = Val[0];
    b = Val[1];
    c = Val[2];
    d = Val[3];
    e = Val[4];
    f = Val[5];
    g = Val[6];
    h = Val[7];

    // for (i = 0; i < 64; i += 8)
    // {
    //     `SHA2_STEP(a, b, c, d, e, f, g, h, i + 0);
    //     `SHA2_STEP(h, a, b, c, d, e, f, g, i + 1);
    //     `SHA2_STEP(g, h, a, b, c, d, e, f, i + 2);
    //     `SHA2_STEP(f, g, h, a, b, c, d, e, i + 3);
    //     `SHA2_STEP(e, f, g, h, a, b, c, d, i + 4);
    //     `SHA2_STEP(d, e, f, g, h, a, b, c, i + 5);
    //     `SHA2_STEP(c, d, e, f, g, h, a, b, i + 6);
    //     `SHA2_STEP(b, c, d, e, f, g, h, a, i + 7);
    // }
    `SHA2_STEP(a, b, c, d, e, f, g, h, 0  /*0 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 1  /*0 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 2  /*0 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 3  /*0 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 4  /*0 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 5  /*0 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 6  /*0 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 7  /*0 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 8  /*8 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 9  /*8 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 10 /*8 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 11 /*8 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 12 /*8 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 13 /*8 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 14 /*8 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 15 /*8 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 16 /*16 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 17 /*16 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 18 /*16 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 19 /*16 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 20 /*16 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 21 /*16 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 22 /*16 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 23 /*16 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 24 /*24 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 25 /*24 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 26 /*24 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 27 /*24 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 28 /*24 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 29 /*24 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 30 /*24 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 31 /*24 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 32 /*32 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 33 /*32 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 34 /*32 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 35 /*32 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 36 /*32 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 37 /*32 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 38 /*32 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 39 /*32 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 40 /*40 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 41 /*40 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 42 /*40 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 43 /*40 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 44 /*40 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 45 /*40 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 46 /*40 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 47 /*40 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 48 /*48 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 49 /*48 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 50 /*48 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 51 /*48 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 52 /*48 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 53 /*48 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 54 /*48 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 55 /*48 + 7*/);

    `SHA2_STEP(a, b, c, d, e, f, g, h, 56 /*56 + 0*/);
    `SHA2_STEP(h, a, b, c, d, e, f, g, 57 /*56 + 1*/);
    `SHA2_STEP(g, h, a, b, c, d, e, f, 58 /*56 + 2*/);
    `SHA2_STEP(f, g, h, a, b, c, d, e, 59 /*56 + 3*/);
    `SHA2_STEP(e, f, g, h, a, b, c, d, 60 /*56 + 4*/);
    `SHA2_STEP(d, e, f, g, h, a, b, c, 61 /*56 + 5*/);
    `SHA2_STEP(c, d, e, f, g, h, a, b, 62 /*56 + 6*/);
    `SHA2_STEP(b, c, d, e, f, g, h, a, 63 /*56 + 7*/);

    Val[0] += a;
    Val[1] += b;
    Val[2] += c;
    Val[3] += d;
    Val[4] += e;
    Val[5] += f;
    Val[6] += g;
    Val[7] += h;
}

// TODO: make this a macro for performance?
static final function RangeDec32BE(
    out array<int> V,
    int Num,
    const out array<byte> Src
)
{
    local int I;
    local int SrcIdx;

    SrcIdx = 0;
    while (Num-- > 0)
    {
        V[I++] = Dec32BE(Src, SrcIdx);
        SrcIdx += 4;
    }
}

// TODO: make this a macro for performance?
static final function int Dec32BE(
    const out array<byte> Src,
    optional int Idx = 0 // TODO: is this needed?
)
{
    return (
          Src[Idx + 0] << 24
        | Src[Idx + 1] << 16
        | Src[Idx + 2] << 8
        | Src[Idx + 3]
    );
}

DefaultProperties
{
    SHA224_IV={(
        0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
    )}

    SHA256_IV={(
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )}

    K={(
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    )}
}
