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
    out int Val
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

    // br_range_dec32be(w, 16, buf);
	// for (i = 16; i < 64; i ++) {
	// 	w[i] = SSG2_1(w[i - 2]) + w[i - 7]
	// 		+ SSG2_0(w[i - 15]) + w[i - 16];
	// }
	// a = val[0];
	// b = val[1];
	// c = val[2];
	// d = val[3];
	// e = val[4];
	// f = val[5];
	// g = val[6];
	// h = val[7];

    // TODO: unroll this.
    for (i = 0; i < 64; i += 8)
    {
		`SHA2_STEP(a, b, c, d, e, f, g, h, i + 0);
		`SHA2_STEP(h, a, b, c, d, e, f, g, i + 1);
		`SHA2_STEP(g, h, a, b, c, d, e, f, i + 2);
		`SHA2_STEP(f, g, h, a, b, c, d, e, i + 3);
		`SHA2_STEP(e, f, g, h, a, b, c, d, i + 4);
		`SHA2_STEP(d, e, f, g, h, a, b, c, i + 5);
		`SHA2_STEP(c, d, e, f, g, h, a, b, i + 6);
		`SHA2_STEP(b, c, d, e, f, g, h, a, i + 7);
	}
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
