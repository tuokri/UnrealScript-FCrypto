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

// Mirrors BearSSL's ec_prime_i15.c.
class FCryptoEC_Prime extends Object
    implements(FCryptoEllipticCurve)
    abstract
    notplaceable;

`include(FCrypto\Classes\FCryptoMacros.uci);
`include(FCrypto\Classes\FCryptoEllipticCurveMacros.uci);

/*
 * Parameters for supported curves:
 *   - field modulus p
 *   - R^2 mod p (R = 2^(15k) for the smallest k such that R >= p)
 *   - b*R mod p (b is the second curve equation parameter)
 */

var const array<int> P256_P;
var const array<int> P256_R2;
var const array<int> P256_B;
var const array<int> P384_P;
var const array<int> P384_R2;
var const array<int> P384_B;
var const array<int> P521_P;
var const array<int> P521_R2;
var const array<int> P521_B;

struct CurveParams
{
    var const array<int> P;
    var const array<int> B;
    var const array<int> R2;
    var const int P0i;
    var const int PointLen;
};

var const array<CurveParams> _PP;

// ((`BR_MAX_EC_SIZE + 29) / 15)
`define I15_LEN 37

// Montgomery representation. Workaround dummy container type
// for Jacobian struct due to UScript not having nested arrays.
struct _Monty
{
    var int X[`I15_LEN];
};

/*
 * Type for a point in Jacobian coordinates:
 * -- three values, x, y and z, in Montgomery representation
 * -- affine coordinates are X = x / z^2 and Y = y / z^3
 * -- for the point at infinity, z = 0
 */
struct Jacobian
{
    // uint16_t c[3][I15_LEN];
    var _Monty C[3];
};

// TODO: not needed?
// const SIZEOF_JACOBIAN = 222;

var const Jacobian ZERO_JACOBIAN;

/*
 * We use a custom interpreter that uses a dozen registers, and
 * only six operations:
 *    MSET(d, a)       copy a into d
 *    MADD(d, a)       d = d+a (modular)
 *    MSUB(d, a)       d = d-a (modular)
 *    MMUL(d, a, b)    d = a*b (Montgomery multiplication)
 *    MINV(d, a, b)    invert d modulo p; a and b are used as scratch registers
 *    MTZ(d)           clear return value if d = 0
 * Destination of MMUL (d) must be distinct from operands (a and b).
 * There is no such constraint for MSUB and MADD.
 *
 * Registers include the operand coordinates, and temporaries.
 */
`define MSET(d, a)      (0x0000 + ((`d) << 8) + ((`a) << 4))
`define MADD(d, a)      (0x1000 + ((`d) << 8) + ((`a) << 4))
`define MSUB(d, a)      (0x2000 + ((`d) << 8) + ((`a) << 4))
`define MMUL(d, a, b)   (0x3000 + ((`d) << 8) + ((`a) << 4) + (`b))
`define MINV(d, a, b)   (0x4000 + ((`d) << 8) + ((`a) << 4) + (`b))
`define MTZ(d)          (0x5000 + ((`d) << 8))
`define ENCODE         0

/*
 * Registers for the input operands.
 */
`define P1x    0
`define P1y    1
`define P1z    2
`define P2x    3
`define P2y    4
`define P2z    5

/*
 * Alternate names for the first input operand.
 */
`define Px     0
`define Py     1
`define Pz     2

/*
 * Temporaries.
 */
`define T1     6
`define T2     7
`define T3     8
`define T4     9
`define T5    10
`define T6    11
`define T7    12

/*
 * Extra scratch registers available when there is no second operand (e.g.
 * for "double" and "affine").
 */
`define T8     3
`define T9     4
`define T10    5

/*
 * Doubling formulas are:
 *
 *   s = 4*x*y^2
 *   m = 3*(x + z^2)*(x - z^2)
 *   x' = m^2 - 2*s
 *   y' = m*(s - x') - 8*y^4
 *   z' = 2*y*z
 *
 * If y = 0 (P has order 2) then this yields infinity (z' = 0), as it
 * should. This case should not happen anyway, because our curves have
 * prime order, and thus do not contain any point of order 2.
 *
 * If P is infinity (z = 0), then again the formulas yield infinity,
 * which is correct. Thus, this code works for all points.
 *
 * Cost: 8 multiplications
 */
var const array<int> CodeDouble;

/*
 * Additions formulas are:
 *
 *   u1 = x1 * z2^2
 *   u2 = x2 * z1^2
 *   s1 = y1 * z2^3
 *   s2 = y2 * z1^3
 *   h = u2 - u1
 *   r = s2 - s1
 *   x3 = r^2 - h^3 - 2 * u1 * h^2
 *   y3 = r * (u1 * h^2 - x3) - s1 * h^3
 *   z3 = h * z1 * z2
 *
 * If both P1 and P2 are infinity, then z1 == 0 and z2 == 0, implying that
 * z3 == 0, so the result is correct.
 * If either of P1 or P2 is infinity, but not both, then z3 == 0, which is
 * not correct.
 * h == 0 only if u1 == u2; this happens in two cases:
 * -- if s1 == s2 then P1 and/or P2 is infinity, or P1 == P2
 * -- if s1 != s2 then P1 + P2 == infinity (but neither P1 or P2 is infinity)
 *
 * Thus, the following situations are not handled correctly:
 * -- P1 = 0 and P2 != 0
 * -- P1 != 0 and P2 = 0
 * -- P1 = P2
 * All other cases are properly computed. However, even in "incorrect"
 * situations, the three coordinates still are properly formed field
 * elements.
 *
 * The returned flag is cleared if r == 0. This happens in the following
 * cases:
 * -- Both points are on the same horizontal line (same Y coordinate).
 * -- Both points are infinity.
 * -- One point is infinity and the other is on line Y = 0.
 * The third case cannot happen with our curves (there is no valid point
 * on line Y = 0 since that would be a point of order 2). If the two
 * source points are non-infinity, then remains only the case where the
 * two points are on the same horizontal line.
 *
 * This allows us to detect the "P1 == P2" case, assuming that P1 != 0 and
 * P2 != 0:
 * -- If the returned value is not the point at infinity, then it was properly
 * computed.
 * -- Otherwise, if the returned flag is 1, then P1+P2 = 0, and the result
 * is indeed the point at infinity.
 * -- Otherwise (result is infinity, flag is 0), then P1 = P2 and we should
 * use the 'double' code.
 *
 * Cost: 16 multiplications
 */
var const array<int> CodeAdd;

/*
 * Check that the point is on the curve. This code snippet assumes the
 * following conventions:
 * -- Coordinates x and y have been freshly decoded in P1 (but not
 * converted to Montgomery coordinates yet).
 * -- P2x, P2y and P2z are set to, respectively, R^2, b*R and 1.
 */
var const array<int> CodeCheck;

/*
 * Conversion back to affine coordinates. This code snippet assumes that
 * the z coordinate of P2 is set to 1 (not in Montgomery representation).
 */
var const array<int> CodeAffine;

// TODO: finish implementation.
static final function int RunCode(
    out Jacobian P1,
    const out Jacobian P2,
    const out CurveParams Cc,
    const out array<int> Code
)
{
    local int R;
    local _Monty T[13];
    local int U;
    local int Op;
    local int D;
    local int D_Tmp;
    local int A;
    local int A_Tmp;
    local int B;
    local int Ctl;
    local int PLen;
    local byte Tp[66]; /* (BR_MAX_EC_SIZE + 7) >> 3 */

    R = 1;

    /*
     * Copy the two operands in the dedicated registers.
     */
    // memcpy(t[P1x], P1->c, 3 * I15_LEN * sizeof(uint16_t));
    // memcpy(t[P2x], P2->c, 3 * I15_LEN * sizeof(uint16_t));
    // class'FCryptoMemory'.static.MemCpy_Jacobian_Monty(T[`P1x], P1.C, 222);
    // class'FCryptoMemory'.static.MemCpy_Jacobian_Monty(T[`P2x], P2.C, 222);
    T[`P1x].X[ 0] = P1.C[0].X[ 0]; T[`P1y].X[ 0] = P1.C[1].X[ 0]; T[`P1z].X[ 0] = P1.C[2].X[ 0];
    T[`P1x].X[ 1] = P1.C[0].X[ 1]; T[`P1y].X[ 1] = P1.C[1].X[ 1]; T[`P1z].X[ 1] = P1.C[2].X[ 1];
    T[`P1x].X[ 2] = P1.C[0].X[ 2]; T[`P1y].X[ 2] = P1.C[1].X[ 2]; T[`P1z].X[ 2] = P1.C[2].X[ 2];
    T[`P1x].X[ 3] = P1.C[0].X[ 3]; T[`P1y].X[ 3] = P1.C[1].X[ 3]; T[`P1z].X[ 3] = P1.C[2].X[ 3];
    T[`P1x].X[ 4] = P1.C[0].X[ 4]; T[`P1y].X[ 4] = P1.C[1].X[ 4]; T[`P1z].X[ 4] = P1.C[2].X[ 4];
    T[`P1x].X[ 5] = P1.C[0].X[ 5]; T[`P1y].X[ 5] = P1.C[1].X[ 5]; T[`P1z].X[ 5] = P1.C[2].X[ 5];
    T[`P1x].X[ 6] = P1.C[0].X[ 6]; T[`P1y].X[ 6] = P1.C[1].X[ 6]; T[`P1z].X[ 6] = P1.C[2].X[ 6];
    T[`P1x].X[ 7] = P1.C[0].X[ 7]; T[`P1y].X[ 7] = P1.C[1].X[ 7]; T[`P1z].X[ 7] = P1.C[2].X[ 7];
    T[`P1x].X[ 8] = P1.C[0].X[ 8]; T[`P1y].X[ 8] = P1.C[1].X[ 8]; T[`P1z].X[ 8] = P1.C[2].X[ 8];
    T[`P1x].X[ 9] = P1.C[0].X[ 9]; T[`P1y].X[ 9] = P1.C[1].X[ 9]; T[`P1z].X[ 9] = P1.C[2].X[ 9];
    T[`P1x].X[10] = P1.C[0].X[10]; T[`P1y].X[10] = P1.C[1].X[10]; T[`P1z].X[10] = P1.C[2].X[10];
    T[`P1x].X[11] = P1.C[0].X[11]; T[`P1y].X[11] = P1.C[1].X[11]; T[`P1z].X[11] = P1.C[2].X[11];
    T[`P1x].X[12] = P1.C[0].X[12]; T[`P1y].X[12] = P1.C[1].X[12]; T[`P1z].X[12] = P1.C[2].X[12];
    T[`P1x].X[13] = P1.C[0].X[13]; T[`P1y].X[13] = P1.C[1].X[13]; T[`P1z].X[13] = P1.C[2].X[13];
    T[`P1x].X[14] = P1.C[0].X[14]; T[`P1y].X[14] = P1.C[1].X[14]; T[`P1z].X[14] = P1.C[2].X[14];
    T[`P1x].X[15] = P1.C[0].X[15]; T[`P1y].X[15] = P1.C[1].X[15]; T[`P1z].X[15] = P1.C[2].X[15];
    T[`P1x].X[16] = P1.C[0].X[16]; T[`P1y].X[16] = P1.C[1].X[16]; T[`P1z].X[16] = P1.C[2].X[16];
    T[`P1x].X[17] = P1.C[0].X[17]; T[`P1y].X[17] = P1.C[1].X[17]; T[`P1z].X[17] = P1.C[2].X[17];
    T[`P1x].X[18] = P1.C[0].X[18]; T[`P1y].X[18] = P1.C[1].X[18]; T[`P1z].X[18] = P1.C[2].X[18];
    T[`P1x].X[19] = P1.C[0].X[19]; T[`P1y].X[19] = P1.C[1].X[19]; T[`P1z].X[19] = P1.C[2].X[19];
    T[`P1x].X[20] = P1.C[0].X[20]; T[`P1y].X[20] = P1.C[1].X[20]; T[`P1z].X[20] = P1.C[2].X[20];
    T[`P1x].X[21] = P1.C[0].X[21]; T[`P1y].X[21] = P1.C[1].X[21]; T[`P1z].X[21] = P1.C[2].X[21];
    T[`P1x].X[22] = P1.C[0].X[22]; T[`P1y].X[22] = P1.C[1].X[22]; T[`P1z].X[22] = P1.C[2].X[22];
    T[`P1x].X[23] = P1.C[0].X[23]; T[`P1y].X[23] = P1.C[1].X[23]; T[`P1z].X[23] = P1.C[2].X[23];
    T[`P1x].X[24] = P1.C[0].X[24]; T[`P1y].X[24] = P1.C[1].X[24]; T[`P1z].X[24] = P1.C[2].X[24];
    T[`P1x].X[25] = P1.C[0].X[25]; T[`P1y].X[25] = P1.C[1].X[25]; T[`P1z].X[25] = P1.C[2].X[25];
    T[`P1x].X[26] = P1.C[0].X[26]; T[`P1y].X[26] = P1.C[1].X[26]; T[`P1z].X[26] = P1.C[2].X[26];
    T[`P1x].X[27] = P1.C[0].X[27]; T[`P1y].X[27] = P1.C[1].X[27]; T[`P1z].X[27] = P1.C[2].X[27];
    T[`P1x].X[28] = P1.C[0].X[28]; T[`P1y].X[28] = P1.C[1].X[28]; T[`P1z].X[28] = P1.C[2].X[28];
    T[`P1x].X[29] = P1.C[0].X[29]; T[`P1y].X[29] = P1.C[1].X[29]; T[`P1z].X[29] = P1.C[2].X[29];
    T[`P1x].X[30] = P1.C[0].X[30]; T[`P1y].X[30] = P1.C[1].X[30]; T[`P1z].X[30] = P1.C[2].X[30];
    T[`P1x].X[31] = P1.C[0].X[31]; T[`P1y].X[31] = P1.C[1].X[31]; T[`P1z].X[31] = P1.C[2].X[31];
    T[`P1x].X[32] = P1.C[0].X[32]; T[`P1y].X[32] = P1.C[1].X[32]; T[`P1z].X[32] = P1.C[2].X[32];
    T[`P1x].X[33] = P1.C[0].X[33]; T[`P1y].X[33] = P1.C[1].X[33]; T[`P1z].X[33] = P1.C[2].X[33];
    T[`P1x].X[34] = P1.C[0].X[34]; T[`P1y].X[34] = P1.C[1].X[34]; T[`P1z].X[34] = P1.C[2].X[34];
    T[`P1x].X[35] = P1.C[0].X[35]; T[`P1y].X[35] = P1.C[1].X[35]; T[`P1z].X[35] = P1.C[2].X[35];
    T[`P1x].X[36] = P1.C[0].X[36]; T[`P1y].X[36] = P1.C[1].X[36]; T[`P1z].X[36] = P1.C[2].X[36];

    T[`P2x].X[ 0] = P2.C[0].X[ 0]; T[`P2y].X[ 0] = P2.C[1].X[ 0]; T[`P2z].X[ 0] = P2.C[2].X[ 0];
    T[`P2x].X[ 1] = P2.C[0].X[ 1]; T[`P2y].X[ 1] = P2.C[1].X[ 1]; T[`P2z].X[ 1] = P2.C[2].X[ 1];
    T[`P2x].X[ 2] = P2.C[0].X[ 2]; T[`P2y].X[ 2] = P2.C[1].X[ 2]; T[`P2z].X[ 2] = P2.C[2].X[ 2];
    T[`P2x].X[ 3] = P2.C[0].X[ 3]; T[`P2y].X[ 3] = P2.C[1].X[ 3]; T[`P2z].X[ 3] = P2.C[2].X[ 3];
    T[`P2x].X[ 4] = P2.C[0].X[ 4]; T[`P2y].X[ 4] = P2.C[1].X[ 4]; T[`P2z].X[ 4] = P2.C[2].X[ 4];
    T[`P2x].X[ 5] = P2.C[0].X[ 5]; T[`P2y].X[ 5] = P2.C[1].X[ 5]; T[`P2z].X[ 5] = P2.C[2].X[ 5];
    T[`P2x].X[ 6] = P2.C[0].X[ 6]; T[`P2y].X[ 6] = P2.C[1].X[ 6]; T[`P2z].X[ 6] = P2.C[2].X[ 6];
    T[`P2x].X[ 7] = P2.C[0].X[ 7]; T[`P2y].X[ 7] = P2.C[1].X[ 7]; T[`P2z].X[ 7] = P2.C[2].X[ 7];
    T[`P2x].X[ 8] = P2.C[0].X[ 8]; T[`P2y].X[ 8] = P2.C[1].X[ 8]; T[`P2z].X[ 8] = P2.C[2].X[ 8];
    T[`P2x].X[ 9] = P2.C[0].X[ 9]; T[`P2y].X[ 9] = P2.C[1].X[ 9]; T[`P2z].X[ 9] = P2.C[2].X[ 9];
    T[`P2x].X[10] = P2.C[0].X[10]; T[`P2y].X[10] = P2.C[1].X[10]; T[`P2z].X[10] = P2.C[2].X[10];
    T[`P2x].X[11] = P2.C[0].X[11]; T[`P2y].X[11] = P2.C[1].X[11]; T[`P2z].X[11] = P2.C[2].X[11];
    T[`P2x].X[12] = P2.C[0].X[12]; T[`P2y].X[12] = P2.C[1].X[12]; T[`P2z].X[12] = P2.C[2].X[12];
    T[`P2x].X[13] = P2.C[0].X[13]; T[`P2y].X[13] = P2.C[1].X[13]; T[`P2z].X[13] = P2.C[2].X[13];
    T[`P2x].X[14] = P2.C[0].X[14]; T[`P2y].X[14] = P2.C[1].X[14]; T[`P2z].X[14] = P2.C[2].X[14];
    T[`P2x].X[15] = P2.C[0].X[15]; T[`P2y].X[15] = P2.C[1].X[15]; T[`P2z].X[15] = P2.C[2].X[15];
    T[`P2x].X[16] = P2.C[0].X[16]; T[`P2y].X[16] = P2.C[1].X[16]; T[`P2z].X[16] = P2.C[2].X[16];
    T[`P2x].X[17] = P2.C[0].X[17]; T[`P2y].X[17] = P2.C[1].X[17]; T[`P2z].X[17] = P2.C[2].X[17];
    T[`P2x].X[18] = P2.C[0].X[18]; T[`P2y].X[18] = P2.C[1].X[18]; T[`P2z].X[18] = P2.C[2].X[18];
    T[`P2x].X[19] = P2.C[0].X[19]; T[`P2y].X[19] = P2.C[1].X[19]; T[`P2z].X[19] = P2.C[2].X[19];
    T[`P2x].X[20] = P2.C[0].X[20]; T[`P2y].X[20] = P2.C[1].X[20]; T[`P2z].X[20] = P2.C[2].X[20];
    T[`P2x].X[21] = P2.C[0].X[21]; T[`P2y].X[21] = P2.C[1].X[21]; T[`P2z].X[21] = P2.C[2].X[21];
    T[`P2x].X[22] = P2.C[0].X[22]; T[`P2y].X[22] = P2.C[1].X[22]; T[`P2z].X[22] = P2.C[2].X[22];
    T[`P2x].X[23] = P2.C[0].X[23]; T[`P2y].X[23] = P2.C[1].X[23]; T[`P2z].X[23] = P2.C[2].X[23];
    T[`P2x].X[24] = P2.C[0].X[24]; T[`P2y].X[24] = P2.C[1].X[24]; T[`P2z].X[24] = P2.C[2].X[24];
    T[`P2x].X[25] = P2.C[0].X[25]; T[`P2y].X[25] = P2.C[1].X[25]; T[`P2z].X[25] = P2.C[2].X[25];
    T[`P2x].X[26] = P2.C[0].X[26]; T[`P2y].X[26] = P2.C[1].X[26]; T[`P2z].X[26] = P2.C[2].X[26];
    T[`P2x].X[27] = P2.C[0].X[27]; T[`P2y].X[27] = P2.C[1].X[27]; T[`P2z].X[27] = P2.C[2].X[27];
    T[`P2x].X[28] = P2.C[0].X[28]; T[`P2y].X[28] = P2.C[1].X[28]; T[`P2z].X[28] = P2.C[2].X[28];
    T[`P2x].X[29] = P2.C[0].X[29]; T[`P2y].X[29] = P2.C[1].X[29]; T[`P2z].X[29] = P2.C[2].X[29];
    T[`P2x].X[30] = P2.C[0].X[30]; T[`P2y].X[30] = P2.C[1].X[30]; T[`P2z].X[30] = P2.C[2].X[30];
    T[`P2x].X[31] = P2.C[0].X[31]; T[`P2y].X[31] = P2.C[1].X[31]; T[`P2z].X[31] = P2.C[2].X[31];
    T[`P2x].X[32] = P2.C[0].X[32]; T[`P2y].X[32] = P2.C[1].X[32]; T[`P2z].X[32] = P2.C[2].X[32];
    T[`P2x].X[33] = P2.C[0].X[33]; T[`P2y].X[33] = P2.C[1].X[33]; T[`P2z].X[33] = P2.C[2].X[33];
    T[`P2x].X[34] = P2.C[0].X[34]; T[`P2y].X[34] = P2.C[1].X[34]; T[`P2z].X[34] = P2.C[2].X[34];
    T[`P2x].X[35] = P2.C[0].X[35]; T[`P2y].X[35] = P2.C[1].X[35]; T[`P2z].X[35] = P2.C[2].X[35];
    T[`P2x].X[36] = P2.C[0].X[36]; T[`P2y].X[36] = P2.C[1].X[36]; T[`P2z].X[36] = P2.C[2].X[36];

    /*
     * Run formulas.
     */
    for (U = 0; True; ++U)
    {
        Op = Code[U];
        if (Op == 0)
        {
            break;
        }

        D = (Op >>> 8) & 0x0F;
        A = (Op >>> 4) & 0x0F;
        B = Op & 0x0F;
        Op = Op >>> 12;
        switch (Op)
        {
            case 0:
                // memcpy(t[d], t[a], I15_LEN * sizeof(uint16_t));
                T[D    ].X[ 0] = T[A    ].X[ 0];
                T[D    ].X[ 1] = T[A    ].X[ 1];
                T[D    ].X[ 2] = T[A    ].X[ 2];
                T[D    ].X[ 3] = T[A    ].X[ 3];
                T[D    ].X[ 4] = T[A    ].X[ 4];
                T[D    ].X[ 5] = T[A    ].X[ 5];
                T[D    ].X[ 6] = T[A    ].X[ 6];
                T[D    ].X[ 7] = T[A    ].X[ 7];
                T[D    ].X[ 8] = T[A    ].X[ 8];
                T[D    ].X[ 9] = T[A    ].X[ 9];
                T[D    ].X[10] = T[A    ].X[10];
                T[D    ].X[11] = T[A    ].X[11];
                T[D    ].X[12] = T[A    ].X[12];
                T[D    ].X[13] = T[A    ].X[13];
                T[D    ].X[14] = T[A    ].X[14];
                T[D    ].X[15] = T[A    ].X[15];
                T[D    ].X[16] = T[A    ].X[16];
                T[D    ].X[17] = T[A    ].X[17];
                T[D    ].X[18] = T[A    ].X[18];
                T[D    ].X[19] = T[A    ].X[19];
                T[D    ].X[20] = T[A    ].X[20];
                T[D    ].X[21] = T[A    ].X[21];
                T[D    ].X[22] = T[A    ].X[22];
                T[D    ].X[23] = T[A    ].X[23];
                T[D    ].X[24] = T[A    ].X[24];
                T[D    ].X[25] = T[A    ].X[25];
                T[D    ].X[26] = T[A    ].X[26];
                T[D    ].X[27] = T[A    ].X[27];
                T[D    ].X[28] = T[A    ].X[28];
                T[D    ].X[29] = T[A    ].X[29];
                T[D    ].X[30] = T[A    ].X[30];
                T[D    ].X[31] = T[A    ].X[31];
                T[D    ].X[32] = T[A    ].X[32];
                T[D    ].X[33] = T[A    ].X[33];
                T[D    ].X[34] = T[A    ].X[34];
                T[D    ].X[35] = T[A    ].X[35];
                T[D    ].X[36] = T[A    ].X[36];

                D_Tmp = D + 1;
                A_Tmp = A + 1;
                T[D_Tmp].X[ 0] = T[A_Tmp].X[ 0];
                T[D_Tmp].X[ 1] = T[A_Tmp].X[ 1];
                T[D_Tmp].X[ 2] = T[A_Tmp].X[ 2];
                T[D_Tmp].X[ 3] = T[A_Tmp].X[ 3];
                T[D_Tmp].X[ 4] = T[A_Tmp].X[ 4];
                T[D_Tmp].X[ 5] = T[A_Tmp].X[ 5];
                T[D_Tmp].X[ 6] = T[A_Tmp].X[ 6];
                T[D_Tmp].X[ 7] = T[A_Tmp].X[ 7];
                T[D_Tmp].X[ 8] = T[A_Tmp].X[ 8];
                T[D_Tmp].X[ 9] = T[A_Tmp].X[ 9];
                T[D_Tmp].X[10] = T[A_Tmp].X[10];
                T[D_Tmp].X[11] = T[A_Tmp].X[11];
                T[D_Tmp].X[12] = T[A_Tmp].X[12];
                T[D_Tmp].X[13] = T[A_Tmp].X[13];
                T[D_Tmp].X[14] = T[A_Tmp].X[14];
                T[D_Tmp].X[15] = T[A_Tmp].X[15];
                T[D_Tmp].X[16] = T[A_Tmp].X[16];
                T[D_Tmp].X[17] = T[A_Tmp].X[17];
                T[D_Tmp].X[18] = T[A_Tmp].X[18];
                T[D_Tmp].X[19] = T[A_Tmp].X[19];
                T[D_Tmp].X[20] = T[A_Tmp].X[20];
                T[D_Tmp].X[21] = T[A_Tmp].X[21];
                T[D_Tmp].X[22] = T[A_Tmp].X[22];
                T[D_Tmp].X[23] = T[A_Tmp].X[23];
                T[D_Tmp].X[24] = T[A_Tmp].X[24];
                T[D_Tmp].X[25] = T[A_Tmp].X[25];
                T[D_Tmp].X[26] = T[A_Tmp].X[26];
                T[D_Tmp].X[27] = T[A_Tmp].X[27];
                T[D_Tmp].X[28] = T[A_Tmp].X[28];
                T[D_Tmp].X[29] = T[A_Tmp].X[29];
                T[D_Tmp].X[30] = T[A_Tmp].X[30];
                T[D_Tmp].X[31] = T[A_Tmp].X[31];
                T[D_Tmp].X[32] = T[A_Tmp].X[32];
                T[D_Tmp].X[33] = T[A_Tmp].X[33];
                T[D_Tmp].X[34] = T[A_Tmp].X[34];
                T[D_Tmp].X[35] = T[A_Tmp].X[35];
                T[D_Tmp].X[36] = T[A_Tmp].X[36];
                break;
            case 1:
                Ctl = class'FCryptoBigInt'.static.Add_Static37(T[D].X, T[A].X, 1);
                Ctl = Ctl | class'FCryptoBigInt'.static.NOT(
                    class'FCryptoBigInt'.static.Sub_Static37_DynB(T[D].X, Cc.P, 0));
                class'FCryptoBigInt'.static.Sub_Static37_DynB(T[D].X, Cc.P, Ctl);
                break;
            case 2:
                class'FCryptoBigInt'.static.Add_Static37_DynB(T[D].X, Cc.P,
                    class'FCryptoBigInt'.static.Sub_Static37(T[D].X, T[A].X, 1));
                break;
            case 3:
                class'FCryptoBigInt'.static.MontyMul_S37_S37_S37_DynM(
                    T[D].X, T[A].X, T[B].X, Cc.P, Cc.P0i);
                break;
            case 4:
                PLen = (Cc.P[0] - (Cc.P[0] >>> 4) + 7) >>> 3;
                class'FCryptoBigInt'.static.Encode_Static66(Tp, PLen, Cc.P);
                Tp[PLen - 1] -= 2;
                class'FCryptoBigInt'.static.ModPow_S37_S66_Dyn_S37_S37(
                    T[D].X, Tp, PLen, Cc.P, Cc.P0i, T[A].X, T[B].X);
                break;
            default:
                R = R & class'FCryptoBigInt'.static.BIsZero_Static37(T[D].X);
                break;
        }
    }

    /*
     * Copy back result.
     */
    // memcpy(P1->c, t[P1x], 3 * I15_LEN * sizeof(uint16_t));
    P1.C[0].X[ 0] = T[`P1x].X[ 0]; P1.C[1].X[ 0] = T[`P1y].X[ 0]; P1.C[2].X[ 0] = T[`P1z].X[ 0];
    P1.C[0].X[ 1] = T[`P1x].X[ 1]; P1.C[1].X[ 1] = T[`P1y].X[ 1]; P1.C[2].X[ 1] = T[`P1z].X[ 1];
    P1.C[0].X[ 2] = T[`P1x].X[ 2]; P1.C[1].X[ 2] = T[`P1y].X[ 2]; P1.C[2].X[ 2] = T[`P1z].X[ 2];
    P1.C[0].X[ 3] = T[`P1x].X[ 3]; P1.C[1].X[ 3] = T[`P1y].X[ 3]; P1.C[2].X[ 3] = T[`P1z].X[ 3];
    P1.C[0].X[ 4] = T[`P1x].X[ 4]; P1.C[1].X[ 4] = T[`P1y].X[ 4]; P1.C[2].X[ 4] = T[`P1z].X[ 4];
    P1.C[0].X[ 5] = T[`P1x].X[ 5]; P1.C[1].X[ 5] = T[`P1y].X[ 5]; P1.C[2].X[ 5] = T[`P1z].X[ 5];
    P1.C[0].X[ 6] = T[`P1x].X[ 6]; P1.C[1].X[ 6] = T[`P1y].X[ 6]; P1.C[2].X[ 6] = T[`P1z].X[ 6];
    P1.C[0].X[ 7] = T[`P1x].X[ 7]; P1.C[1].X[ 7] = T[`P1y].X[ 7]; P1.C[2].X[ 7] = T[`P1z].X[ 7];
    P1.C[0].X[ 8] = T[`P1x].X[ 8]; P1.C[1].X[ 8] = T[`P1y].X[ 8]; P1.C[2].X[ 8] = T[`P1z].X[ 8];
    P1.C[0].X[ 9] = T[`P1x].X[ 9]; P1.C[1].X[ 9] = T[`P1y].X[ 9]; P1.C[2].X[ 9] = T[`P1z].X[ 9];
    P1.C[0].X[10] = T[`P1x].X[10]; P1.C[1].X[10] = T[`P1y].X[10]; P1.C[2].X[10] = T[`P1z].X[10];
    P1.C[0].X[11] = T[`P1x].X[11]; P1.C[1].X[11] = T[`P1y].X[11]; P1.C[2].X[11] = T[`P1z].X[11];
    P1.C[0].X[12] = T[`P1x].X[12]; P1.C[1].X[12] = T[`P1y].X[12]; P1.C[2].X[12] = T[`P1z].X[12];
    P1.C[0].X[13] = T[`P1x].X[13]; P1.C[1].X[13] = T[`P1y].X[13]; P1.C[2].X[13] = T[`P1z].X[13];
    P1.C[0].X[14] = T[`P1x].X[14]; P1.C[1].X[14] = T[`P1y].X[14]; P1.C[2].X[14] = T[`P1z].X[14];
    P1.C[0].X[15] = T[`P1x].X[15]; P1.C[1].X[15] = T[`P1y].X[15]; P1.C[2].X[15] = T[`P1z].X[15];
    P1.C[0].X[16] = T[`P1x].X[16]; P1.C[1].X[16] = T[`P1y].X[16]; P1.C[2].X[16] = T[`P1z].X[16];
    P1.C[0].X[17] = T[`P1x].X[17]; P1.C[1].X[17] = T[`P1y].X[17]; P1.C[2].X[17] = T[`P1z].X[17];
    P1.C[0].X[18] = T[`P1x].X[18]; P1.C[1].X[18] = T[`P1y].X[18]; P1.C[2].X[18] = T[`P1z].X[18];
    P1.C[0].X[19] = T[`P1x].X[19]; P1.C[1].X[19] = T[`P1y].X[19]; P1.C[2].X[19] = T[`P1z].X[19];
    P1.C[0].X[20] = T[`P1x].X[20]; P1.C[1].X[20] = T[`P1y].X[20]; P1.C[2].X[20] = T[`P1z].X[20];
    P1.C[0].X[21] = T[`P1x].X[21]; P1.C[1].X[21] = T[`P1y].X[21]; P1.C[2].X[21] = T[`P1z].X[21];
    P1.C[0].X[22] = T[`P1x].X[22]; P1.C[1].X[22] = T[`P1y].X[22]; P1.C[2].X[22] = T[`P1z].X[22];
    P1.C[0].X[23] = T[`P1x].X[23]; P1.C[1].X[23] = T[`P1y].X[23]; P1.C[2].X[23] = T[`P1z].X[23];
    P1.C[0].X[24] = T[`P1x].X[24]; P1.C[1].X[24] = T[`P1y].X[24]; P1.C[2].X[24] = T[`P1z].X[24];
    P1.C[0].X[25] = T[`P1x].X[25]; P1.C[1].X[25] = T[`P1y].X[25]; P1.C[2].X[25] = T[`P1z].X[25];
    P1.C[0].X[26] = T[`P1x].X[26]; P1.C[1].X[26] = T[`P1y].X[26]; P1.C[2].X[26] = T[`P1z].X[26];
    P1.C[0].X[27] = T[`P1x].X[27]; P1.C[1].X[27] = T[`P1y].X[27]; P1.C[2].X[27] = T[`P1z].X[27];
    P1.C[0].X[28] = T[`P1x].X[28]; P1.C[1].X[28] = T[`P1y].X[28]; P1.C[2].X[28] = T[`P1z].X[28];
    P1.C[0].X[29] = T[`P1x].X[29]; P1.C[1].X[29] = T[`P1y].X[29]; P1.C[2].X[29] = T[`P1z].X[29];
    P1.C[0].X[30] = T[`P1x].X[30]; P1.C[1].X[30] = T[`P1y].X[30]; P1.C[2].X[30] = T[`P1z].X[30];
    P1.C[0].X[31] = T[`P1x].X[31]; P1.C[1].X[31] = T[`P1y].X[31]; P1.C[2].X[31] = T[`P1z].X[31];
    P1.C[0].X[32] = T[`P1x].X[32]; P1.C[1].X[32] = T[`P1y].X[32]; P1.C[2].X[32] = T[`P1z].X[32];
    P1.C[0].X[33] = T[`P1x].X[33]; P1.C[1].X[33] = T[`P1y].X[33]; P1.C[2].X[33] = T[`P1z].X[33];
    P1.C[0].X[34] = T[`P1x].X[34]; P1.C[1].X[34] = T[`P1y].X[34]; P1.C[2].X[34] = T[`P1z].X[34];
    P1.C[0].X[35] = T[`P1x].X[35]; P1.C[1].X[35] = T[`P1y].X[35]; P1.C[2].X[35] = T[`P1z].X[35];
    P1.C[0].X[36] = T[`P1x].X[36]; P1.C[1].X[36] = T[`P1y].X[36]; P1.C[2].X[36] = T[`P1z].X[36];

    return R;
}

static final function SetOne(
    out int X[37],
    const out int P[37]
)
{
    local int PLen;

    PLen = (P[0] + 31) >>> 4;
    // memset(x, 0, plen * sizeof *x);
    class'FCryptoMemory'.static.MemSet_UInt16_Static37(X, 0, PLen * SIZEOF_UINT16_T);
    X[0] = P[0];
    X[1] = 0x0001;
}

static final function PointZero(
    out Jacobian P,
    const out CurveParams Cc
)
{
    // memset(P, 0, sizeof *P);
    // `ZERO_JACOBIAN(P); <-- this is much slower than assignment.
    P = default.ZERO_JACOBIAN;

    P.C[0].X[0] = Cc.P[0];
    P.C[1].X[0] = Cc.P[0];
    P.C[2].X[0] = Cc.P[0];
}

static final function PointDouble(
    out Jacobian P,
    const out CurveParams Cc
)
{
    RunCode(P, P, Cc, default.CodeDouble);
}

static final function int PointAdd(
    out Jacobian P1,
    const out Jacobian P2,
    const out CurveParams Cc
)
{
    return RunCode(P1, P2, Cc, default.CodeAdd);
}

static final function PointMul(
    out Jacobian P,
    const out array<byte> X,
    int XLen,
    const out CurveParams Cc
)
{
    local int Qz;
    local int K;
    local int Bits;
    local int Bnz;
    local int XOffset;
    local Jacobian P2;
    local Jacobian P3;
    local Jacobian Q;
    local Jacobian T;
    local Jacobian U;

    /*
     * We do a simple double-and-add ladder with a 2-bit window
     * to make only one add every two doublings. We thus first
     * precompute 2P and 3P in some local buffers.
     *
     * We always perform two doublings and one addition; the
     * addition is with P, 2P and 3P and is done in a temporary
     * array.
     *
     * The addition code cannot handle cases where one of the
     * operands is infinity, which is the case at the start of the
     * ladder. We therefore need to maintain a flag that controls
     * this situation.
     */

    // memcpy(&P2, P, sizeof P2);
    PointDouble(P2, Cc);
    // memcpy(&P3, P, sizeof P3);
    PointAdd(P3, P2, Cc);

    PointZero(Q, Cc);
    Qz = 1;
    XOffset = 0;
    while (XLen-- > 0)
    {
        for (K = 6; K >= 0; K -= 2)
        {
            PointDouble(Q, Cc);
            PointDouble(Q, Cc);
            // memcpy(&T, P, sizeof T);
            // memcpy(&U, &Q, sizeof U);
            // TODO: offset parameter needed for X?
            Bits = (X[XOffset] >>> K) & 3;
            Bnz = class'FCryptoBigInt'.static.NEQ(Bits, 0);
            // TODO:
            // class'FCryptoBigInt'.static.CCOPY(class'FCryptoBigInt'.static.EQ(Bits, 2), T, P2, 0 /* sizeof T */);
            // class'FCryptoBigInt'.static.CCOPY(class'FCryptoBigInt'.static.EQ(Bits, 3), T, P3, 0 /* sizeof T */);
            PointAdd(U, T, Cc);
            // CCOPY(bnz & qz, &Q, &T, sizeof Q);
            // CCOPY(bnz & ~qz, &Q, &U, sizeof Q);
            Qz = Qz & (~Bnz);
        }
        ++XOffset;
    }
    // memcpy(P, &Q, sizeof Q);
}

static final function int PointDecode(
    out Jacobian P,
    const out array<byte> Src,
    int Len,
    const out CurveParams Cc
)
{
    local int PLen;
    local int ZLen;
    local int R;
    local Jacobian Q;

    /*
     * Points must use uncompressed format:
     * -- first byte is 0x04;
     * -- coordinates X and Y use unsigned big-endian, with the same
     *    length as the field modulus.
     *
     * We don't support hybrid format (uncompressed, but first byte
     * has value 0x06 or 0x07, depending on the least significant bit
     * of Y) because it is rather useless, and explicitly forbidden
     * by PKIX (RFC 5480, section 2.2).
     *
     * We don't support compressed format either, because it is not
     * much used in practice (there are or were patent-related
     * concerns about point compression, which explains the lack of
     * generalised support). Also, point compression support would
     * need a bit more code.
     */

    PointZero(P, Cc);
    PLen = (CC.P[0] - (CC.P[0] >>> 4) + 7) >>> 3;
    if (Len != 1 + (PLen << 1))
    {
        return 0;
    }
    // R = class'FCryptoBigInt'.static.DecodeMod(P.C[0], Buf + 1, PLen, CC.P);
    // R = R & class'FCryptoBigInt'.static.DecodeMod(P.C[0], Buf + 1 + PLen, PLen, Cc.P);

    /*
     * Check first byte.
     */
    R = R & class'FCryptoBigInt'.static.EQ(Src[0], 0x04);

    /*
     * Convert coordinates and check that the point is valid.
     */
    // ZLen = ((Cc.P[0] + 31) >>> 4) * SIZEOF_UINT16_T;
    // memcpy(Q.c[0], cc->R2, zlen);
	// memcpy(Q.c[1], cc->b, zlen);
	// SetOne(Q.C[2], Cc.P); TODO: need another variant for this.
	R = R & ~RunCode(P, Q, Cc, default.CodeCheck);
    return R;
}

/*
 * Encode a point. This method assumes that the point is correct and is
 * not the point at infinity. Encoded size is always 1+2*plen, where
 * plen is the field modulus length, in bytes.
 */
static final function PointEncode(
    out array<byte> Dst,
    const out Jacobian P,
    const out CurveParams Cc
)
{
}

// Differs from C version: const out param for performance.
// TODO: benchmark the actual difference when this has a return value struct.
static final function IdToCurve(
    EFCEllipticCurve Curve,
    out CurveParams out_CurveParams
)
{
    out_CurveParams = default._PP[Curve - FCEC_Secp256r1];
}

static function array<byte> Generator(EFCEllipticCurve Curve, out int Len)
{
    local array<byte> TODO;
    TODO.Length = 0;
    return TODO;
}

static function array<byte> Order(EFCEllipticCurve Curve, out int Len)
{
    local array<byte> TODO;
    TODO.Length = 0;
    return TODO;
}

static function int XOff(EFCEllipticCurve Curve, out int Len)
{
    return -1;
}

static function int Mul(
    out array<byte> G,
    int GLen,
    const out array<byte> Kb,
    int KbLen,
    EFCEllipticCurve Curve
)
{
    return -1;
}

static function int MulGen(
    out array<byte> R,
    const out array<byte> X,
    int XLen,
    EFCEllipticCurve Curve
)
{
    return -1;
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
    return -1;
}

DefaultProperties
{
    // TODO: are these needed?
    P256_P  = {(`P256_P_VALUES)}
    P256_R2 = {(`P256_R2_VALUES)}
    P256_B  = {(`P256_B_VALUES)}
    P384_P  = {(`P384_P_VALUES)}
    P384_R2 = {(`P384_R2_VALUES)}
    P384_B  = {(`P384_B_VALUES)}
    P521_P  = {(`P521_P_VALUES)}
    P521_R2 = {(`P521_R2_VALUES)}
    P521_B  = {(`P521_B_VALUES)}

    _PP(0)={(P=(`P256_P_VALUES), B=(`P256_B_VALUES), R2=(`P256_R2_VALUES), P0i=0x001, PointLen=65)}
    _PP(1)={(P=(`P384_P_VALUES), B=(`P384_B_VALUES), R2=(`P384_R2_VALUES), P0i=0x001, PointLen=97)}
    _PP(2)={(P=(`P521_P_VALUES), B=(`P521_B_VALUES), R2=(`P521_R2_VALUES), P0i=0x001, PointLen=133)}

    CodeDouble={(
        /*
        * Compute z^2 (in t1).
        */
        // `MMUL(`t1, `Pz, `Pz),
        13858,

        /*
        * Compute x-z^2 (in t2) and then x+z^2 (in t1).
        */
        // `MSET(`t2, `Px),
        // `MSUB(`t2, `t1),
        // `MADD(`t1, `Px),
        1792,
        10080,
        5632,

        /*
        * Compute m = 3*(x+z^2)*(x-z^2) (in t1).
        */
        // `MMUL(`t3, `t1, `t2),
        // `MSET(`t1, `t3),
        // `MADD(`t1, `t3),
        // `MADD(`t1, `t3),
        14439,
        1664,
        5760,
        5760,

        /*
        * Compute s = 4*x*y^2 (in t2) and 2*y^2 (in t3).
        */
        // `MMUL(`t3, `Py, `Py),
        // `MADD(`t3, `t3),
        // `MMUL(`t2, `Px, `t3),
        // `MADD(`t2, `t2),
        14353,
        6272,
        14088,
        6000,

        /*
        * Compute x' = m^2 - 2*s.
        */
        // `MMUL(`Px, `t1, `t1),
        // `MSUB(`Px, `t2),
        // `MSUB(`Px, `t2),
        12390,
        8304,
        8304,

        /*
        * Compute z' = 2*y*z.
        */
        // `MMUL(`t4, `Py, `Pz),
        // `MSET(`Pz, `t4),
        // `MADD(`Pz, `t4),
        14610,
        656,
        4752,

        /*
        * Compute y' = m*(s - x') - 8*y^4. Note that we already have
        * 2*y^2 in t3.
        */
        // `MSUB(`t2, `Px),
        // `MMUL(`Py, `t1, `t2),
        // `MMUL(`t4, `t3, `t3),
        // `MSUB(`Py, `t4),
        // `MSUB(`Py, `t4),
        9984,
        12647,
        14728,
        8592,
        8592,

        `ENCODE
    )}

    CodeAdd={(

        `ENCODE
    )}

    CodeCheck={(

        `ENCODE
    )}
}
