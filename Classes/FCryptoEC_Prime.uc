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

static final function CurveParams IdToCurve(FCryptoEllipticCurve Curve)
{
    return _PP[Curve - FCEC_Secp256r1];
};

`define I15_LEN   ((`BR_MAX_EC_SIZE + 29) / 15)

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
`define ENDCODE         0

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

DefaultProperties
{
    P256_P={(
        0x0111,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x003F, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x1000, 0x0000, 0x4000, 0x7FFF,
        0x7FFF, 0x0001
    )}
    P256_R2={(
        0x0111,
        0x0000, 0x6000, 0x0000, 0x0000, 0x0000, 0x0000, 0x7FFC, 0x7FFF,
        0x7FBF, 0x7FFF, 0x7FBF, 0x7FFF, 0x7FFF, 0x7FFF, 0x77FF, 0x7FFF,
        0x4FFF, 0x0000
    )}
    P256_B={(
        0x0111,
        0x770C, 0x5EEF, 0x29C4, 0x3EC4, 0x6273, 0x0486, 0x4543, 0x3993,
        0x3C01, 0x6B56, 0x212E, 0x57EE, 0x4882, 0x204B, 0x7483, 0x3C16,
        0x0187, 0x0000
    )}
    P384_P={(
        0x0199,
        0x7FFF, 0x7FFF, 0x0003, 0x0000, 0x0000, 0x0000, 0x7FC0, 0x7FFF,
        0x7EFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x01FF
    )}
    P384_R2={(
        0x0199,
        0x1000, 0x0000, 0x0000, 0x7FFF, 0x7FFF, 0x0001, 0x0000, 0x0010,
        0x0000, 0x0000, 0x0000, 0x7F00, 0x7FFF, 0x01FF, 0x0000, 0x1000,
        0x0000, 0x2000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000
    )}
    P384_B={(
        0x0199,
        0x7333, 0x2096, 0x70D1, 0x2310, 0x3020, 0x6197, 0x1464, 0x35BB,
        0x70CA, 0x0117, 0x1920, 0x4136, 0x5FC8, 0x5713, 0x4938, 0x7DD2,
        0x4DD2, 0x4A71, 0x0220, 0x683E, 0x2C87, 0x4DB1, 0x7BFF, 0x6C09,
        0x0452, 0x0084
    )}
    P521_P={(
        0x022B,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
        0x7FFF, 0x7FFF, 0x07FF
    )}
    P521_R2={(
        0x022B,
        0x0100, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000
    )}
    P521_B={(
        0x022B,
        0x7002, 0x6A07, 0x751A, 0x228F, 0x71EF, 0x5869, 0x20F4, 0x1EFC,
        0x7357, 0x37E0, 0x4EEC, 0x605E, 0x1652, 0x26F6, 0x31FA, 0x4A8F,
        0x6193, 0x3C2A, 0x3C42, 0x48C7, 0x3489, 0x6771, 0x4C57, 0x5CCD,
        0x2725, 0x545B, 0x503B, 0x5B42, 0x21A0, 0x2534, 0x687E, 0x70E4,
        0x1618, 0x27D7, 0x0465
    )}

    _PP(0)=(P=P256_P, B=P256_B, R2=P256R2, P0i=0x001, PointLen=65)
    _PP(1)=(P=P384_P, B=P384_B, R2=P384R2, P0i=0x001, PointLen=97)
    _PP(2)=(P=P521_P, B=P521_B, R2=P521R2, P0i=0x001, PointLen=133)
}
