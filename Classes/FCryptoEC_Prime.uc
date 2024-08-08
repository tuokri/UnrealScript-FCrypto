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

static final function CurveParams IdToCurve(EFCEllipticCurve Curve)
{
    return default._PP[Curve - FCEC_Secp256r1];
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
    P256_P={(`P256_P_VALUES)}
    P256_R2={(`P256_R2_VALUES)}
    P256_B={(`P256_B_VALUES)}
    P384_P={(`P384_P_VALUES)}
    P384_R2={(`P384_R2_VALUES)}
    P384_B={(`P384_B_VALUES)}
    P521_P={(`P521_P_VALUES)}
    P521_R2={(`P521_R2_VALUES)}
    P521_B={(`P521_B_VALUES)}

    _PP(0)={(P=(`P256_P_VALUES), B=(`P256_B_VALUES), R2=(`P256_R2_VALUES), P0i=0x001, PointLen=65)}
    _PP(1)={(P=(`P384_P_VALUES), B=(`P384_B_VALUES), R2=(`P384_R2_VALUES), P0i=0x001, PointLen=97)}
    _PP(2)={(P=(`P521_P_VALUES), B=(`P521_B_VALUES), R2=(`P521_R2_VALUES), P0i=0x001, PointLen=133)}
}
