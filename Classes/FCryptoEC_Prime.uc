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
    local int A;
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
    // TODO: need static memcpy for these array sizes.

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
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                break;
            case 4:
                break;
            default:
                // TODO: need static variant for this too.
                // R = R & (class'FCryptoBigInt'.static.BIsZero(T[D]));
                break;
        }
    }

    return R;
}

static final function CurveParams IdToCurve(EFCEllipticCurve Curve)
{
    return default._PP[Curve - FCEC_Secp256r1];
};

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

        `ENDCODE
    )}

    CodeAdd={(

    )}

    CodeCheck={(

    )}
}
