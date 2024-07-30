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
interface FCryptoEllipticCurve;

`include(FCrypto\Classes\FCryptoMacros.uci);

enum EFCEllipticCurve
{
    FCEC_Reserved,              // Not used.
    FCEC_Sect163k1,             // Not used.
    FCEC_Sect163r1,             // Not used.
    FCEC_Sect163r2,             // Not used.
    FCEC_Sect193r1,             // Not used.
    FCEC_Sect193r2,             // Not used.
    FCEC_Sect233k1,             // Not used.
    FCEC_Sect233r1,             // Not used.
    FCEC_Sect239k1,             // Not used.
    FCEC_Sect283k1,             // Not used.
    FCEC_Sect283r1,             // Not used.
    FCEC_Sect409k1,             // Not used.
    FCEC_Sect409r1,             // Not used.
    FCEC_Sect571k1,             // Not used.
    FCEC_Sect571r1,             // Not used.
    FCEC_Secp160k1,             // Not used.
    FCEC_Secp160r1,             // Not used.
    FCEC_Secp160r2,             // Not used.
    FCEC_Secp192k1,             // Not used.
    FCEC_Secp192r1,             // Not used.
    FCEC_Secp224k1,             // Not used.
    FCEC_Secp224r1,             // Not used.
    FCEC_Secp256k1,             // Not used.
    FCEC_Secp256r1,             // TODO: Not used?
    FCEC_Secp384r1,             // TODO: Not used?
    FCEC_Secp521r1,             // TODO: Not used?
    FCEC_BrainpoolP256r1,       // Not used.
    FCEC_BrainpoolP384r1,       // Not used.
    FCEC_BrainpoolP512r1,       // Not used.
    FCEC_Curve25519,
    FCEC_Curve448,              // Not used.
};

static function array<byte> Generator(EFCEllipticCurve Curve, out int Len);

static function array<byte> Order(EFCEllipticCurve Curve, out int Len);

static function int XOff(EFCEllipticCurve Curve, out int Len);

static function int Mul(
    out array<byte> G,
    int GLen,
    const out array<byte> Kb,
    int KbLen,
    EFCEllipticCurve Curve
);

static function int MulGen(
    out array<byte> R,
    const out array<byte> X,
    int XLen,
    EFCEllipticCurve Curve
);

static function int MulAdd(
    out array<byte> A,
    const out array<byte> B,
    int Len,
    const out array<byte> X,
    int XLen,
    const out array<byte> Y,
    int YLen,
    EFCEllipticCurve Curve
);
