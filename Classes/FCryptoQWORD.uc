/*
 * Copyright (c) 2024 Tuomo Kriikkula <tuokri@tuta.io>
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

class FCryptoQWORD extends Object
    abstract
    notplaceable;

// 64-bit unsigned integer simulated as two 32-bit signed integers.
struct FCQWORD
{
    var int A; // High.
    var int B; // Low.
};

// 64-bit unsigned integer simulated as four 16-bit signed words.
struct FCQWORD16
{
    var int A; // High.
    var int B;
    var int C;
    var int D; // Low.
};

// TODO: need conversion functions between FCQWORD <-> FCQWORD16!
// TODO: need variants of all comparison functions also for FCQWORD16?
// TODO: make FCQWORD_Mul with the help of FCQWORD16_Mul?

// Return A > B.
final static function bool IsGt(const out FCQWORD A, const out FCQWORD B)
{
    if (IsGt_AsUInt32(A.A, B.A))
    {
        return True;
    }

    return IsGt_AsUInt32(A.B, B.B);
}

// For benchmarking.
final static function bool IsGt_NonConst(FCQWORD A, FCQWORD B)
{
    if (IsGt_AsUInt32(A.A, B.A))
    {
        return True;
    }

    return IsGt_AsUInt32(A.B, B.B);
}

// Interpret A and B as unsigned 32-bit integers and return A > B.
final static function bool IsGt_AsUInt32(int A, int B)
{
    local int Ltb;
    local int Gtb;

    // All bits in A that are less than their corresponding bits in B.
    Ltb = ~A & B;

    // All bits in A that are greater than their corresponding bits in B.
    Gtb = A & ~B;

    Ltb = Ltb | (Ltb >>>  1);
    Ltb = Ltb | (Ltb >>>  2);
    Ltb = Ltb | (Ltb >>>  4);
    Ltb = Ltb | (Ltb >>>  8);
    Ltb = Ltb | (Ltb >>> 16);

    // A >  B --> non-zero.
    // A <= B --> zero.
    return bool(Gtb & ~Ltb);
}

final static function bool IsLt_AsUInt32(int A, int B)
{
    local int Ltb;
    local int Gtb;

    // All bits in A that are less than their corresponding bits in B.
    Ltb = ~A & B;

    // All bits in A that are greater than their corresponding bits in B.
    Gtb = A & ~B;

    Gtb = Gtb | (Gtb >>>  1);
    Gtb = Gtb | (Gtb >>>  2);
    Gtb = Gtb | (Gtb >>>  4);
    Gtb = Gtb | (Gtb >>>  8);
    Gtb = Gtb | (Gtb >>> 16);

    // A >  B --> non-zero. // TODO: does this work?
    // A <= B --> zero.     // TODO: does this work?
    return bool(Ltb & ~Gtb);
}

final static function bool IsGte_AsUInt32(int A, int B)
{
    local int Msb;

    Msb = A ^ B;
    Msb = Msb | (Msb >>>  1);
    Msb = Msb | (Msb >>>  2);
    Msb = Msb | (Msb >>>  4);
    Msb = Msb | (Msb >>>  8);
    Msb = Msb | (Msb >>> 16);
    Msb = Msb - (Msb >>>  1);
    return !bool((A & Msb) ^ Msb);
}

final static function bool IsLte_AsUInt32(int A, int B)
{
    local int Msb;

    Msb = A ^ B;
    Msb = Msb | (Msb >>>  1);
    Msb = Msb | (Msb >>>  2);
    Msb = Msb | (Msb >>>  4);
    Msb = Msb | (Msb >>>  8);
    Msb = Msb | (Msb >>> 16);
    Msb = Msb - (Msb >>>  1);
    return !bool((B & Msb) ^ Msb);
}

// Calculate QW *= Mul, return carry.
final static function int FCQWORD16_Mul(out FCQWORD16 QW, FCQWORD16 Mul)
{
    local FCQWORD16 Res;
    local int Tmp;
    local int Carry;
    local int Carry_Hi16;

    Tmp = QW.D * Mul.D;
    Carry = (Tmp >>> 16) & 0xffff;
    Res.D = Tmp & 0xffff;

    Tmp = Carry + (QW.D * Mul.C) + (QW.C * Mul.D);
    Carry = (Tmp >>> 16) & 0xffff;
    Res.C = Tmp & 0xffff;

    Tmp = Carry + (QW.D * Mul.B) + (QW.C * Mul.C) + (QW.B * Mul.D);
    Carry = (Tmp >>> 16) & 0xffff;
    Res.B = Tmp & 0xffff;

    Tmp = Carry + (QW.D * Mul.A) + (QW.C * Mul.B) + (QW.B * Mul.C) + (QW.A * Mul.D);
    Carry_Hi16 = ((QW.A * Mul.B) + (QW.B * Mul.A)) << 16;
    Carry = Carry_Hi16 | (((Tmp >>> 16) & 0xffff) + ((QW.A * Mul.C) + (QW.B * Mul.B) + (QW.C * Mul.A)));
    Res.A = Tmp & 0xffff;

    QW = Res;
    return Carry;
}

// Calculate QW += X, return carry.
final static function int FCQWORD16_AddInt(out FCQWORD16 Qw, int X)
{
    local int Carry;

    QW.D += X;

    QW.C += (QW.D >>> 16) & 0xffff;
    QW.D = QW.D & 0xffff;

    QW.B += (QW.C >>> 16) & 0xffff;
    QW.C = QW.C & 0xffff;

    QW.A += (QW.B >>> 16) & 0xffff;
    QW.B = QW.B & 0xffff;
    Carry = (QW.A >>> 16) & 0xffff;
    QW.A = QW.A & 0xffff;

    return Carry;
}
