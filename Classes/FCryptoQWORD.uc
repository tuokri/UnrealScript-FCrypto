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
    // This is actually "less-than-or-equal"?
    // local int Msb;

    // Msb = A ^ B;
    // Msb = Msb | (Msb >>>  1);
    // Msb = Msb | (Msb >>>  2);
    // Msb = Msb | (Msb >>>  4);
    // Msb = Msb | (Msb >>>  8);
    // Msb = Msb | (Msb >>> 16);
    // Msb = Msb - (Msb >>>  1);
    // return !bool((B & Msb) ^ Msb);

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
