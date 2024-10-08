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
 * Functions for C-style memory manipulation. There are probably
 * many things here to optimize out by using UScript language
 * features, but in order to maintain parity with BearSSL code
 * we'll be using these functions for now. Code duplication is
 * tolerated for the sake of performance to avoid nested function
 * calls where possible.
 *
 * Each memory block manipulation function has the following
 * name and signature scheme:
 *      FuncName_DstType_SrcType[_OptionalWidth] (args...),
 * since UScript does not have generics and multiple variants
 * of the same function are needed that take in different
 * combinations of dynamic and static arrays of different
 * static widths of bytes or integers. E.g.;
 *   MemMove_SBytes_DInts_64 (out byte Dst[64], const out array<int> Src, ...)
 *   MemMove_DInts_DInts (out array<int> Dst, const out array<int> Src, ...)
 *
 * Abbreviations:
 *   SBytes  ->  Static Bytes      ->  byte Arr[WIDTH]
 *   SInts   ->  Static Integers   ->  int Arr[WIDTH]
 *   DBytes  ->  Dynamic Bytes     ->  array<byte>
 *   DInts   ->  Dynamic Integers  ->  array<int>
 *
 * TODO: do we need functions with both Dst and Src being
 * static arrays, but with different widths?
 */
class FCryptoMemory extends Object
    abstract
    notplaceable;

`include(FCrypto\Classes\FCryptoMacros.uci);
`include(FCrypto\Classes\FCryptoMemoryMacros.uci);

static final function MemMove_SBytes_SBytes_64(
    out byte Dst[64],
    const out byte Src[64],
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    `MEMMOVE_IMPL_STATIC_DST_64();
}

static final function MemMove_SBytes_DBytes_64(
    out byte Dst[64],
    const out array<byte> Src,
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    `MEMMOVE_IMPL_STATIC_DST_64();
}

// static final function MemMove_SInts_DBytes_64(
//     out int Dst[64],
//     const out array<byte> Src,
//     int NumBytes,
//     optional int DstOffset = 0,
//     optional int SrcOffset = 0
// )
// {
// }

static final function MemCpy_SBytes_SBytes_64(
    out byte Dst[64],
    const out byte Src[64],
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    // TODO: optimized memcpy for non-overlapping arrays?
    `MEMMOVE_IMPL_STATIC_DST_64();
}

static final function MemCpy_SInts_SInts_8(
    out int Dst[8],
    const out int Src[8],
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    local int IntIndex;
    local int ByteIndex;
    local int Shift;
    local int Mask;
    local array<byte> DstBytes;
    local int DstTmp;

    DstBytes.Length = NumBytes;

    /*
     * Take all 16-bit integers from Src and put them
     * into DstBytes byte array, taking SrcOffset into account.
     */
    IntIndex = SrcOffset;
    ByteIndex = 0;
    Shift = 8;
    while (ByteIndex < NumBytes)
    {
        DstBytes[ByteIndex] = (Src[IntIndex] >>> Shift) & 0xff;
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        ++ByteIndex;
    }

    /*
     * Write DstBytes into Dst, taking DstOffset into account.
     */
    Shift = 8;
    Mask = 0xff << Shift;
    IntIndex = DstOffset;

    for (ByteIndex = 0; ByteIndex < NumBytes; ++ByteIndex)
    {
        // TODO: is DstTmp needed? (Also check other memory functions).
        DstTmp = (Dst[IntIndex] & ~Mask) | ((DstBytes[ByteIndex] & 0xff) << Shift);
        Dst[IntIndex] = DstTmp;

        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        Mask = 0xff << Shift;
    }
}

/**
 * C-style memset operation.
 * Offset is the number of byte values
 * to ignore from the beginning of S.
 */
static final function MemSet_SBytes64(
    out byte S[64],
    byte C,
    int NumBytes,
    optional int Offset = 0
)
{
    local int ByteIndex;

    for (ByteIndex = Offset; ByteIndex < NumBytes; ++ByteIndex)
    {
        S[ByteIndex] = C;
    }
}

static final function MemSet_UInt16_Static37(
    out int S[37],
    byte C,
    int NumBytes,
    optional int Offset = 0
)
{
    local int IntIndex;
    local int ByteIndex;
    local int Shift;
    local int Mask;

    Shift = 8;
    Mask = 0xff << Shift;
    IntIndex = Offset;
    for (ByteIndex = 0; ByteIndex < NumBytes; ++ByteIndex)
    {
        S[IntIndex] = (S[IntIndex] & ~Mask) | ((C & 0xff) << Shift);
        // Shift = (Shift + 8) % 16;
        Shift = (Shift + 8) & 15;
        // IntIndex += ByteIndex % 2;
        IntIndex += ByteIndex & 1;
        Mask = 0xff << Shift;
    }
}

// TODO: is this even needed?
// // Specialized for FCryptoEC_Prime.Jacobian 2D arrays.
// static final function MemCpy_Jacobian_Monty(
//     out FCryptoEC_Prime._Monty Dst,
//     const out FCryptoEC_Prime._Monty Src[3],
//     int NumBytes
// )
// {
//     local int DstIdx;
//     local int SrcIdx_0;
//     local int SrcIdx_1;

//     // Start with first sub-array, copy items until NumBytes
//     // satisfied, moving to next sub-array as needed.

//     // TODO: probably also need a temporary byte array for this.

//     DstIdx = 0;
//     SrcIdx_0 = 0;
//     SrcIdx_1 = 0;
//     while (NumBytes > 0)
//     {
//         Dst.X[DstIdx++] = Src[SrcIdx_0].X[SrcIdx_1];
//         --NumBytes;
//     }
// }
