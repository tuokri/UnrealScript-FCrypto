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

`define MEMMOVE_IMPL_STATIC_DST_64                      \
    local int ByteIndex;                                \
    local int I;                                        \
    local byte DstBytes[64];                            \
                                                        \
    ByteIndex = 0;                                      \
    I = SrcOffset;                                      \
                                                        \
    while (ByteIndex < NumBytes)                        \
    {                                                   \
        DstBytes[ByteIndex++] = Src[I++];               \
    }                                                   \
                                                        \
    ByteIndex = DstOffset;                              \
    for (I = 0; I < NumBytes; ++I)                      \
    {                                                   \
        Dst[ByteIndex++] = DstBytes[I];                 \
    }                                                   \

static final function MemMove_SBytes_SBytes_64(
    out byte Dst[64],
    const out byte Src[64],
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    `MEMMOVE_IMPL_STATIC_DST_64
}

static final function MemMove_SBytes_DBytes_64(
    out byte Dst[64],
    const out array<byte> Src,
    int NumBytes,
    optional int DstOffset = 0,
    optional int SrcOffset = 0
)
{
    `MEMMOVE_IMPL_STATIC_DST_64
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
