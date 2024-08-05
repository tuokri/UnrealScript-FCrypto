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
`include(FCrypto\Classes\FCryptoSHA2Macros.uci);

var const array<int> SHA224_IV;
var const array<int> SHA256_IV;
var const array<int> K;

static final function Sha2SmallRound(
    const out array<byte> Buf,
    out array<int> Val
)
{
    local int T1;
    local int T2;
    local int A;
    local int B;
    local int C;
    local int D;
    local int E;
    local int F;
    local int G;
    local int H;
    // TODO: make this a static array? Does it make sense?
    //       If we do that, we'll also have to modify RangeDec32BE
    //       to take int a static array (and also implement multiple)
    //       variants for different array sizes.
    local array<int> W;

    W.Length = 64;

    RangeDec32BE(W, 16, Buf);

    `SHA_224_BODY();
}

// TODO: use more macros to reduce duplication between variants
//       of this function.
static final function Sha2SmallRound_SBuf64_SVal8(
    const out byte Buf[64],
    out int Val[8]
)
{
    local int T1;
    local int T2;
    local int A;
    local int B;
    local int C;
    local int D;
    local int E;
    local int F;
    local int G;
    local int H;
    // TODO: make this a static array? Does it make sense?
    //       If we do that, we'll also have to modify RangeDec32BE
    //       to take int a static array (and also implement multiple)
    //       variants for different array sizes.
    local array<int> W;

    W.Length = 64;

    // TODO: we definitely need multiple variants of this too.
    // RangeDec32BE(W, 16, Buf);

    `SHA_224_BODY();
}

static final function Sha2SmallUpdate(
    out FCryptoSHA224Context Cc,
    const out array<byte> Data,
    int Len
)
{
    local int Ptr;
    local int CLen;
    local int DataIdx;

    DataIdx = 0;

    // TODO: can we simply use 32 bit integers here?
    // TODO: if not, use QWORDs?
    Ptr = Cc.Count & 63;
    Cc.Count += Len;
    while (Len > 0)
    {
        CLen = 64 - Ptr;
        if (CLen > Len)
        {
            CLen = Len;
        }
        // TODO: move all memory functions to dedicated file.
        // TODO: use MemCpy here?
        class'FCryptoMemory'.static.MemMove_SBytes_DBytes_64(Cc.Buf, Data, CLen, Ptr, DataIdx);
        Ptr += CLen;
        DataIdx += CLen;
        Len -= CLen;

        if (Ptr == 64)
        {
            Sha2SmallRound_SBuf64_SVal8(Cc.Buf, Cc.Val);
            Ptr = 0;
        }
    }
}

static final function Sha2SmallOut(
    const out FCryptoSHA224Context Cc,
    out array<byte> Dst,
    int Num
)
{
    local byte Buf[64];
    local int Val[8];
    local int Ptr;

    Ptr = Cc.Count & 63;
    class'FCryptoMemory'.static.MemCpy_SBytes_SBytes_64(Buf, Cc.Buf, Ptr);
    class'FCryptoMemory'.static.MemCpy_SInts_SInts_8(Val, CC.Val, 32 /* sizeof Val */);
    Buf[Ptr++] = 0x80;
    if (Ptr > 56)
    {
        // class'FCryptoMemory'.static.MemSet(Buf, 0, 64 - Ptr, Ptr);
        // Sha2SmallRound(Buf, Val);
        // class'FCryptoMemory'.static.MemSet(Buf, 0, 56);
    }
    else
    {
        // class'FCryptoMemory'.static.MemSet(Buf, 0, 56 - Ptr, Ptr);
    }

    // Enc64BE(Buf /* + 56 */, Cc.Count << 3); // TODO
    // Sha2SmallRound(Buf, Val); // TODO
    // RangeEnc32BE(Dst, Val, Num); // TODO
}

// TODO: make this a macro for performance?
static final function RangeDec32BE(
    out array<int> V,
    int Num,
    const out array<byte> Src
)
{
    local int I;
    local int SrcIdx;

    SrcIdx = 0;
    while (Num-- > 0)
    {
        V[I++] = Dec32BE(Src, SrcIdx);
        SrcIdx += 4;
    }
}

// TODO: make this a macro for performance?
static final function int Dec32BE(
    const out array<byte> Src,
    optional int Idx = 0 // TODO: is this needed?
)
{
    return (
          Src[Idx + 0] << 24
        | Src[Idx + 1] << 16
        | Src[Idx + 2] << 8
        | Src[Idx + 3]
    );
}

// TODO: make this a macro for performance?
static final function Enc64BE(
    out array<byte> Dst,
    int X // TODO: need to use a QWORD here?
)
{
	// br_enc32be(buf, (uint32_t)(x >> 32));
	// br_enc32be(buf + 4, (uint32_t)x);
}

// TODO: make this a macro for performance?
static final function Enc32BE(
    out array<byte> Dst,
    int X
)
{
    Dst[0] = byte(X >>> 24);
    Dst[1] = byte(X >>> 16);
    Dst[2] = byte(X >>>  8);
    Dst[3] = byte(X       );
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
