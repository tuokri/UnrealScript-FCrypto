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
`include(FCrypto\Classes\FCryptoSHA2Constants.uci);

var const array<int> SHA224_IV;
var const array<int> SHA256_IV;
var const array<int> K_SMALL;
var const array<FCQWORD> K_BIG;

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
    local int W[64];

    RangeDec32BE_Static64(W, 16, Buf);

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
        class'FCryptoMemory'.static.MemSet_SBytes64(Buf, 0, 64 - Ptr, Ptr);
        Sha2SmallRound_SBuf64_SVal8(Buf, Val);
        class'FCryptoMemory'.static.MemSet_SBytes64(Buf, 0, 56);
    }
    else
    {
        class'FCryptoMemory'.static.MemSet_SBytes64(Buf, 0, 56 - Ptr, Ptr);
    }

    Enc64BE_Static64(Buf, Cc.Count << 3, 56); // TODO: QWORD impl?
    Sha2SmallRound_SBuf64_SVal8(Buf, Val);
    RangeEnc32BE_SVal8(Dst, Val, Num);
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

static final function RangeDec32BE_Static64(
    out int V[64],
    int Num,
    const out byte Src[64]
)
{
    local int I;
    local int SrcIdx;

    SrcIdx = 0;
    while (Num-- > 0)
    {
        V[I++] = Dec32BE_Static64(Src, SrcIdx);
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
static final function int Dec32BE_Static64(
    const out byte Src[64],
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
static final function Enc64BE_Static64(
    out byte Dst[64],
    int X, // TODO: need to use a QWORD here?
    optional int Offset = 0
)
{
    // TODO: QWORD impl here?
    // br_enc32be(buf, (uint32_t)(x >> 32));
    // br_enc32be(buf + 4, (uint32_t)x);

    Enc32BE_Static64(Dst, X, Offset);
}

// TODO: make this a macro for performance?
static final function Enc32BE(
    out array<byte> Dst,
    int X,
    optional int Offset = 0
)
{
    Dst[Offset + 0] = byte(X >>> 24);
    Dst[Offset + 1] = byte(X >>> 16);
    Dst[Offset + 2] = byte(X >>>  8);
    Dst[Offset + 3] = byte(X       );
}

static final function Enc32BE_Static64(
    out byte Dst[64],
    int X,
    optional int Offset = 0
)
{
    Dst[Offset + 0] = byte(X >>> 24);
    Dst[Offset + 1] = byte(X >>> 16);
    Dst[Offset + 2] = byte(X >>>  8);
    Dst[Offset + 3] = byte(X       );
}

static final function RangeEnc32BE_SVal8(
    out array<byte> Dst,
    const out int Val[8],
    int Num
)
{
    local int Offset;
    local int V;
    local int VIdx;

    Offset = 0;
    VIdx = 0;
    while (Num-- > 0)
    {
        V = Val[VIdx++];
        Enc32BE(Dst, V, Offset);
        Offset += 4;
    }
}

// TODO: do we need this in UScript?
static final function Sha224Init(out FCryptoSHA224Context Cc)
{
    Cc.Val[0] = default.SHA224_IV[0];
    Cc.Val[1] = default.SHA224_IV[1];
    Cc.Val[2] = default.SHA224_IV[2];
    Cc.Val[3] = default.SHA224_IV[3];
    Cc.Val[4] = default.SHA224_IV[4];
    Cc.Val[5] = default.SHA224_IV[5];
    Cc.Val[5] = default.SHA224_IV[6];
    Cc.Val[6] = default.SHA224_IV[7];
}

// TODO: what's the point of this abstraction?
static final function Sha224Update(
    out FCryptoSHA224Context Cc,
    const out array<byte> Data,
    int Len
)
{
    Sha2SmallUpdate(Cc, Data, Len);
}

static final function Sha256Update(
    out FCryptoSHA224Context Cc,
    const out array<byte> Data,
    int Len
)
{
    Sha2SmallUpdate(Cc, Data, Len);
}

DefaultProperties
{
    SHA224_IV={(
        SHA224_IV_VAL0, SHA224_IV_VAL1, SHA224_IV_VAL2, SHA224_IV_VAL3,
        SHA224_IV_VAL4, SHA224_IV_VAL5, SHA224_IV_VAL6, SHA224_IV_VAL7
    )}

    SHA256_IV={(
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )}

    K_SMALL={(
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

    K_BIG={(
        (A=0x428A2F98, B=0xD728AE22), (A=0x71374491, B=0x23EF65CD),
        (A=0xB5C0FBCF, B=0xEC4D3B2F), (A=0xE9B5DBA5, B=0x8189DBBC),
        (A=0x3956C25B, B=0xF348B538), (A=0x59F111F1, B=0xB605D019),
        (A=0x923F82A4, B=0xAF194F9B), (A=0xAB1C5ED5, B=0xDA6D8118),
        (A=0xD807AA98, B=0xA3030242), (A=0x12835B01, B=0x45706FBE),
        (A=0x243185BE, B=0x4EE4B28C), (A=0x550C7DC3, B=0xD5FFB4E2),
        (A=0x72BE5D74, B=0xF27B896F), (A=0x80DEB1FE, B=0x3B1696B1),
        (A=0x9BDC06A7, B=0x25C71235), (A=0xC19BF174, B=0xCF692694),
        (A=0xE49B69C1, B=0x9EF14AD2), (A=0xEFBE4786, B=0x384F25E3),
        (A=0x0FC19DC6, B=0x8B8CD5B5), (A=0x240CA1CC, B=0x77AC9C65),
        (A=0x2DE92C6F, B=0x592B0275), (A=0x4A7484AA, B=0x6EA6E483),
        (A=0x5CB0A9DC, B=0xBD41FBD4), (A=0x76F988DA, B=0x831153B5),
        (A=0x983E5152, B=0xEE66DFAB), (A=0xA831C66D, B=0x2DB43210),
        (A=0xB00327C8, B=0x98FB213F), (A=0xBF597FC7, B=0xBEEF0EE4),
        (A=0xC6E00BF3, B=0x3DA88FC2), (A=0xD5A79147, B=0x930AA725),
        (A=0x06CA6351, B=0xE003826F), (A=0x14292967, B=0x0A0E6E70),
        (A=0x27B70A85, B=0x46D22FFC), (A=0x2E1B2138, B=0x5C26C926),
        (A=0x4D2C6DFC, B=0x5AC42AED), (A=0x53380D13, B=0x9D95B3DF),
        (A=0x650A7354, B=0x8BAF63DE), (A=0x766A0ABB, B=0x3C77B2A8),
        (A=0x81C2C92E, B=0x47EDAEE6), (A=0x92722C85, B=0x1482353B),
        (A=0xA2BFE8A1, B=0x4CF10364), (A=0xA81A664B, B=0xBC423001),
        (A=0xC24B8B70, B=0xD0F89791), (A=0xC76C51A3, B=0x0654BE30),
        (A=0xD192E819, B=0xD6EF5218), (A=0xD6990624, B=0x5565A910),
        (A=0xF40E3585, B=0x5771202A), (A=0x106AA070, B=0x32BBD1B8),
        (A=0x19A4C116, B=0xB8D2D0C8), (A=0x1E376C08, B=0x5141AB53),
        (A=0x2748774C, B=0xDF8EEB99), (A=0x34B0BCB5, B=0xE19B48A8),
        (A=0x391C0CB3, B=0xC5C95A63), (A=0x4ED8AA4A, B=0xE3418ACB),
        (A=0x5B9CCA4F, B=0x7763E373), (A=0x682E6FF3, B=0xD6B2B8A3),
        (A=0x748F82EE, B=0x5DEFB2FC), (A=0x78A5636F, B=0x43172F60),
        (A=0x84C87814, B=0xA1F0AB72), (A=0x8CC70208, B=0x1A6439EC),
        (A=0x90BEFFFA, B=0x23631E28), (A=0xA4506CEB, B=0xDE82BDE9),
        (A=0xBEF9A3F7, B=0xB2C67915), (A=0xC67178F2, B=0xE372532B),
        (A=0xCA273ECE, B=0xEA26619C), (A=0xD186B8C7, B=0x21C0C207),
        (A=0xEADA7DD6, B=0xCDE0EB1E), (A=0xF57D4F7F, B=0xEE6ED178),
        (A=0x06F067AA, B=0x72176FBA), (A=0x0A637DC5, B=0xA2C898A6),
        (A=0x113F9804, B=0xBEF90DAE), (A=0x1B710B35, B=0x131C471B),
        (A=0x28DB77F5, B=0x23047D84), (A=0x32CAAB7B, B=0x40C72493),
        (A=0x3C9EBE0A, B=0x15C9BEBC), (A=0x431D67C4, B=0x9C100D4C),
        (A=0x4CC5D4BE, B=0xCB3E42B6), (A=0x597F299C, B=0xFC657E2A),
        (A=0x5FCB6FAB, B=0x3AD6FAEC), (A=0x6C44198C, B=0x4A475817)
    )}
}
