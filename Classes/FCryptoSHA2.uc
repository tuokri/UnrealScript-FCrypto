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
// var const array<QWORD> K_BIG; // TODO

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

    // TODO: QWORDs needed?
    // K_BIG={(
    //     0x428A2F98D728AE22, 0x7137449123EF65CD,
    //     0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    //     0x3956C25BF348B538, 0x59F111F1B605D019,
    //     0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    //     0xD807AA98A3030242, 0x12835B0145706FBE,
    //     0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    //     0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
    //     0x9BDC06A725C71235, 0xC19BF174CF692694,
    //     0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    //     0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    //     0x2DE92C6F592B0275, 0x4A7484AA6EA6E483,
    //     0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    //     0x983E5152EE66DFAB, 0xA831C66D2DB43210,
    //     0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    //     0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    //     0x06CA6351E003826F, 0x142929670A0E6E70,
    //     0x27B70A8546D22FFC, 0x2E1B21385C26C926,
    //     0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    //     0x650A73548BAF63DE, 0x766A0ABB3C77B2A8,
    //     0x81C2C92E47EDAEE6, 0x92722C851482353B,
    //     0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    //     0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    //     0xD192E819D6EF5218, 0xD69906245565A910,
    //     0xF40E35855771202A, 0x106AA07032BBD1B8,
    //     0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
    //     0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    //     0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    //     0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    //     0x748F82EE5DEFB2FC, 0x78A5636F43172F60,
    //     0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    //     0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9,
    //     0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    //     0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    //     0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    //     0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
    //     0x113F9804BEF90DAE, 0x1B710B35131C471B,
    //     0x28DB77F523047D84, 0x32CAAB7B40C72493,
    //     0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    //     0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    //     0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
    // )}
}
