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
 * AES implementation mirroring BearSSL's aes_ct.c
 */
class FCryptoAES extends Object
    notplaceable
    abstract;

`include(FCrypto\Classes\FCryptoAESMacros.uci);

var const array<byte> RCon;

static final function AesCtBitSliceSBox(out array<int> Q)
{
    /*
     * This S-box implementation is a straightforward translation of
     * the circuit described by Boyar and Peralta in "A new
     * combinational logic minimization technique with applications
     * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
     *
     * Note that variables x* (input) and s* (output) are numbered
     * in "reverse" order (x0 is the high bit, x7 is the low bit).
     */

    local int X0;
    local int X1;
    local int X2;
    local int X3;
    local int X4;
    local int X5;
    local int X6;
    local int X7;
    local int Y1;
    local int Y2;
    local int Y3;
    local int Y4;
    local int Y5;
    local int Y6;
    local int Y7;
    local int Y8;
    local int Y9;
    local int Y10;
    local int Y11;
    local int Y12;
    local int Y13;
    local int Y14;
    local int Y15;
    local int Y16;
    local int Y17;
    local int Y18;
    local int Y19;
    local int Y20;
    local int Y21;
    local int Z0;
    local int Z1;
    local int Z2;
    local int Z3;
    local int Z4;
    local int Z5;
    local int Z6;
    local int Z7;
    local int Z8;
    local int Z9;
    local int Z10;
    local int Z11;
    local int Z12;
    local int Z13;
    local int Z14;
    local int Z15;
    local int Z16;
    local int Z17;
    local int T0;
    local int T1;
    local int T2;
    local int T3;
    local int T4;
    local int T5;
    local int T6;
    local int T7;
    local int T8;
    local int T9;
    local int T10;
    local int T11;
    local int T12;
    local int T13;
    local int T14;
    local int T15;
    local int T16;
    local int T17;
    local int T18;
    local int T19;
    local int T20;
    local int T21;
    local int T22;
    local int T23;
    local int T24;
    local int T25;
    local int T26;
    local int T27;
    local int T28;
    local int T29;
    local int T30;
    local int T31;
    local int T32;
    local int T33;
    local int T34;
    local int T35;
    local int T36;
    local int T37;
    local int T38;
    local int T39;
    local int T40;
    local int T41;
    local int T42;
    local int T43;
    local int T44;
    local int T45;
    local int T46;
    local int T47;
    local int T48;
    local int T49;
    local int T50;
    local int T51;
    local int T52;
    local int T53;
    local int T54;
    local int T55;
    local int T56;
    local int T57;
    local int T58;
    local int T59;
    local int T60;
    local int T61;
    local int T62;
    local int T63;
    local int T64;
    local int T65;
    local int T66;
    local int T67;
    local int S0;
    local int S1;
    local int S2;
    local int S3;
    local int S4;
    local int S5;
    local int S6;
    local int S7;

    X0 = Q[7];
    X1 = Q[6];
    X2 = Q[5];
    X3 = Q[4];
    X4 = Q[3];
    X5 = Q[2];
    X6 = Q[1];
    X7 = Q[0];

    /*
     * Top linear transformation.
     */
    Y14 = X3 ^ X5;
    Y13 = X0 ^ X6;
    Y9 = X0 ^ X3;
    Y8 = X0 ^ X5;
    T0 = X1 ^ X2;
    Y1 = T0 ^ X7;
    Y4 = Y1 ^ X3;
    Y12 = Y13 ^ Y14;
    Y2 = Y1 ^ X0;
    Y5 = Y1 ^ X6;
    Y3 = Y5 ^ Y8;
    T1 = X4 ^ Y12;
    Y15 = T1 ^ X5;
    Y20 = T1 ^ X1;
    Y6 = Y15 ^ X7;
    Y10 = Y15 ^ T0;
    Y11 = Y20 ^ Y9;
    Y7 = X7 ^ Y11;
    Y17 = Y10 ^ Y11;
    Y19 = Y10 ^ Y8;
    Y16 = T0 ^ Y11;
    Y21 = Y13 ^ Y16;
    Y18 = X0 ^ Y16;

    /*
     * Non-linear section.
     */
    T2 = Y12 & Y15;
    T3 = Y3 & Y6;
    T4 = T3 ^ T2;
    T5 = Y4 & X7;
    T6 = T5 ^ T2;
    T7 = Y13 & Y16;
    T8 = Y5 & Y1;
    T9 = T8 ^ T7;
    T10 = Y2 & Y7;
    T11 = T10 ^ T7;
    T12 = Y9 & Y11;
    T13 = Y14 & Y17;
    T14 = T13 ^ T12;
    T15 = Y8 & Y10;
    T16 = T15 ^ T12;
    T17 = T4 ^ T14;
    T18 = T6 ^ T16;
    T19 = T9 ^ T14;
    T20 = T11 ^ T16;
    T21 = T17 ^ Y20;
    T22 = T18 ^ Y19;
    T23 = T19 ^ Y21;
    T24 = T20 ^ Y18;

    T25 = T21 ^ T22;
    T26 = T21 & T23;
    T27 = T24 ^ T26;
    T28 = T25 & T27;
    T29 = T28 ^ T22;
    T30 = T23 ^ T24;
    T31 = T22 ^ T26;
    T32 = T31 & T30;
    T33 = T32 ^ T24;
    T34 = T23 ^ T33;
    T35 = T27 ^ T33;
    T36 = T24 & T35;
    T37 = T36 ^ T34;
    T38 = T27 ^ T36;
    T39 = T29 & T38;
    T40 = T25 ^ T39;

    T41 = T40 ^ T37;
    T42 = T29 ^ T33;
    T43 = T29 ^ T40;
    T44 = T33 ^ T37;
    T45 = T42 ^ T41;
    Z0 = T44 & Y15;
    Z1 = T37 & Y6;
    Z2 = T33 & X7;
    Z3 = T43 & Y16;
    Z4 = T40 & Y1;
    Z5 = T29 & Y7;
    Z6 = T42 & Y11;
    Z7 = T45 & Y17;
    Z8 = T41 & Y10;
    Z9 = T44 & Y12;
    Z10 = T37 & Y3;
    Z11 = T33 & Y4;
    Z12 = T43 & Y13;
    Z13 = T40 & Y5;
    Z14 = T29 & Y2;
    Z15 = T42 & Y9;
    Z16 = T45 & Y14;
    Z17 = T41 & Y8;

    /*
     * Bottom linear transformation.
     */
    T46 = Z15 ^ Z16;
    T47 = Z10 ^ Z11;
    T48 = Z5 ^ Z13;
    T49 = Z9 ^ Z10;
    T50 = Z2 ^ Z12;
    T51 = Z2 ^ Z5;
    T52 = Z7 ^ Z8;
    T53 = Z0 ^ Z3;
    T54 = Z6 ^ Z7;
    T55 = Z16 ^ Z17;
    T56 = Z12 ^ T48;
    T57 = T50 ^ T53;
    T58 = Z4 ^ T46;
    T59 = Z3 ^ T54;
    T60 = T46 ^ T57;
    T61 = Z14 ^ T57;
    T62 = T52 ^ T58;
    T63 = T49 ^ T58;
    T64 = Z4 ^ T59;
    T65 = T61 ^ T62;
    T66 = Z1 ^ T63;
    S0 = T59 ^ T63;
    S6 = T56 ^ ~T62;
    S7 = T48 ^ ~T60;
    T67 = T64 ^ T65;
    S3 = T53 ^ T66;
    S4 = T51 ^ T66;
    S5 = T47 ^ T65;
    S1 = T64 ^ ~S3;
    S2 = T55 ^ ~T67;

    Q[7] = S0;
    Q[6] = S1;
    Q[5] = S2;
    Q[4] = S3;
    Q[3] = S4;
    Q[2] = S5;
    Q[1] = S6;
    Q[0] = S7;
}

static final function AesCtOrtho(
    out array<int> Q,
    optional int Offset = 0
)
{
    local int A;
    local int B;

    `SWAP2(Q[Offset + 0], Q[Offset + 1]);
    `SWAP2(Q[Offset + 2], Q[Offset + 3]);
    `SWAP2(Q[Offset + 4], Q[Offset + 5]);
    `SWAP2(Q[Offset + 6], Q[Offset + 7]);

    `SWAP4(Q[Offset + 0], Q[Offset + 2]);
    `SWAP4(Q[Offset + 1], Q[Offset + 3]);
    `SWAP4(Q[Offset + 4], Q[Offset + 6]);
    `SWAP4(Q[Offset + 5], Q[Offset + 7]);

    `SWAP8(Q[Offset + 0], Q[Offset + 4]);
    `SWAP8(Q[Offset + 1], Q[Offset + 5]);
    `SWAP8(Q[Offset + 2], Q[Offset + 6]);
    `SWAP8(Q[Offset + 3], Q[Offset + 7]);
}

static final function int SubWord(int X)
{
    local array<int> Q;
    // local int I;

    Q.Length = 8;
    // for (I = 0; I < 8; ++I)
    // {
    //     Q[I] = X;
    // }
    Q[0] = X;
    Q[1] = X;
    Q[2] = X;
    Q[3] = X;
    Q[4] = X;
    Q[5] = X;
    Q[6] = X;
    Q[7] = X;

    AesCtOrtho(Q);
    AesCtBitSliceSBox(Q);
    AesCtOrtho(Q);
    return Q[0];
}

static final function int AesCtKeySched(
    out array<int> CompSKey,
    const out array<byte> Key,
    int KeyLen
)
{
    local int NumRounds;
    local int I;
    local int J;
    local int K;
    local int Nk;
    local int Nkf;
    local int Tmp;
    local array<int> SKey;

    SKey.Length = 120;

    switch (KeyLen)
    {
        case 16:
            NumRounds = 10;
            break;
        case 24:
            NumRounds = 12;
            break;
        case 32:
            NumRounds = 14;
            break;
        default:
            // TODO: log error?
            return 0;
    }

    Nk = KeyLen >>> 2;
    Nkf = (NumRounds + 1) << 2;
    Tmp = 0;
    for (I = 0; I < Nk; ++I)
    {
        Tmp = class'FCryptoEncDec'.static.Dec32LE(Key, I << 2);
        SKey[(I << 1)    ] = Tmp;
        SKey[(I << 1) + 1] = Tmp;
    }
    J = 0;
    K = 0;
    for (I = Nk; I < Nkf; ++I)
    {
        if (J == 0)
        {
            Tmp = (Tmp << 24) | (Tmp >>> 8);
            Tmp = SubWord(Tmp) ^ default.RCon[K];
        }
        else if (Nk > 6 && J == 4)
        {
            Tmp = SubWord(Tmp);
        }
        Tmp = Tmp ^ (SKey[(I - Nk) << 1]);
        SKey[(I << 1)    ] = Tmp;
        SKey[(I << 1) + 1] = Tmp;
        if (++J == Nk)
        {
            J = 0;
            ++K;
        }
    }
    for (I = 0; I < Nkf; I += 4)
    {
        AesCtOrtho(SKey, I << 1);
    }
    J = 0;
    for (I = 0; I < Nkf; ++I)
    {
        CompSKey[I] = (SKey[J] & 0x55555555) | (SKey[J + 1] & 0xAAAAAAAA);
        J += 2;
    }
    return NumRounds;
}

static final function AesCtSKeyExpand(
    out array<int> SKey,
    int NumRounds,
    const out array<int> CompSKey
)
{
    local int U;
    local int V;
    local int N;
    local int X;
    local int Y;

    N = (NumRounds + 1) << 2;
    V = 0;
    for (U = 0; U < N; ++U)
    {
        X = CompSKey[U];
        Y = CompSKey[U];
        X = X & 0x55555555;
        SKey[V    ] = X | (X << 1);
        Y = Y & 0xAAAAAAAA;
        SKey[V + 1] = Y | (Y >>> 1);
        V += 2;
    }
}

static final function AesCtBitSliceInvSBox(out array<int> Q)
{
    /*
    * AES S-box is:
    *   S(x) = A(I(x)) ^ 0x63
    * where I() is inversion in GF(256), and A() is a linear
    * transform (0 is formally defined to be its own inverse).
    * Since inversion is an involution, the inverse S-box can be
    * computed from the S-box as:
    *   iS(x) = B(S(B(x ^ 0x63)) ^ 0x63)
    * where B() is the inverse of A(). Indeed, for any y in GF(256):
    *   iS(S(y)) = B(A(I(B(A(I(y)) ^ 0x63 ^ 0x63))) ^ 0x63 ^ 0x63) = y
    *
    * Note: we reuse the implementation of the forward S-box,
    * instead of duplicating it here, so that total code size is
    * lower. By merging the B() transforms into the S-box circuit
    * we could make faster CBC decryption, but CBC decryption is
    * already quite faster than CBC encryption because we can
    * process two blocks in parallel.
    */

    local int Q0;
    local int Q1;
    local int Q2;
    local int Q3;
    local int Q4;
    local int Q5;
    local int Q6;
    local int Q7;

    Q0 = ~Q[0];
    Q1 = ~Q[1];
    Q2 = Q[2];
    Q3 = Q[3];
    Q4 = Q[4];
    Q5 = ~Q[5];
    Q6 = ~Q[6];
    Q7 = Q[7];
    Q[7] = Q1 ^ Q4 ^ Q6;
    Q[6] = Q0 ^ Q3 ^ Q5;
    Q[5] = Q7 ^ Q2 ^ Q4;
    Q[4] = Q6 ^ Q1 ^ Q3;
    Q[3] = Q5 ^ Q0 ^ Q2;
    Q[2] = Q4 ^ Q7 ^ Q1;
    Q[1] = Q3 ^ Q6 ^ Q0;
    Q[0] = Q2 ^ Q5 ^ Q7;

    AesCtBitSliceSBox(Q);

    Q0 = ~Q[0];
    Q1 = ~Q[1];
    Q2 = Q[2];
    Q3 = Q[3];
    Q4 = Q[4];
    Q5 = ~Q[5];
    Q6 = ~Q[6];
    Q7 = Q[7];
    Q[7] = Q1 ^ Q4 ^ Q6;
    Q[6] = Q0 ^ Q3 ^ Q5;
    Q[5] = Q7 ^ Q2 ^ Q4;
    Q[4] = Q6 ^ Q1 ^ Q3;
    Q[3] = Q5 ^ Q0 ^ Q2;
    Q[2] = Q4 ^ Q7 ^ Q1;
    Q[1] = Q3 ^ Q6 ^ Q0;
    Q[0] = Q2 ^ Q5 ^ Q7;
}

// TODO: can be made a macro for performance?
static final function AddRoundKey(
    out array<int> Q,
    const out array<int> SK,
    optional int Offset = 0
)
{
    // local int I;

    // for (I = 0; I < 8; ++I)
    // {
    //     Q[I] = Q[I] ^ SK[I];
    // }

    // TODO: need to benchmark whether a temp var here is better.

    Q[Offset + 0] = Q[Offset + 0] ^ SK[Offset + 0];
    Q[Offset + 1] = Q[Offset + 1] ^ SK[Offset + 1];
    Q[Offset + 2] = Q[Offset + 2] ^ SK[Offset + 2];
    Q[Offset + 3] = Q[Offset + 3] ^ SK[Offset + 3];
    Q[Offset + 4] = Q[Offset + 4] ^ SK[Offset + 4];
    Q[Offset + 5] = Q[Offset + 5] ^ SK[Offset + 5];
    Q[Offset + 6] = Q[Offset + 6] ^ SK[Offset + 6];
    Q[Offset + 7] = Q[Offset + 7] ^ SK[Offset + 7];
}

// TODO: can be made a macro for performance?
static final function InvShiftRows(out array<int> Q)
{
    local int X;

    // for (i = 0; i < 8; i ++) unrolled.

    X = Q[0];
    Q[0] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[1];
    Q[1] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[2];
    Q[2] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[3];
    Q[3] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[4];
    Q[4] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[5];
    Q[5] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[6];
    Q[6] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
    X = Q[7];
    Q[7] = (X & 0x000000FF)
        | ((X & 0x00003F00) << 2) | ((X & 0x0000C000) >>> 6)
        | ((X & 0x000F0000) << 4) | ((X & 0x00F00000) >>> 4)
        | ((X & 0x03000000) << 6) | ((X & 0xFC000000) >>> 2);
}

// static final function int RotR16(int X)
// {
//     return (X << 16) | (X >>> 16);
// }
`define ROTR16(X) (((`X << 16) | (`X >>> 16)))

static final function InvMixColumns(out array<int> Q)
{
    local int Q0;
    local int Q1;
    local int Q2;
    local int Q3;
    local int Q4;
    local int Q5;
    local int Q6;
    local int Q7;
    local int R0;
    local int R1;
    local int R2;
    local int R3;
    local int R4;
    local int R5;
    local int R6;
    local int R7;

    Q0 = Q[0];
    Q1 = Q[1];
    Q2 = Q[2];
    Q3 = Q[3];
    Q4 = Q[4];
    Q5 = Q[5];
    Q6 = Q[6];
    Q7 = Q[7];
    R0 = (Q0 >> 8) | (Q0 << 24);
    R1 = (Q1 >> 8) | (Q1 << 24);
    R2 = (Q2 >> 8) | (Q2 << 24);
    R3 = (Q3 >> 8) | (Q3 << 24);
    R4 = (Q4 >> 8) | (Q4 << 24);
    R5 = (Q5 >> 8) | (Q5 << 24);
    R6 = (Q6 >> 8) | (Q6 << 24);
    R7 = (Q7 >> 8) | (Q7 << 24);

    Q[0] = Q5 ^ Q6 ^ Q7 ^ R0 ^ R5 ^ R7 ^ `ROTR16(Q0 ^ Q5 ^ Q6 ^ R0 ^ R5);
    Q[1] = Q0 ^ Q5 ^ R0 ^ R1 ^ R5 ^ R6 ^ R7 ^ `ROTR16(Q1 ^ Q5 ^ Q7 ^ R1 ^ R5 ^ R6);
    Q[2] = Q0 ^ Q1 ^ Q6 ^ R1 ^ R2 ^ R6 ^ R7 ^ `ROTR16(Q0 ^ Q2 ^ Q6 ^ R2 ^ R6 ^ R7);
    Q[3] = Q0 ^ Q1 ^ Q2 ^ Q5 ^ Q6 ^ R0 ^ R2 ^ R3 ^ R5 ^ `ROTR16(Q0 ^ Q1 ^ Q3 ^ Q5 ^ Q6 ^ Q7 ^ R0 ^ R3 ^ R5 ^ R7);
    Q[4] = Q1 ^ Q2 ^ Q3 ^ Q5 ^ R1 ^ R3 ^ R4 ^ R5 ^ R6 ^ R7 ^ `ROTR16(Q1 ^ Q2 ^ Q4 ^ Q5 ^ Q7 ^ R1 ^ R4 ^ R5 ^ R6);
    Q[5] = Q2 ^ Q3 ^ Q4 ^ Q6 ^ R2 ^ R4 ^ R5 ^ R6 ^ R7 ^ `ROTR16(Q2 ^ Q3 ^ Q5 ^ Q6 ^ R2 ^ R5 ^ R6 ^ R7);
    Q[6] = Q3 ^ Q4 ^ Q5 ^ Q7 ^ R3 ^ R5 ^ R6 ^ R7 ^ `ROTR16(Q3 ^ Q4 ^ Q6 ^ Q7 ^ R3 ^ R6 ^ R7);
    Q[7] = Q4 ^ Q5 ^ Q6 ^ R4 ^ R6 ^ R7 ^ `ROTR16(Q4 ^ Q5 ^ Q7 ^ R4 ^ R7);
}

static final function AesCtBitSliceDecrypt(
    int NumRounds,
    const out array<int> SKey,
    out array<int> Q
)
{
    local int U;

    AddRoundKey(Q, SKey, NumRounds << 3);
    for (U = NumRounds - 1; U > 0; --U)
    {
        InvShiftRows(Q);
        AesCtBitSliceInvSBox(Q);
        AddRoundKey(Q, SKey, U << 3);
        InvMixColumns(Q);
    }
    InvShiftRows(Q);
    AesCtBitSliceInvSBox(Q);
    AddRoundKey(Q, SKey);
}

DefaultProperties
{
    //    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    RCon=(1,    2,    4,    8,    16,   32,   64,   128,  27,   54)
}
