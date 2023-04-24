/*
 * Copyright (c) 2023 Tuomo Kriikkula <tuokri@tuta.io>
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
 * Utility mutator for running tests. Used to work around the issue
 * with mod commandlets not being found by VNGame.exe.
 */
class FCryptoTestMutator extends ROMutator
    config(Mutator_FCryptoTest);

var(FCryptoTests) editconst const array<int> Ints_257871904;
var(FCryptoTests) editconst const array<int> Ints_683384335291162482276352519;

var(FCryptoTests) editconst const array<byte> Bytes_257871904;
var(FCryptoTests) editconst const array<byte> Bytes_683384335291162482276352519;

simulated event PostBeginPlay()
{
    super.PostBeginPlay();

    TestMath();
}

final simulated function int StringsShouldEqual(string S1, string S2)
{
    if (S1 != S2)
    {
        `fcerror("[" $ S1 $ "]" @ "DOES NOT MATCH" @ "[" $ S2 $ "]");
        return 1;
    }
    return 0;
}

final simulated function int BytesShouldEqual(
    const out array<byte> B1,
    const out array<byte> B2
)
{
    // TODO: check test_match.c check_eqz().
    return 0;
}

final simulated function LogBytes(const out array<byte> X)
{
    local int I;
    local string Str;

    Str = "";
    for (I = 0; I < X.Length; ++I)
    {
        Str $= Right(ToHex(X[I]), 2);
        if (I < X.Length - 1)
        {
            Str @= "";
        }
    }
    `fclog(Str);
}

simulated function TestMath()
{
    local float ClockTime;
    local float StartTime;
    local float StopTime;
    local array<int> X;
    local array<byte> XEncoded;
    local int XLen;
    local string BigIntString;
    local int Failures;

    StartTime = WorldInfo.RealTimeSeconds;
    Clock(ClockTime);

    class'BigInt'.static.Decode(
        X,
        Bytes_257871904,
        Bytes_257871904.Length
    );
    BigIntString = class'BigInt'.static.ToString(X);
    `fclog("257871904                   BigInt :" @ BigIntString);
    // 00001EBD 00005020 (1, 13)
    // 1EBD 5020 (1, 13)
    Failures += StringsShouldEqual(
        BigIntString,
        "00001EBD 00005020 (1, 13)"
    );
    X.Length = 0;

    class'BigInt'.static.Decode(
        X,
        Bytes_683384335291162482276352519,
        Bytes_683384335291162482276352519.Length
    );
    BigIntString = class'BigInt'.static.ToString(X);
    `fclog("683384335291162482276352519 BigInt :" @ BigIntString);
    // 46A9 0430 62D7 1A7A 5DB9 4207 (5, 15)
    // 000046A9 00000430 000062D7 00001A7A 00005DB9 00004207 (5, 15)
    Failures += StringsShouldEqual(
        BigIntString,
        "000046A9 00000430 000062D7 00001A7A 00005DB9 00004207 (5, 15)"
    );
    XLen = ((X[0] + 15) & ~15) >>> 2;
    class'BigInt'.static.Encode(XEncoded, XLen, X);
    LogBytes(XEncoded);
    Failures += BytesShouldEqual(Bytes_683384335291162482276352519, XEncoded);
    X.Length = 0;
    //                                     02 35 48 43 0C 5A E6 9E AE DC C2 07
    // 00 00 00 00 00 00 00 00 00 00 00 00 02 35 48 43 0C 5A E6 9E AE DC C2 07

    StopTime = WorldInfo.RealTimeSeconds;
    UnClock(ClockTime);
    `fclog("Clock time :" @ ClockTime);
    `fclog("Time       :" @ StopTime - StartTime);

    if (Failures > 0)
    {
        `fcerror("---" @ Failures @ "FAILED CHECKS ---");
        `warn("---" @ nameof(TestMath) @ "TEST SUITE FAILED ---");
    }
    else
    {
        `fclog("--- ALL" @ nameof(TestMath) @ "TESTS PASSED SUCCESSFULLY ---");
    }
}

DefaultProperties
{
    // mpz_t LE export format.
    Ints_257871904(0)=0x0F5E
    Ints_257871904(1)=0xD020
    Bytes_257871904(0)=15  // 0x0F
    Bytes_257871904(1)=94  // 0x5E
    Bytes_257871904(2)=208 // 0xD0
    Bytes_257871904(3)=32  // 0x20

    Ints_683384335291162482276352519(0)=0x0235
    Ints_683384335291162482276352519(1)=0x4843
    Ints_683384335291162482276352519(2)=0x0C5A
    Ints_683384335291162482276352519(3)=0xE69E
    Ints_683384335291162482276352519(4)=0xAEDC
    Ints_683384335291162482276352519(5)=0xC207
    Bytes_683384335291162482276352519( 0)=2   // 0x02
    Bytes_683384335291162482276352519( 1)=53  // 0x35
    Bytes_683384335291162482276352519( 2)=72  // 0x48
    Bytes_683384335291162482276352519( 3)=67  // 0x43
    Bytes_683384335291162482276352519( 4)=12  // 0x0C
    Bytes_683384335291162482276352519( 5)=90  // 0x5A
    Bytes_683384335291162482276352519( 6)=230 // 0xE6
    Bytes_683384335291162482276352519( 7)=158 // 0x9E
    Bytes_683384335291162482276352519( 8)=174 // 0xAE
    Bytes_683384335291162482276352519( 9)=220 // 0xDC
    Bytes_683384335291162482276352519(10)=194 // 0xC2
    Bytes_683384335291162482276352519(11)=7   // 0x07
}
