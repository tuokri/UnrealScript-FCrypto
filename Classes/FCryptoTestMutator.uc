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
 * with mod commandlets not being found by VNGame.exe. This library was
 * developed against Rising Storm 2: Vietnam. Commandlets may work for
 * other UE3/UDK builds/games.
 *
 * Run the tests with: Game.exe Level?mutator=FCrypto.FCryptoTestMutator [arguments]
 * E.g.:
 * VNGame.exe VNTE-Cuchi?mutator=FCrypto.FCryptoTestMutator -log -useunpublished -nostartupmovies
 */
class FCryptoTestMutator extends Mutator
    config(Mutator_FCryptoTest);

var(FCryptoTests) editconst const array<int> Ints_257871904;
var(FCryptoTests) editconst const array<int> Ints_683384335291162482276352519;

var(FCryptoTests) editconst const array<byte> Bytes_257871904;
var(FCryptoTests) editconst const array<byte> Bytes_683384335291162482276352519;

// Run tests with a delay to allow the game to finish loading etc.
// Overwrite with launch option ?TestDelay=FLOAT_VALUE.
var(FCryptoTests) editconst float TestDelay;
// Number of times to repeat all test suites in a loop.
// Overwrite with launch option ?NumTestLoops=INT_VALUE.
var(FCryptoTests) editconst int NumTestLoops;

var(FCryptoTests) editconst float GlobalStartTime;
var(FCryptoTests) editconst float GlobalStopTime;
var(FCryptoTests) editconst float GlobalClock;

// Workaround for UScript not supporting nested arrays.
struct PrimeWrapper
{
    var array<byte> P;
};

// Pre-generated "random" primes with GMP (see BearSSL test_math.c rand_prime()).
var(FCryptoTests) editconst const array<PrimeWrapper> Primes;
// Current index to `Primes` array.
var(FCryptoTests) editconst int PrimeIndex;

function InitMutator(string Options, out string ErrorMessage)
{
    local string TestDelayOption;
    local string NumTestLoopsOption;

    TestDelayOption = class'GameInfo'.static.ParseOption(Options, "TestDelay");
    if (TestDelayOption != "")
    {
        TestDelay = float(TestDelayOption);
        `fclog("Using TestDelay:" @ TestDelay);
    }

    NumTestLoopsOption = class'GameInfo'.static.ParseOption(Options, "NumTestLoops");
    if (NumTestLoopsOption != "")
    {
        NumTestLoops = Max(1, Abs(int(NumTestLoopsOption)));
        `fclog("Using NumTestLoops:" @ NumTestLoops);
    }

    super.InitMutator(Options, ErrorMessage);
}

simulated event PostBeginPlay()
{
    super.PostBeginPlay();
    SetTimer(TestDelay, False, nameof(RunTests));
}

private delegate int TestSuite();

private final simulated function RunTest(
    delegate<TestSuite> TestSuiteDelegate,
    name TestSuiteName,
    int Iteration
)
{
    local float ClockTime;
    local float StartTime;
    local float StopTime;
    local int Failures;

    `fclog("--- RUNNING" @ TestSuiteName @ "(" $ Iteration $ ")" @ "---");

    // StartTime = WorldInfo.RealTimeSeconds;
    ClockTime = 0;
    Clock(ClockTime);

    Failures = TestSuiteDelegate();

    // StopTime = WorldInfo.RealTimeSeconds;
    UnClock(ClockTime);
    `fclog("Clock time :" @ ClockTime * 1000);
    // `fclog("Time       :" @ StopTime - StartTime);

    if (Failures > 0)
    {
        `fcerror("---" @ Failures @ "FAILED CHECKS ---");
        `warn("---" @ TestSuiteName @ "TEST SUITE FAILED ---");
    }
    else
    {
        `fclog("--- ALL" @ TestSuiteName @ "TESTS PASSED SUCCESSFULLY ---");
    }
}

private final simulated function RunTests()
{
    local int I;

    // GlobalStartTime = WorldInfo.RealTimeSeconds;
    GlobalClock = 0.0;
    Clock(GlobalClock);

    for (I = 0; I < NumTestLoops; ++I)
    {
        RunTest(TestMath, nameof(TestMath), I);
    }

    UnClock(GlobalClock);
    // GlobalStopTime = WorldInfo.RealTimeSeconds;

    // `fclog("--- TOTAL TIME       :" @ GlobalStopTime - GlobalStartTime @ "---");
    `fclog("--- TOTAL CLOCK TIME :" @ GlobalClock @ "---");
}

private final simulated function int StringsShouldBeEqual(string S1, string S2)
{
    if (S1 != S2)
    {
        `fcerror("[" $ S1 $ "]" @ "DOES NOT MATCH" @ "[" $ S2 $ "]");
        return 1;
    }
    return 0;
}

private final simulated function int BytesShouldBeEqual(
    const out array<byte> B1,
    const out array<byte> B2
)
{
    // TODO: check test_match.c check_eqz().
    return 0;
}

private final simulated function LogBytes(const out array<byte> X)
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

private final simulated function GetPrime(
    out array<byte> Dst
)
{
    Dst = Primes[PrimeIndex].P;
    PrimeIndex = PrimeIndex % Primes.Length;
}

// Similar to GMP's mpz_urandomm.
// Generate a random integer in the range 0 to N-1, inclusive.
private final simulated function RandomBigInt(
    out array<byte> Dst,
    const out array<byte> N
)
{
    // TODO.
}

private final simulated function int TestMath()
{
    local array<int> X;
    local array<byte> P;
    local array<byte> A;
    local array<byte> B;
    local array<byte> V;
    local array<byte> XEncoded;
    local int XLen;
    local int Failures;
    local int K;
    local int I;
    local int Ctl;
    local int MP0I;
    local string BigIntString;

    class'BigInt'.static.Decode(
        X,
        Bytes_257871904,
        Bytes_257871904.Length
    );
    BigIntString = class'BigInt'.static.ToString(X);
    // `fclog("257871904                   BigInt :" @ BigIntString);
    //     1EBD     5020 (1, 13) (BearSSL)
    // 00001EBD 00005020 (1, 13) (UScript)
    Failures += StringsShouldBeEqual(
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
    // `fclog("683384335291162482276352519 BigInt :" @ BigIntString);
    //     46A9     0430     62D7     1A7A     5DB9     4207 (5, 15) (BearSSL)
    // 000046A9 00000430 000062D7 00001A7A 00005DB9 00004207 (5, 15) (UScript)
    Failures += StringsShouldBeEqual(
        BigIntString,
        "000046A9 00000430 000062D7 00001A7A 00005DB9 00004207 (5, 15)"
    );
    XLen = ((X[0] + 15) & ~15) >>> 2;
    class'BigInt'.static.Encode(XEncoded, XLen, X);
    // LogBytes(XEncoded);
    //                                     02 35 48 43 0C 5A E6 9E AE DC C2 07
    // 00 00 00 00 00 00 00 00 00 00 00 00 02 35 48 43 0C 5A E6 9E AE DC C2 07
    Failures += BytesShouldBeEqual(Bytes_683384335291162482276352519, XEncoded);
    X.Length = 0;

    for (K = 2; K <= 128; ++K)
    {
        for (I = 0; I < 10; ++I)
        {
            GetPrime(P);
            RandomBigInt(A, P);
            RandomBigInt(B, P);

            // TODO: just pre-generate these?
            // RandomBigInt(V, K + 60); // mpz_rrandomb
        }
    }

    return Failures;
}

DefaultProperties
{
    PrimeIndex=0
    TestDelay=5.0
    GlobalClock=0.0

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

    Primes(0)=(P=(0))
}
