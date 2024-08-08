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
 * Utility mutator for running tests. Used to work around the issue
 * with mod commandlets not being found by VNGame.exe. This library was
 * developed against Rising Storm 2: Vietnam. Commandlets may work for
 * other UE3/UDK builds/games.
 * TODO: UPDATE THIS TEXT BLOCK. COMMANDLETS **DO** WORK, BUT
 *       THEY ARE RAN DIFFERENTLY THAN THE DOCS STATE. USE
 *       'UDK.EXE RUN "COMMANDLETNAME"'. MUTATOR IS ALSO REQUIRED
 *       FOR TICKING ACTORS SUCH AS TCP LINK.
 *
 * Run the tests with: Game.exe Level?mutator=FCrypto.FCryptoTestMutator [arguments]
 * E.g., using Rising Storm 2 client to run the tests:
 * VNGame.exe VNTE-Cuchi?mutator=FCrypto.FCryptoTestMutator -log -useunpublished -nostartupmovies
 *
 * Using UDK server (e.g. from UDK-Lite) to run the tests:
 * UDK.exe server Entry?Mutator=FCrypto.FCryptoTestMutator?bIsLanMatch=true?dedicated=true
 *     -log -useunpublished -UNATTENDED -FORCELOGFLUSH
 */
class FCryptoTestMutator extends Mutator
    config(Mutator_FCryptoTest);

`include(FCrypto\Classes\FCryptoMacros.uci);

var private FCryptoGMPClient GMPClient;
var private FCryptoUtils Utils;

var(FCryptoTests) editconst const array<byte> Bytes_0;
var(FCryptoTests) editconst const array<byte> Bytes_257871904;
var(FCryptoTests) editconst const array<byte> Bytes_683384335291162482276352519;

var(FCryptoTests) editconst array<int> MontyMaBefore;
var(FCryptoTests) editconst array<byte> MontyMaBefore_Bytes;
var(FCryptoTests) editconst array<int> MontyMaAfter;
var(FCryptoTests) editconst array<byte> MontyMaAfter_Bytes;
var(FCryptoTests) editconst array<int> MontyMp;
var(FCryptoTests) editconst array<byte> MontyMp_Bytes;
var(FCryptoTests) editconst array<byte> MontyEa;

// Run tests with a delay to allow the game to finish loading etc.
// Overwrite with launch option ?TestDelay=FLOAT_VALUE.
var(FCryptoTests) editconst float TestDelay;
// Number of times to repeat all test suites in a loop.
// Overwrite with launch option ?NumTestLoops=INT_VALUE.
var(FCryptoTests) editconst int NumTestLoops;
// Current test iteration.
var(FCryptoTests) editconst int CurrentTestIteration;

var(FCryptoTests) bool bExitTimerSet;
var(FCryptoTests) float ExitDelaySeconds;
var(FCryptoTests) bool bTestsDone;

var(FCryptoTests) editconst float GlobalStartTime;
var(FCryptoTests) editconst float GlobalStopTime;
var(FCryptoTests) editconst float GlobalClock;

// Workaround for UScript not supporting nested arrays.
struct PrimeWrapper
{
    var array<byte> P;
};

// Pre-generated "random" primes with GMP (see BearSSL test_math.c rand_prime()).
// Data generated with DevUtils/primes.py.
var(FCryptoTests) editconst const array<PrimeWrapper> Primes;
// Current index to `Primes` array.
var(FCryptoTests) editconst int PrimeIndex;

// Generated dynamically at the beginning of each test run.
var(FCryptoTests) editconst array<PrimeWrapper> RandomPrimes;
// Current index to `RandomPrimes` array.
var(FCryptoTests) editconst int RandomPrimeIndex;

// Whether to use random or pre-generated prime array.
var(FCryptoTests) editconst bool bUseRandomPrimes;

// Total number of test failures in all tests.
var(FCryptoTests) int Failures;

struct TestDelegatePair
{
    var delegate<TestSuite> TestDelegate;
    var name TestName;
};

// Test suite functions to run in order.
var(FCryptoTests) array<TestDelegatePair> TestDelegatesToRun;
// Index to current running test in TestDelegatesToRun array.
var(FCryptoTests) int CurrentTestDelegateIndex;

var private bool bRandPrimesRequested;

var const array<byte> RepeatedBinaryRandoms;

/*
 * AES known-answer tests. Order: key, plaintext, ciphertext.
 */
var(FCryptoTests) editconst const array<string> KAT_AES;

/*
 * AES known-answer tests for CBC. Order: key, IV, plaintext, ciphertext.
 */
var(FCryptoTests) editconst const array<string> KAT_AES_CBC;

/*
 * AES known-answer tests for CTR. Order: key, IV, plaintext, ciphertext.
 */
var(FCryptoTests) editconst const array<string> KAT_AES_CTR;

// Callback to FCryptoGMPClient::RandPrime.
final simulated function AddRandomPrime(
    const out array<byte> P
)
{
    // `fclog(
    //     "Idx:" @ RandomPrimeIndex
    //     @ "Len:" @ RandomPrimes.Length
    //     @ "P:" @ BytesWordsToString(P)
    // );
    RandomPrimes.Length = RandomPrimes.Length + 1;
    RandomPrimes[RandomPrimes.Length - 1].P = P;

    if (RandomPrimes.Length % 100 == 0)
    {
        GMPClient.StopTransferRateSample();
        GMPClient.LogTransferRates();
    }
}

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

    GMPClient = Spawn(class'FCryptoGMPClient', self);
    if (GMPClient == None)
    {
        `fcerror("failed to spawn GMPClient!");
    }
    else
    {
        GMPClient.ConnectToServer();
    }

    if (TestDelay > 0)
    {
        SetTimer(TestDelay, False, NameOf(RunTests));
    }
    else
    {
        RunTests();
    }
}

simulated event PreBeginPlay()
{
    Utils = new (self) class'FCryptoUtils';

    TestDelegatesToRun.Length = 4;
    TestDelegatesToRun[0].TestDelegate = TestMemory;
    TestDelegatesToRun[0].TestName = NameOf(TestMemory);
    TestDelegatesToRun[1].TestDelegate = TestOperations;
    TestDelegatesToRun[1].TestName = NameOf(TestOperations);
    TestDelegatesToRun[2].TestDelegate = TestMath;
    TestDelegatesToRun[2].TestName = NameOf(TestMath);
    TestDelegatesToRun[3].TestDelegate = TestAesCt;
    TestDelegatesToRun[3].TestName = NameOf(TestAesCt);

    super.PreBeginPlay();
}

simulated event Tick(float DeltaTime)
{
    super.Tick(DeltaTime);

    if (GMPClient.bDone && !bExitTimerSet && bTestsDone)
    {
        `fclog("--- --- --- GMPClient done! Exiting in"
            @ ExitDelaySeconds @ "seconds. --- --- ---");

        bExitTimerSet = True;
        SetTimer(ExitDelaySeconds, False, NameOf(ExitTests));
    }
}

private final simulated function ExitTests()
{
    ConsoleCommand("QUIT", True);
}

private delegate int TestSuite();

private final simulated function RunNextTest()
{
    local delegate<TestSuite> NextTestFunction;
    local name NextTestName;

    `fclog("CurrentTestDelegateIndex=" $ CurrentTestDelegateIndex
        @ "TestDelegatesToRun.Length=" $ TestDelegatesToRun.Length);

    if (CurrentTestIteration >= NumTestLoops)
    {
        bTestsDone = True;
        GMPClient.bTestMutatorDone = True;

        UnClock(GlobalClock) ;
        GlobalStopTime = Utils.GetSystemTimeStamp();

        `fclog("--- TOTAL TIME       :" @ (GlobalStopTime - GlobalStartTime) @ "---");
        `fclog("--- TOTAL CLOCK TIME :" @ GlobalClock @ "---");

        if (Failures > 0)
        {
            `fcerror("--- ##ERROR##" @ Failures @ "TOTAL FAILED CHECKS ---");
        }

        return;
    }

    // Grab next test.
    if (CurrentTestDelegateIndex < TestDelegatesToRun.Length)
    {
        bUseRandomPrimes = bool(CurrentTestIteration % 2);
        `fclog("bUseRandomPrimes:" @ bUseRandomPrimes);

        NextTestFunction = TestDelegatesToRun[CurrentTestDelegateIndex].TestDelegate;
        NextTestName = TestDelegatesToRun[CurrentTestDelegateIndex].TestName;
        ++CurrentTestDelegateIndex;
        `fclog("NextTestFunction=" $ NextTestFunction);
        RunTest(NextTestFunction, NextTestName, CurrentTestIteration);
    }
    // Reset test delegate index and start again.
    else
    {
        CurrentTestDelegateIndex = 0;
        CurrentTestIteration += 1;
        SetTimer(0.001, False, NameOf(RunNextTest));
    }
}

private final simulated function RunTest(
    delegate<TestSuite> TestSuiteDelegate,
    name TestSuiteName,
    int Iteration
)
{
    local int TestFailures;
    local float ClockTime;
    // local float StartTime;
    // local float StopTime;

    `fclog("--- RUNNING" @ TestSuiteName @ "(" $ Iteration $ ")" @ "---");

    // StartTime = WorldInfo.RealTimeSeconds;
    ClockTime = 0;
    Clock(ClockTime);

    TestFailures = TestSuiteDelegate();

    // StopTime = WorldInfo.RealTimeSeconds;
    UnClock(ClockTime);
    `fclog("Clock time :" @ ClockTime * 1000);
    `fclog("Clock time :" @ ClockTime * 1000000);
    `fclog("Clock time :" @ ClockTime * 1000000000);
    // `fclog("Time       :" @ StopTime - StartTime);

    if (TestFailures > 0)
    {
        `fcerror("---" @ TestFailures @ "(Iteration=" $ Iteration $ ")" @ "FAILED CHECKS ---");
        `warn("---" @ TestSuiteName @ "TEST SUITE FAILED ---");
    }
    else
    {
        `fclog("--- ALL" @ TestSuiteName @ "TESTS PASSED SUCCESSFULLY ---");
    }

    SetTimer(0.001, False, NameOf(RunNextTest));

    Failures += TestFailures;
}

private final simulated function RunTests()
{
    local int I;
    local int K;

    if (!GMPClient.IsConnected())
    {
        `fclog("GMPClient not connected, state:" @ GMPClient.LinkState);
        if (GMPClient != None)
        {
            GMPClient.Close();
            GMPClient.ConnectToServer();
        }
        SetTimer(0.1, False, NameOf(RunTests));
        return;
    }

    if (!bRandPrimesRequested)
    {
        // RandomPrimes.Length = 1270;
        GMPClient.RandPrimeDelegate = AddRandomPrime;
        for (K = 2; K <= 128; ++K)
        {
            for (I = 0; I < 10; ++I)
            {
                GMPClient.RandPrime(K);
            }
        }
        bRandPrimesRequested = True;
    }

    if (bRandPrimesRequested && (RandomPrimes.Length < 1270))
    {
        `fclog("RandomPrimes.Length:" @ RandomPrimes.Length @ "checking again...");
        SetTimer(0.0000001, False, NameOf(RunTests));
        return;
    }

    GlobalStartTime = Utils.GetSystemTimeStamp();
    GlobalClock = 0.0;
    Clock(GlobalClock);

    `fclog("SystemTimeStamp:" @ Utils.GetSystemTimeStamp());

    RunNextTest();
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

private static final simulated function int IntsShouldBeEqual(
    int A,
    int B,
    optional string Msg = ""
)
{
    if (A != B)
    {
        `fcswarn("Mismatch:" @ A @ "!=" @ B @ Msg);
        return 1;
    }

    return 0;
}

private static final simulated function int IntAShouldBeGreater(
    int A,
    int B,
    optional string Msg = ""
)
{
    if (A <= B)
    {
        `fcswarn("Mismatch:" @ A @ "<=" @ B @ Msg);
        return 1;
    }

    return 0;
}

private static final simulated function int IntAShouldBeLess(
    int A,
    int B,
    optional string Msg = ""
)
{
    if (A >= B)
    {
        `fcswarn("Mismatch:" @ A @ ">=" @ B @ Msg);
        return 1;
    }

    return 0;
}

private static final simulated function int BytesShouldBeEqual(
    const out array<byte> X,
    const out array<byte> Z,
    optional string Msg = ""
)
{
    local int XLen;
    local int ZLen;
    local int Good;
    local int U;
    local int Cmp;

    XLen = X.Length;
    Good = 1;
    ZLen = Z.Length;

    // UnrealScript NOTE: ZLen is 0 in BearSSL
    // because mpz length is 0 for number 0. We have to
    // adjust here to match the functionality.
    if (ZLen == 1 && Z[0] == 0)
    {
        ZLen = 0;
    }

    if (XLen < ZLen)
    {
        `fcswarn("XLen < ZLen:" @ XLen @ ZLen);
        Good = 0;
    }
    else if (XLen > ZLen)
    {
        for (U = XLen; U > ZLen; --U)
        {
            if (X[XLen - U] != 0)
            {
                Good = 0;
                break;
            }
        }
    }
    Cmp = class'FCryptoBigInt'.static.MemCmp_Bytes(
        X, Z, ZLen, XLen + ZLen);
    Good = int(bool(Good) && (Cmp == 0));
    if (!bool(Good))
    {
        `fcswarn("Mismatch:" @ "Cmp:" @ Cmp @ Msg);
        LogBytes(X);
        LogBytes(Z);
    }

    return 1 - Good;
}

static final simulated function int BigIntsShouldBeEqual(
    const out array<int> A,
    const out array<int> B,
    optional string Msg = ""
)
{
    local array<byte> ABytes;
    local array<byte> BBytes;
    local int ALen;
    local int BLen;

    ALen = ((A[0] + 15) & ~15) >>> 2;
    BLen = ((B[0] + 15) & ~15) >>> 2;
    class'FCryptoBigInt'.static.Encode(ABytes, ALen, A);
    class'FCryptoBigInt'.static.Encode(BBytes, BLen, B);

    return BytesShouldBeEqual(ABytes, BBytes, Msg);
}

static final simulated function LogIntArray(
    const out array<int> Arr,
    optional string Delimiter = " "
)
{
    local int I;
    local string ArrStr;

    ArrStr = "";
    for (I = 0; I < Arr.Length; ++I)
    {
        ArrStr $= ToHex(Arr[I]);
        if (I < Arr.Length - 1 && Delimiter != "")
        {
            ArrStr $= Delimiter;
        }
    }

    `fcslog(ArrStr);
}

static final simulated function int IntArraysShouldBeEqual(
    const out array<int> A,
    const out array<int> B,
    optional string Msg = ""
)
{
    local int I;

    if (A.Length != B.Length)
    {
        `fcswarn("A.Length != B.Length" @ A.Length @ "!=" @ B.Length @ Msg);
        return 1;
    }

    for (I = 0; I < A.Length; ++I)
    {
        if (A[I] != B[I])
        {
            `fcswarn("A != B" @ Msg);
            LogIntArray(A);
            LogIntArray(B);
            `fcswarn("I:" @ I);
            return 1;
        }
    }

    return 0;
}

// Compare BigInt and GMP exported bytes.
// See: BearSSL test_match.c check_eqz().
static final simulated function int CheckEqz(
    const out array<int> X,
    const out array<byte> Z,
    optional string Msg = ""
)
{
    local int XLen;
    local array<byte> Xb;

    XLen = ((X[0] + 15) & ~15) >>> 2;
    class'FCryptoBigInt'.static.Encode(Xb, XLen, X);
    return BytesShouldBeEqual(Xb, Z, Msg);
}

static final simulated function string BytesWordsToString(
    const out array<byte> X,
    optional string Delimiter = " "
)
{
    local int I;
    local string Str;

    Str = "";
    for (I = 0; I < X.Length; ++I)
    {
        Str $= Right(ToHex(X[I]), 2);
        if (I < X.Length - 1 && Delimiter != "")
        {
            Str $= Delimiter;
        }
    }

    return Str;
}

static final simulated function LogBytes(
    const out array<byte> X
)
{
    `fcslog(BytesWordsToString(X));
}

private final simulated function GetRandomPrime(
    out array<byte> Dst
)
{
    // `fclog("RandomPrimeIndex:" @ RandomPrimeIndex);
    Dst = RandomPrimes[RandomPrimeIndex++].P;
    RandomPrimeIndex = RandomPrimeIndex % RandomPrimes.Length;
    // `fclog("Dst             :" @ BytesWordsToString(Dst));
}

private final simulated function GetPrime(
    out array<byte> Dst
)
{
    Dst = Primes[PrimeIndex++].P;
    PrimeIndex = PrimeIndex % Primes.Length;
}

// "Similar" to GMP's mpz_urandomm.
// Generate a random integer in the range 0 to N-1, inclusive(?).
// This is actually probably a quite bad PRNG, but good enough
// for testing purposes. I hope. Horribly inefficient though.
private final simulated function RandomBigInt(
    out array<byte> Dst,
    const out array<byte> N
)
{
    local int Ctl;
    local int I;
    local int Rounds;
    local array<int> BigIntCheck;
    local array<int> BigIntN;
    local int BICLen;
    local int BINLen;
    local int RandomIndex;
    // local string BigIntNString;

    class'FCryptoBigInt'.static.Decode(BigIntN, N, N.Length);
    // BigIntNString = class'FCryptoBigInt'.static.WordsToString(BigIntN);

    if (N.Length == 1)
    {
        if (N[0] == 0)
        {
            Dst.Length = 1;
            Dst[0] = 0;
        }
    }

    if (N.Length == 0)
    {
        Dst.Length = 1;
        Dst[0] = 0;
        return;
    }

    // Do at most (N.Length - 1) rounds.
    Rounds = Rand(N.Length);
    // `fclog("*** Rounds :" @ Rounds);

    if (Rounds == 0)
    {
        Dst.Length = 1;
        Dst[0] = Rand(N[0]);

        // class'FCryptoBigInt'.static.Decode(BigIntCheck, Dst, 1);
        // `fclog("BigIntCheck :" @ class'FCryptoBigInt'.static.WordsToString(BigIntCheck));

        return;
    }

    RandomIndex = 0;
    Dst.Length = 0;
    for (I = 0; I <= Rounds; ++I)
    {
        Ctl = 0;

        // NOTE: this is attempting to somewhat imitate GMP mpz_rrandomb behavior
        //       to generate an integer with long strings of zeros and ones in the
        //       binary representation.
        // TODO: better algorithm.
        if (FRand() >= 0.33)
        {
            // Pick one of known numbers with a binary representation that has a lot
            // of consecutive ones or zeros.
            Dst[I] = RepeatedBinaryRandoms[RandomIndex];
            RandomIndex = (RandomIndex + 1) % RepeatedBinaryRandoms.Length;
        }
        else
        {
            Dst[I] = Rand(256);
        }

        // Convert Dst to a BigInt for checking whether it's
        // less or greater than BigIntN.
        // BigIntCheck.Length = 0;
        // class'FCryptoBigInt'.static.Decode(BigIntCheck, Dst, Dst.Length);

        // `fclog("---");
        // `fclog("Dst Bytes:");
        // LogBytes(Dst);
        // `fclog("BigIntN     :" @ BigIntNString);
        // `fclog("N   Bytes:");
        // LogBytes(N);
        // `fclog("BigIntCheck :" @ class'FCryptoBigInt'.static.WordsToString(BigIntCheck));

        // TODO: we can probably skip this check until I == Rounds?
        // Ctl = class'FCryptoBigInt'.static.Sub(BigIntCheck, BigIntN, Ctl);
        // `fclog("Ctl         :" @ Ctl);
        // `fclog("I           :" @ I);
        // `fclog("BigIntCheck :" @ class'FCryptoBigInt'.static.WordsToString(BigIntCheck));

        if (I >= Rounds)
        {
            BigIntCheck.Length = 0;
            class'FCryptoBigInt'.static.Decode(BigIntCheck, Dst, Dst.Length);

            BICLen = (BigIntCheck[0] + 15) >>> 4;
            BINLen = (BigIntN[0] + 15) >>> 4;

            // Need to make sure announced bit lengths are equal
            // before using Sub().
            if (BICLen < BINLen)
            {
                BigIntCheck[0] = BigIntN[0];
            }
            else if (BINLen < BICLen)
            {
                BigIntN[0] = BigIntCheck[0];
            }

            // if (BICLen != BINLen)
            // {
            //     `fcwarn("BICLen != BINLen" @ BICLen @ BINLen);
            // }

            // Ctl == 0 -> BigIntCheck > BigIntN.
            // Ctl != 0 -> BigIntN     > BigIntCheck.
            Ctl = class'FCryptoBigInt'.static.Sub(BigIntCheck, BigIntN, 0);

            // Went above, drop top byte and call it good. There's probably
            // a better method, like re-randomizing the top byte?
            if (Ctl == 0)
            {
                Dst.Remove(0, 1);

                // BigIntCheck.Length = 0;
                // class'FCryptoBigInt'.static.Decode(BigIntCheck, Dst, Dst.Length);
                // `fclog("final       :");
                // `fclog("BigIntCheck :" @ class'FCryptoBigInt'.static.WordsToString(BigIntCheck));

                return;
            }
        }
    }
}

private final simulated function IntToBytes(
    int I,
    out array<byte> Bytes
)
{
    if (I <= 255)
    {
        Bytes.Length = 1;
        Bytes[0] = I & 0xFF;
        return;
    }

    if (I <= 65535)
    {
        Bytes.Length = 2;
        Bytes[0] = (I >>> 8) & 0xFF;
        Bytes[1] = (I      ) & 0xFF;
        return;
    }

    if (I <= 16777215)
    {
        Bytes.Length = 3;
        Bytes[0] = (I >>> 16) & 0xFF;
        Bytes[1] = (I >>>  8) & 0xFF;
        Bytes[2] = (I       ) & 0xFF;
        return;
    }

    Bytes[0] = (I >>> 24) & 0xFF;
    Bytes[1] = (I >>> 16) & 0xFF;
    Bytes[2] = (I >>>  8) & 0xFF;
    Bytes[3] = (I       ) & 0xFF;
}

private final simulated function int TestMemory()
{
    local int TestFailures;
    local int XLen;
    local int MLen;
    local int XLen0;
    local int XLen1;
    local int XLen2;
    local int XLen3;
    local array<byte> XBytes;
    local array<byte> Expected;
    local array<byte> In0;
    local array<byte> In1;
    local array<byte> In2;
    local array<byte> In3;
    local array<byte> Out0;
    local array<byte> Out1;
    local array<byte> Out2;
    local array<byte> Out3;
    local array<int> X;
    local array<int> XIn0;
    local array<int> XIn1;
    local array<int> XIn2;
    local array<int> XIn3;
    // local array<int> XOut0;
    // local array<int> XOut1;
    // local array<int> XOut2;
    // local array<int> XOut3;
    local array<byte> XBytes0;
    local array<byte> XBytes1;
    local array<byte> XBytes2;
    local array<byte> XBytes3;
    local array<int> MemoryIn0;
    // local array<int> MemoryIn1;
    local array<int> MemoryOut0;
    // local array<int> MemoryOut1;

    TestFailures = 0;

    MemoryIn0[0] = 0x4bc2;
    MemoryIn0[1] = 0xcbea;
    MemoryIn0[2] = 0xc810;
    MemoryIn0[3] = 0xaa90;
    MemoryIn0[4] = 0x9ab9;
    MemoryIn0[5] = 0xbabd;
    MemoryIn0[6] = 0x42a2;
    MemoryIn0[7] = 0xa58c;
    MemoryIn0[8] = 0xb873;
    MemoryIn0[9] = 0x5da1;
    MemoryOut0[0] = 0x4bc2;
    MemoryOut0[1] = 0xaa90;
    MemoryOut0[2] = 0x9ab9;
    MemoryOut0[3] = 0xbabd;
    MemoryOut0[4] = 0x42a2;
    MemoryOut0[5] = 0xa58c;
    MemoryOut0[6] = 0xb873;
    MemoryOut0[7] = 0x5da1;
    MemoryOut0[8] = 0xb873;
    MemoryOut0[9] = 0x5da1;

    // 4bc2cbeac810aa909ab9babd42a2a58cb8735da1 <-- original

    // 4bc2cbeac810 DstBytes: aa909ab9babd42a2a58cb8735da1
    // 4bc2aa909ab9babd42a2a58cb8735da1b8735da1 <-- result
    // 4bc2 aa90 9ab9 babd 42a2 a58c b873 5da1 b873 5da1

    `fclog("mutate self with MemMove");
    class'FCryptoBigInt'.static.MemMove(MemoryIn0, MemoryIn0, SIZEOF_UINT16_T * 7, 1, 3);
    // class'FCryptoBigInt'.static.MemMove(MemoryIn1);

    TestFailures += IntArraysShouldBeEqual(MemoryIn0, MemoryOut0);
    // TestFailures += IntArraysShouldBeEqual();

    class'FCryptoBigInt'.static.BytesFromHex(XBytes, "8815d9cd39874d1931329255ecd391");
    class'FCryptoBigInt'.static.BytesFromHex(Expected, "8815d915d9cd39874d1931329255ecd");

    class'FCryptoBigInt'.static.Decode(X, XBytes, XBytes.Length);

    class'FCryptoBigInt'.static.BytesFromHex(In0, "884753771b798de8756166bd568754b1");
    class'FCryptoBigInt'.static.BytesFromHex(In1, "0e2c492e944ca4f1a6e62783b6c243b21");
    class'FCryptoBigInt'.static.BytesFromHex(In2, "5c5c89702d405b397661e064d453ed29d3");
    class'FCryptoBigInt'.static.BytesFromHex(In3, "8055d419f13a6211673dc61602306efe8");
    class'FCryptoBigInt'.static.BytesFromHex(Out0, "4753771b798de8756166bd568754b154b1");
    class'FCryptoBigInt'.static.BytesFromHex(Out1, "2c492e944ca4f1a6e62783b6c243b213b21");
    class'FCryptoBigInt'.static.BytesFromHex(Out2, "5c89702d405b397661e064d453ed29d329d3");
    class'FCryptoBigInt'.static.BytesFromHex(Out3, "55d419f13a6211673dc61602306efe8fe8");

    class'FCryptoBigInt'.static.Decode(XIn0, In0, In0.Length);
    class'FCryptoBigInt'.static.Decode(XIn1, In1, In1.Length);
    class'FCryptoBigInt'.static.Decode(XIn2, In2, In2.Length);
    class'FCryptoBigInt'.static.Decode(XIn3, In3, In3.Length);

    // MLen = (M[0] + 15) >>> 4;
    MLen = 9;

    `fclog("MemMoving static cases generated with BearSSL");
    // Static cases generated with BearSSL test_math.
    class'FCryptoBigInt'.static.MemMove(XIn0, XIn0, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);
    class'FCryptoBigInt'.static.MemMove(XIn1, XIn1, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);
    class'FCryptoBigInt'.static.MemMove(XIn2, XIn2, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);
    class'FCryptoBigInt'.static.MemMove(XIn3, XIn3, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);

    XLen0 = ((XIn0[0] + 15) & ~15) >>> 2;
    XLen1 = ((XIn1[0] + 15) & ~15) >>> 2;
    XLen2 = ((XIn2[0] + 15) & ~15) >>> 2;
    XLen3 = ((XIn3[0] + 15) & ~15) >>> 2;

    class'FCryptoBigInt'.static.Encode(XBytes0, XLen0, XIn0);
    class'FCryptoBigInt'.static.Encode(XBytes1, XLen1, XIn1);
    class'FCryptoBigInt'.static.Encode(XBytes2, XLen2, XIn2);
    class'FCryptoBigInt'.static.Encode(XBytes3, XLen3, XIn3);

    TestFailures += BytesShouldBeEqual(XBytes0, Out0, "XBytes0 != Out0");
    TestFailures += BytesShouldBeEqual(XBytes1, Out1, "XBytes1 != Out1");
    TestFailures += BytesShouldBeEqual(XBytes2, Out2, "XBytes2 != Out2");
    TestFailures += BytesShouldBeEqual(XBytes3, Out3, "XBytes3 != Out3");

    `fclog("final MemMove, SIZEOF_UINT16_T="
        $ SIZEOF_UINT16_T $ ", MLen=" $ MLen $ ", X.Length=" $ X.Length
        $ ", X=" $ class'FCryptoBigInt'.static.WordsToString(X));
    // memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
    class'FCryptoBigInt'.static.MemMove(X, X, (MLen - 1) * SIZEOF_UINT16_T, 2, 1);
    `fclog("(after) X.Length=" $ X.Length $ ", X=" $ class'FCryptoBigInt'.static.WordsToString(X));

    XBytes.Length = 0;
    XLen = ((X[0] + 15) & ~15) >>> 2;
    class'FCryptoBigInt'.static.Encode(XBytes, XLen, X);

    TestFailures += BytesShouldBeEqual(XBytes, Expected, "XBytes != Expected");

    `fclog("done");

    return TestFailures;
}

private final simulated function int TestOperations()
{
`if(`isdefined(FCDEBUG))
    local array<int> X;
    local int Test;
    local int Test2;
    local int Result;
    local int TestFailures;

    TestFailures = 0;

    class'FCryptoBigInt'.static.Decode(
        X,
        Bytes_0,
        Bytes_0.Length
    );

    Test = 0;
    Result = class'FCryptoBigInt'.static.NOT(Test);
    TestFailures += IntsShouldBeEqual(Result, 1, "NOT");
    Result = class'FCryptoBigInt'.static.NOT(Result);
    TestFailures += IntsShouldBeEqual(Result, 0, "NOT");

    Test = 0;
    Test2 = 1;
    Result = class'FCryptoBigInt'.static.MUX(0, Test, Test2);
    TestFailures += IntsShouldBeEqual(Result, Test2, "MUX");
    Result = class'FCryptoBigInt'.static.MUX(1, Test, Test2);
    TestFailures += IntsShouldBeEqual(Result, Test, "MUX");

    Result = class'FCryptoBigInt'.static.EQ(5, 5);
    TestFailures += IntsShouldBeEqual(Result, 1, "EQ");
    Result = class'FCryptoBigInt'.static.EQ(7574, 0);
    TestFailures += IntsShouldBeEqual(Result, 0, "EQ");

    Result = class'FCryptoBigInt'.static.NEQ(5, 5);
    TestFailures += IntsShouldBeEqual(Result, 0, "NEQ");
    Result = class'FCryptoBigInt'.static.NEQ(7574, 0);
    TestFailures += IntsShouldBeEqual(Result, 1, "NEQ");

    Result = class'FCryptoBigInt'.static.GT(5, 5);
    TestFailures += IntsShouldBeEqual(Result, 0, "GT");
    Result = class'FCryptoBigInt'.static.GT(7574, 0);
    TestFailures += IntsShouldBeEqual(Result, 1, "GT");
    Result = class'FCryptoBigInt'.static.GT(5, 7345345);
    TestFailures += IntsShouldBeEqual(Result, 0, "GT");

    Result = class'FCryptoBigInt'.static.CMP(5, 5);
    TestFailures += IntsShouldBeEqual(Result, 0, "CMP");
    Result = class'FCryptoBigInt'.static.CMP(7574, 0);
    TestFailures += IntsShouldBeEqual(Result, 1, "CMP");
    Result = class'FCryptoBigInt'.static.CMP(5, 7345345);
    TestFailures += IntsShouldBeEqual(Result, -1, "CMP");

    Result = class'FCryptoBigInt'.static.EQ0(5);
    TestFailures += IntsShouldBeEqual(Result, 0, "EQ0");
    Result = class'FCryptoBigInt'.static.EQ0(0);
    TestFailures += IntsShouldBeEqual(Result, 1, "EQ0");
    Result = class'FCryptoBigInt'.static.EQ0(7345345);
    TestFailures += IntsShouldBeEqual(Result, 0, "EQ0");

    // Have to define these elsewhere to be able to test them.
    // Result = `GE(5, 0);
    // TestFailures += IntsShouldBeEqual(Result, 1, "GE");
    // Result = `GE(0, 15);
    // TestFailures += IntsShouldBeEqual(Result, 0, "GE");
    // Result = `GE(1, 1);
    // TestFailures += IntsShouldBeEqual(Result, 1, "GE");

    return TestFailures;
`else
    `fcslog("Not debugging, skipping...");
    return 0;
`endif
}

// TODO: prototyping.
final static function bool IsEq(int A, int B)
{
    local int C;

    C = A ^ B;
    C = C | (C >>> 16);
    C = C | (C >>> 8);
    C = C | (C >>> 4);
    C = C | (C >>> 2);
    C = C | (C >>> 1);
    return bool(-(C & 1));
}

// TODO: prototyping.
final static function bool IsGt(int A, int B)
{
    local int Ltb;
    local int Gtb;

    // These are all the bits in a that are less than their corresponding bits in b.
    Ltb = ~A & B;

    // These are all the bits in a that are greater than their corresponding bits in b.
    Gtb = A & ~B;

    Ltb = Ltb | (Ltb >>>  1);
    Ltb = Ltb | (Ltb >>>  2);
    Ltb = Ltb | (Ltb >>>  4);
    Ltb = Ltb | (Ltb >>>  8);
    Ltb = Ltb | (Ltb >>> 16);

    // Nonzero if a > b
    // Zero if a <= b
    return bool(Gtb & ~Ltb);
}

// Mirrors most of the tests from BearSSL's test_match.c,
// with some UnrealScript-specific additions.
private final simulated function int TestMath()
{
    local array<int> X;
    local array<byte> P;
    local array<byte> A;
    local array<byte> B;
    local array<byte> V;
    local array<byte> KArr;
    local array<byte> XEncoded;
    local array<byte> MontyMaExpectedAfterDecodeMod;
    local array<byte> TempBytes;
    local array<int> Mp;
    local array<int> Ma;
    local array<int> Mb;
    local array<int> Mv;
    local array<int> Mt1;
    local array<int> MontyMaBuf;
    local int TempLen;
    local int XLen;
    local int TestFailures;
    local int K;
    local int I;
    local int Ctl;
    local int Ctl2;
    local int MP0I;
    local int Test1;
    local int Test2;
    local int Result;
    local int Remainder;
    local int HardCodedMontyFail;
    local int MontyDecodeResult;
    local string BigIntString;

    local int Dummy;
    local FCQWORD QW;
    local bool bQWCarry;

    // TODO: Design for FCQWORD arithmetic.
    Dummy = 0xFFFFFFFF;
    `fclog("Dummy=" $ Dummy);
    `fclog("Dummy=" $ ToHex(Dummy));
    Dummy += 0xF;
    `fclog("Dummy=" $ Dummy);
    `fclog("Dummy=" $ ToHex(Dummy));

    QW.A = 0x00000000;
    QW.B = 0xFFFFFFFF;
    QW.B += 0xF;
    `fclog("QW.B=" $ QW.B);
    `fclog("QW.B=" $ ToHex(QW.B));
    bQWCarry = QW.B < 0xFFFFFFFF; // TODO: might need a bitwise check for this?
    `fclog("bQWCarry=" $ bQWCarry);

    QW.B = MaxInt;
    QW.B += 0xF;
    `fclog("QW.B=" $ QW.B);
    `fclog("QW.B=" $ ToHex(QW.B));
    bQWCarry = QW.B < 0xFFFFFFFF; // TODO: might need a bitwise check for this?
    `fclog("bQWCarry=" $ bQWCarry);

    `fclog("0x00000000 == 0xFFFFFFFF :" @ IsEq(0x00000000, 0xFFFFFFFF));
    `fclog("0xFFFFFFFF == 0xFFFFFFFF :" @ IsEq(0xFFFFFFFF, 0xFFFFFFFF));
    `fclog("0x00000000 == 0x00000000 :" @ IsEq(0x00000000, 0x00000000));
    `fclog("0x7FFFFFFF == 0x00000000 :" @ IsEq(0x7FFFFFFF, 0x00000000));
    `fclog("0x00000000 == 0x7FFFFFFF :" @ IsEq(0x00000000, 0x7FFFFFFF));
    `fclog("0x00000001 == 0x00000002 :" @ IsEq(0x00000001, 0x00000002));
    `fclog("0x00000002 == 0x00000001 :" @ IsEq(0x00000002, 0x00000001));
    `fclog("0x7FFFFFFF == 0xFFFFFFFF :" @ IsEq(0x7FFFFFFF, 0xFFFFFFFF));
    `fclog("0xFFFFFFFF == 0x7FFFFFFF :" @ IsEq(0xFFFFFFFF, 0x7FFFFFFF));

    `fclog("0x00000000 >  0xFFFFFFFF :" @ IsGt(0x00000000, 0xFFFFFFFF));
    `fclog("0xFFFFFFFF >  0xFFFFFFFF :" @ IsGt(0xFFFFFFFF, 0xFFFFFFFF));
    `fclog("0x00000000 >  0x00000000 :" @ IsGt(0x00000000, 0x00000000));
    `fclog("0x7FFFFFFF >  0x00000000 :" @ IsGt(0x7FFFFFFF, 0x00000000));
    `fclog("0x00000000 >  0x7FFFFFFF :" @ IsGt(0x00000000, 0x7FFFFFFF));
    `fclog("0x00000001 >  0x00000002 :" @ IsGt(0x00000001, 0x00000002));
    `fclog("0x00000002 >  0x00000001 :" @ IsGt(0x00000002, 0x00000001));
    `fclog("0x7FFFFFFF >  0xFFFFFFFF :" @ IsGt(0x7FFFFFFF, 0xFFFFFFFF));
    `fclog("0xFFFFFFFF >  0x7FFFFFFF :" @ IsGt(0xFFFFFFFF, 0x7FFFFFFF));

    // BearSSL assumes all operands caller-allocated.
    // We'll do some bare minimum allocations here to avoid issues.
    // TODO: does UScript dynamic array allocation break CT guarantees?
    // It most probably does. Is there an easy way to avoid it?
    // TODO: these are most probably useless. We "re-allocate" arrays
    // during big integer random generation anyway.
    P.Length = 4;
    A.Length = 4;
    B.Length = 4;
    V.Length = 4;
    Mp.Length = 4;
    Ma.Length = 4;
    Mb.Length = 4;
    Mv.Length = 4;

    `fcdebug("basic zero decode check");
    class'FCryptoBigInt'.static.Decode(
        X,
        Bytes_0,
        Bytes_0.Length
    );
    BigIntString = class'FCryptoBigInt'.static.WordsToString(X);
    TestFailures += StringsShouldBeEqual(
        BigIntString,
        "00000000 (0, 0)"
    );
    X.Length = 0;

    `fcdebug("check decode Bytes_257871904");
    class'FCryptoBigInt'.static.Decode(
        X,
        Bytes_257871904,
        Bytes_257871904.Length
    );
    BigIntString = class'FCryptoBigInt'.static.WordsToString(X);
    // `fclog("257871904                   BigInt :" @ BigIntString);
    //     1EBD     5020 (1, 13) (BearSSL)
    // 00001EBD 00005020 (1, 13) (UScript)
    TestFailures += StringsShouldBeEqual(
        BigIntString,
        "00001EBD 00005020 (1, 13)"
    );
    X.Length = 0;

    `fcdebug("check decode Bytes_683384335291162482276352519");
    class'FCryptoBigInt'.static.Decode(
        X,
        Bytes_683384335291162482276352519,
        Bytes_683384335291162482276352519.Length
    );
    BigIntString = class'FCryptoBigInt'.static.WordsToString(X);
    // `fclog("683384335291162482276352519 BigInt :" @ BigIntString);
    //     46A9     0430     62D7     1A7A     5DB9     4207 (5, 15) (BearSSL)
    // 000046A9 00000430 000062D7 00001A7A 00005DB9 00004207 (5, 15) (UScript)
    TestFailures += StringsShouldBeEqual(
        BigIntString,
        "000046A9 00000430 000062D7 00001A7A 00005DB9 00004207 (5, 15)"
    );
    XLen = ((X[0] + 15) & ~15) >>> 2;
    class'FCryptoBigInt'.static.Encode(XEncoded, XLen, X);
    // LogBytes(XEncoded);
    //                                     02 35 48 43 0C 5A E6 9E AE DC C2 07
    // 00 00 00 00 00 00 00 00 00 00 00 00 02 35 48 43 0C 5A E6 9E AE DC C2 07
    TestFailures += BytesShouldBeEqual(XEncoded, Bytes_683384335291162482276352519, "XEncoded");
    X.Length = 0;

    HardCodedMontyFail = 0;

    /*
    ------------------------- before monty
    ea:
    888EA7DC6FCC68E87AC2C1AF6B43D4B1
    ma:
    0086 0CC6 26E4 6E9B 1647 1536 134E 07EE 130F (9, 136, 8, 8)
    mp:
    0089 79A3 10BE 71C8 6074 7E3D 520D 764C 5DC3 (9, 136, 8, 8)
    ma bytes:
    86198C9B9374D96472A6C4D383F7130F
    mp bytes:
    89F34642FB8E46074FC7B4837B265DC3
    ------------------------- after monty
    ma:
    004C 008E 6E16 7B76 21B2 06C6 0435 1F56 2CB8 (9, 136, 8, 8)
    mp:
    0089 79A3 10BE 71C8 6074 7E3D 520D 764C 5DC3 (9, 136, 8, 8)
    ma bytes:
    4C011DB85BDBB21B20D8C10D4FAB2CB8
    -------------------------
    -------------------------
    -------------------------
    done.
    */

    `fcdebug("hard-coded monty test");

    class'FCryptoBigInt'.static.BytesFromHex(
        MontyEa,
        "888EA7DC6FCC68E87AC2C1AF6B43D4B1"
    );

    class'FCryptoBigInt'.static.BytesFromHex(
        MontyMaBefore_Bytes,
        "86198C9B9374D96472A6C4D383F7130F"
    );
    class'FCryptoBigInt'.static.Decode(
        MontyMaBefore,
        MontyMaBefore_Bytes,
        MontyMaBefore_Bytes.Length
    );

    class'FCryptoBigInt'.static.BytesFromHex(
        MontyMp_Bytes,
        "89F34642FB8E46074FC7B4837B265DC3"
    );
    class'FCryptoBigInt'.static.Decode(
        MontyMp,
        MontyMp_Bytes,
        MontyMp_Bytes.Length
    );

    class'FCryptoBigInt'.static.BytesFromHex(
        MontyMaAfter_Bytes,
        "4C011DB85BDBB21B20D8C10D4FAB2CB8"
    );
    class'FCryptoBigInt'.static.Decode(
        MontyMaAfter,
        MontyMaAfter_Bytes,
        MontyMaAfter_Bytes.Length
    );

    class'FCryptoBigInt'.static.BytesFromHex(
        MontyMaExpectedAfterDecodeMod,
        "884753771B798D0E87561606BD568754B1"
    );

    MontyMaBuf = MontyMaBefore;
    MontyDecodeResult = class'FCryptoBigInt'.static.DecodeMod(MontyMaBuf, MontyEa, MontyEa.Length, MontyMp);

    TempLen = ((MontyMaBuf[0] + 15) & ~15) >>> 2;
    class'FCryptoBigInt'.static.Encode(
        TempBytes,
        TempLen,
        MontyMaBuf
    );
    TestFailures += BytesShouldBeEqual(
        TempBytes,
        MontyMaExpectedAfterDecodeMod,
        "TempBytes != MontyMaExpectedAfterDecodeMod"
    );

    class'FCryptoBigInt'.static.ToMonty(MontyMaBuf, MontyMp);
    HardCodedMontyFail += BigIntsShouldBeEqual(MontyMaBuf, MontyMaAfter, "Hardcoded Monty Test");

    if (MontyDecodeResult != 1)
    {
        TestFailures += 1;
        `fcwarn("MontyDecodeResult != 1, actual value:" @ MontyDecodeResult);
    }

    if (HardCodedMontyFail > 0)
    {
        `fcwarn("MontyMaBuf    :" @ class'FCryptoBigInt'.static.WordsToString(MontyMaBuf));
        `fcwarn("MontyMaBefore :" @ class'FCryptoBigInt'.static.WordsToString(MontyMaBefore));
        `fcwarn("MontyMaAfter  :" @ class'FCryptoBigInt'.static.WordsToString(MontyMaAfter));
        `fcwarn("MontyMp       :" @ class'FCryptoBigInt'.static.WordsToString(MontyMp));
        `fcwarn("MontyEa       :" @ BytesWordsToString(MontyEa));
    }

    TestFailures += HardCodedMontyFail;

    `fcdebug("testing with primes, bUseRandomPrimes=" $ bUseRandomPrimes);

    KArr.Length = 4;
    for (K = 2; K <= 128; ++K)
    {
        for (I = 0; I < 10; ++I)
        {
            if (!bUseRandomPrimes)
            {
                GetPrime(P);
            }
            else
            {
                GetRandomPrime(P);
            }

            RandomBigInt(A, P);
            RandomBigInt(B, P);

            // TODO: mpz_rrandomb.
            IntToBytes(K + 60, KArr);
            RandomBigInt(V, KArr);

            Test1 = 10;
            Test2 = 2;
            Result = class'FCryptoBigInt'.static.DivRem16(Test1, Test2, Remainder);
            TestFailures += IntsShouldBeEqual(Result, 10 / 2, "DivRem16");
            TestFailures += IntsShouldBeEqual(Remainder, 0, "DivRem16");

            Test1 = 22;
            Test2 = 3;
            Result = class'FCryptoBigInt'.static.DivRem16(Test1, Test2, Remainder);
            TestFailures += IntsShouldBeEqual(Result, 7, "DivRem16");
            TestFailures += IntsShouldBeEqual(Remainder, 1, "DivRem16");

            class'FCryptoBigInt'.static.Decode(Mp, P, P.Length);
            if (class'FCryptoBigInt'.static.DecodeMod(Ma, A, A.Length, Mp) != 1)
            {
                `fclog("Decode error!");
                `fclog("A bytes:");
                LogBytes(A);
                `fclog("Mp:" @ class'FCryptoBigInt'.static.WordsToString(Mp));
                ++TestFailures;
            }

            MP0I = class'FCryptoBigInt'.static.NInv15(Mp[1]);
            if (class'FCryptoBigInt'.static.DecodeMod(Mb, B, B.Length, Mp) != 1)
            {
                `fclog("Decode error!");
                `fclog("B bytes:");
                LogBytes(B);
                `fclog("Mp:" @ class'FCryptoBigInt'.static.WordsToString(Mp));
                `fclog("MP0I:" @ MP0I);
                ++TestFailures;
            }

            class'FCryptoBigInt'.static.Decode(Mv, V, V.Length);
            TestFailures += CheckEqz(Mp, P, "Mp != P");
            TestFailures += CheckEqz(Ma, A, "Ma != A");
            TestFailures += CheckEqz(Mb, B, "Mb != B");
            TestFailures += CheckEqz(Mv, V, "Mv != V");

            class'FCryptoBigInt'.static.DecodeMod(Ma, A, A.Length, Mp);
            class'FCryptoBigInt'.static.DecodeMod(Mb, B, B.Length, Mp);
            Ctl = class'FCryptoBigInt'.static.Add(Ma, Mb, 1);
            Ctl = Ctl | (class'FCryptoBigInt'.static.Sub(Ma, Mp, 0) ^ 1);
            class'FCryptoBigInt'.static.Sub(Ma, Mp, Ctl);
            GMPClient.Begin();
            GMPClient.Var("T1", "");
            GMPClient.Var("A", BytesWordsToString(A, ""));
            GMPClient.Var("B", BytesWordsToString(B, ""));
            GMPClient.Var("P", BytesWordsToString(P, ""));
            GMPClient.Op("mpz_add", "T1", "A", "B");
            GMPClient.Op("mpz_mod", "T1", "T1", "P");
            GMPClient.Eq("T1", Ma, "T1 == Ma");
            GMPClient.End();

            class'FCryptoBigInt'.static.DecodeMod(Ma, A, A.Length, Mp);
            class'FCryptoBigInt'.static.DecodeMod(MB, B, B.Length, Mp);
            class'FCryptoBigInt'.static.Add(
                Ma,
                Mp,
                class'FCryptoBigInt'.static.Sub(Ma, Mb, 1)
            );
            GMPClient.Begin();
            GMPClient.Var("T1", "");
            GMPClient.Var("A", BytesWordsToString(A, ""));
            GMPClient.Var("B", BytesWordsToString(B, ""));
            GMPClient.Var("P", BytesWordsToString(P, ""));
            GMPClient.Op("mpz_sub", "T1", "A", "B");
            GMPClient.Op("mpz_mod", "T1", "T1", "P");
            GMPClient.Eq("T1", Ma, "T1 == Ma");
            GMPClient.End();

            class'FCryptoBigInt'.static.DecodeReduce(Ma, V, V.Length, Mp);
            GMPClient.Begin();
            GMPClient.Var("T1", "");
            GMPClient.Var("V", BytesWordsToString(V, ""));
            GMPClient.Var("P", BytesWordsToString(P, ""));
            GMPClient.Op("mpz_mod", "T1", "V", "P");
            GMPClient.Eq("T1", Ma, "T1 == Ma");
            GMPClient.End();

            class'FCryptoBigInt'.static.Decode(Mv, V, V.Length);
            class'FCryptoBigInt'.static.Reduce(Ma, Mv, Mp);
            GMPClient.Begin();
            GMPClient.Var("T1", "");
            GMPClient.Var("V", BytesWordsToString(V, ""));
            GMPClient.Var("P", BytesWordsToString(P, ""));
            GMPClient.Op("mpz_mod", "T1", "V", "P");
            GMPClient.Eq("T1", Ma, "T1 == Ma");
            GMPClient.End();

            // Ctl2 == 0 -> Ma >= Mp.
            // Ctl2 != 0 -> Ma <  Mp.
            Ctl2 = class'FCryptoBigInt'.static.Sub(Ma, Mp, 0);
            if (Ctl2 == 0)
            {
                `fcwarn("warning, (Ma < Mp) check failed before DecodeMod for:");
                `fcwarn("Ma   :" @ class'FCryptoBigInt'.static.WordsToString(Ma));
                `fcwarn("Mp   :" @ class'FCryptoBigInt'.static.WordsToString(Mp));
                `fcwarn("Ctl2 :" @ Ctl2);
            }

            class'FCryptoBigInt'.static.DecodeMod(Ma, A, A.Length, Mp);
            class'FCryptoBigInt'.static.ToMonty(Ma, Mp);
            GMPClient.Begin();
            GMPClient.Var("T1", "");
            GMPClient.Var("A", BytesWordsToString(A, ""));
            GMPClient.Var("P", BytesWordsToString(P, ""));
            // ((k + impl->word_size - 1) / impl->word_size) * impl->word_size
            GMPClient.Var("C", ToHex(((K + WORD_SIZE - 1) / WORD_SIZE) * WORD_SIZE));
            GMPClient.Op("mpz_mul_2exp", "T1", "A", "C");
            GMPClient.Op("mpz_mod", "T1", "T1", "P");
            GMPClient.Eq("T1", Ma, "T1 == Ma (DecodeMod+ToMonty)");
            GMPClient.End();

            class'FCryptoBigInt'.static.FromMonty(Ma, Mp, MP0I);
            GMPClient.Begin();
            GMPClient.Var("A", BytesWordsToString(A, ""));
            GMPClient.Op("nop", "A", "A", "A");
            GMPClient.Eq("A", Ma, "A == Ma (FromMonty)");
            GMPClient.End();

            class'FCryptoBigInt'.static.DecodeMod(Ma, A, A.Length, Mp);
            class'FCryptoBigInt'.static.DecodeMod(Mb, B, B.Length, Mp);
            class'FCryptoBigInt'.static.ToMonty(Ma, Mp);
            class'FCryptoBigInt'.static.MontyMul(Mt1, Ma, Mb, Mp, MP0I);
            GMPClient.Begin();
            GMPClient.Var("T1", "0");
            GMPClient.Var("A", BytesWordsToString(A, ""));
            GMPClient.Var("B", BytesWordsToString(B, ""));
            GMPClient.Var("P", BytesWordsToString(P, ""));
            GMPClient.Op("mpz_mul", "T1", "A", "B");
            GMPClient.Op("mpz_mod", "T1", "T1", "P");
            GMPClient.Eq("T1", Mt1);
            GMPClient.End();
        }
    }

    // Force sample update since timer in GMPClient might not
    // fire at the right time to update samples between tests.
    GMPClient.StopTransferRateSample();
    GMPClient.LogTransferRates();

    return TestFailures;
}

private final simulated function int TestAesCt()
{
    return 0;
}

DefaultProperties
{
    Failures=0
    PrimeIndex=0
    RandomPrimeIndex=0
    TestDelay=0.0
    NumTestLoops=1
    CurrentTestIteration=0
    GlobalClock=0.0
    bRandPrimesRequested=False

    bExitTimerSet=False
    ExitDelaySeconds=3.0
    bTestsDone=False

    CurrentTestDelegateIndex=0
    // TODO: This does not work in DefaultProperties?
    // TestDelegatesToRun[0]=(TestDelegate=TestMemory,TestName='TestMemory')
    // TestDelegatesToRun[1]=(TestDelegate=TestOperations,TestName='TestOperations')
    // TestDelegatesToRun[2]=(TestDelegate=TestMath,TestName='TestMath')
    // TestDelegatesToRun[3]=(TestDelegate=TestCrypto,TestName='TestCrypto')

    TickGroup=TG_DuringAsyncWork

    Begin Object Class=FCryptoUtils Name=Utils
    End Object

    RepeatedBinaryRandoms={(
        255,    // 11111111
        255,    // 11111111
        255,    // 11111111
        245,    // 11111110
        0,      // 00000000
        64,     // 10000000
        0,      // 00000000
        0,      // 00000000
        0,      // 00000000
        0,      // 00000000
        65,     // 10000010
        0,      // 00000000
        66,     // 10000100
        0,      // 00000000
        255,    // 11111111
        255,    // 11111111
        255,    // 11111111
        255,    // 11111111
    )}

    Bytes_0(0)=0

    // GMP mpz big endian export format.
    Bytes_257871904(0)=15  // 0x0F
    Bytes_257871904(1)=94  // 0x5E
    Bytes_257871904(2)=208 // 0xD0
    Bytes_257871904(3)=32  // 0x20

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

    Primes(0)=(P=(3))
    Primes(1)=(P=(3))
    Primes(2)=(P=(3))
    Primes(3)=(P=(3))
    Primes(4)=(P=(3))
    Primes(5)=(P=(3))
    Primes(6)=(P=(3))
    Primes(7)=(P=(3))
    Primes(8)=(P=(3))
    Primes(9)=(P=(3))
    Primes(10)=(P=(7))
    Primes(11)=(P=(5))
    Primes(12)=(P=(7))
    Primes(13)=(P=(7))
    Primes(14)=(P=(5))
    Primes(15)=(P=(7))
    Primes(16)=(P=(5))
    Primes(17)=(P=(5))
    Primes(18)=(P=(7))
    Primes(19)=(P=(5))
    Primes(20)=(P=(11))
    Primes(21)=(P=(11))
    Primes(22)=(P=(13))
    Primes(23)=(P=(13))
    Primes(24)=(P=(11))
    Primes(25)=(P=(11))
    Primes(26)=(P=(13))
    Primes(27)=(P=(11))
    Primes(28)=(P=(13))
    Primes(29)=(P=(11))
    Primes(30)=(P=(23))
    Primes(31)=(P=(19))
    Primes(32)=(P=(23))
    Primes(33)=(P=(19))
    Primes(34)=(P=(29))
    Primes(35)=(P=(19))
    Primes(36)=(P=(29))
    Primes(37)=(P=(19))
    Primes(38)=(P=(31))
    Primes(39)=(P=(19))
    Primes(40)=(P=(47))
    Primes(41)=(P=(61))
    Primes(42)=(P=(61))
    Primes(43)=(P=(37))
    Primes(44)=(P=(61))
    Primes(45)=(P=(41))
    Primes(46)=(P=(61))
    Primes(47)=(P=(43))
    Primes(48)=(P=(41))
    Primes(49)=(P=(37))
    Primes(50)=(P=(113))
    Primes(51)=(P=(109))
    Primes(52)=(P=(127))
    Primes(53)=(P=(83))
    Primes(54)=(P=(89))
    Primes(55)=(P=(101))
    Primes(56)=(P=(73))
    Primes(57)=(P=(89))
    Primes(58)=(P=(73))
    Primes(59)=(P=(67))
    Primes(60)=(P=(211))
    Primes(61)=(P=(149))
    Primes(62)=(P=(241))
    Primes(63)=(P=(191))
    Primes(64)=(P=(163))
    Primes(65)=(P=(167))
    Primes(66)=(P=(157))
    Primes(67)=(P=(251))
    Primes(68)=(P=(191))
    Primes(69)=(P=(151))
    Primes(70)=(P=(1,103))
    Primes(71)=(P=(1,183))
    Primes(72)=(P=(1,25))
    Primes(73)=(P=(1,7))
    Primes(74)=(P=(1,141))
    Primes(75)=(P=(1,243))
    Primes(76)=(P=(1,235))
    Primes(77)=(P=(1,103))
    Primes(78)=(P=(1,231))
    Primes(79)=(P=(1,231))
    Primes(80)=(P=(3,41))
    Primes(81)=(P=(2,141))
    Primes(82)=(P=(3,209))
    Primes(83)=(P=(3,139))
    Primes(84)=(P=(3,5))
    Primes(85)=(P=(3,223))
    Primes(86)=(P=(3,199))
    Primes(87)=(P=(2,149))
    Primes(88)=(P=(3,143))
    Primes(89)=(P=(2,207))
    Primes(90)=(P=(7,115))
    Primes(91)=(P=(6,121))
    Primes(92)=(P=(6,187))
    Primes(93)=(P=(6,157))
    Primes(94)=(P=(7,235))
    Primes(95)=(P=(4,163))
    Primes(96)=(P=(5,147))
    Primes(97)=(P=(5,219))
    Primes(98)=(P=(4,225))
    Primes(99)=(P=(7,195))
    Primes(100)=(P=(12,49))
    Primes(101)=(P=(11,155))
    Primes(102)=(P=(10,237))
    Primes(103)=(P=(15,107))
    Primes(104)=(P=(14,143))
    Primes(105)=(P=(10,117))
    Primes(106)=(P=(15,209))
    Primes(107)=(P=(10,153))
    Primes(108)=(P=(9,37))
    Primes(109)=(P=(11,27))
    Primes(110)=(P=(17,209))
    Primes(111)=(P=(31,133))
    Primes(112)=(P=(16,61))
    Primes(113)=(P=(20,107))
    Primes(114)=(P=(19,217))
    Primes(115)=(P=(30,77))
    Primes(116)=(P=(31,57))
    Primes(117)=(P=(16,57))
    Primes(118)=(P=(28,51))
    Primes(119)=(P=(21,37))
    Primes(120)=(P=(48,239))
    Primes(121)=(P=(58,183))
    Primes(122)=(P=(46,25))
    Primes(123)=(P=(42,221))
    Primes(124)=(P=(58,135))
    Primes(125)=(P=(62,15))
    Primes(126)=(P=(37,141))
    Primes(127)=(P=(50,207))
    Primes(128)=(P=(49,45))
    Primes(129)=(P=(41,117))
    Primes(130)=(P=(101,251))
    Primes(131)=(P=(108,169))
    Primes(132)=(P=(105,101))
    Primes(133)=(P=(78,193))
    Primes(134)=(P=(86,243))
    Primes(135)=(P=(102,1))
    Primes(136)=(P=(97,111))
    Primes(137)=(P=(82,9))
    Primes(138)=(P=(77,5))
    Primes(139)=(P=(86,255))
    Primes(140)=(P=(188,153))
    Primes(141)=(P=(178,73))
    Primes(142)=(P=(199,13))
    Primes(143)=(P=(186,127))
    Primes(144)=(P=(226,205))
    Primes(145)=(P=(244,75))
    Primes(146)=(P=(244,163))
    Primes(147)=(P=(209,153))
    Primes(148)=(P=(162,247))
    Primes(149)=(P=(178,21))
    Primes(150)=(P=(1,145,23))
    Primes(151)=(P=(1,230,113))
    Primes(152)=(P=(1,90,13))
    Primes(153)=(P=(1,225,237))
    Primes(154)=(P=(1,234,87))
    Primes(155)=(P=(1,44,149))
    Primes(156)=(P=(1,121,185))
    Primes(157)=(P=(1,27,19))
    Primes(158)=(P=(1,233,85))
    Primes(159)=(P=(1,50,91))
    Primes(160)=(P=(3,220,135))
    Primes(161)=(P=(2,159,17))
    Primes(162)=(P=(2,21,99))
    Primes(163)=(P=(3,172,229))
    Primes(164)=(P=(2,185,49))
    Primes(165)=(P=(3,197,219))
    Primes(166)=(P=(3,100,211))
    Primes(167)=(P=(2,59,73))
    Primes(168)=(P=(3,137,239))
    Primes(169)=(P=(2,50,199))
    Primes(170)=(P=(5,45,189))
    Primes(171)=(P=(4,206,217))
    Primes(172)=(P=(7,165,181))
    Primes(173)=(P=(5,203,31))
    Primes(174)=(P=(6,107,63))
    Primes(175)=(P=(4,126,61))
    Primes(176)=(P=(6,182,201))
    Primes(177)=(P=(4,80,55))
    Primes(178)=(P=(7,222,193))
    Primes(179)=(P=(5,71,97))
    Primes(180)=(P=(9,34,153))
    Primes(181)=(P=(10,60,91))
    Primes(182)=(P=(8,145,121))
    Primes(183)=(P=(13,121,17))
    Primes(184)=(P=(11,131,141))
    Primes(185)=(P=(11,37,91))
    Primes(186)=(P=(14,129,153))
    Primes(187)=(P=(10,188,185))
    Primes(188)=(P=(11,219,27))
    Primes(189)=(P=(11,40,191))
    Primes(190)=(P=(29,150,243))
    Primes(191)=(P=(19,162,121))
    Primes(192)=(P=(16,27,243))
    Primes(193)=(P=(19,72,85))
    Primes(194)=(P=(16,138,43))
    Primes(195)=(P=(29,101,61))
    Primes(196)=(P=(19,56,247))
    Primes(197)=(P=(17,161,249))
    Primes(198)=(P=(25,175,99))
    Primes(199)=(P=(20,66,233))
    Primes(200)=(P=(40,73,161))
    Primes(201)=(P=(44,164,241))
    Primes(202)=(P=(56,25,113))
    Primes(203)=(P=(33,5,209))
    Primes(204)=(P=(60,60,71))
    Primes(205)=(P=(47,151,35))
    Primes(206)=(P=(60,63,65))
    Primes(207)=(P=(59,116,31))
    Primes(208)=(P=(45,126,61))
    Primes(209)=(P=(38,228,143))
    Primes(210)=(P=(111,164,3))
    Primes(211)=(P=(92,212,183))
    Primes(212)=(P=(99,87,227))
    Primes(213)=(P=(108,199,159))
    Primes(214)=(P=(84,206,27))
    Primes(215)=(P=(101,102,45))
    Primes(216)=(P=(80,244,139))
    Primes(217)=(P=(88,156,109))
    Primes(218)=(P=(73,226,129))
    Primes(219)=(P=(82,193,189))
    Primes(220)=(P=(165,77,179))
    Primes(221)=(P=(206,68,123))
    Primes(222)=(P=(161,72,123))
    Primes(223)=(P=(132,210,211))
    Primes(224)=(P=(180,112,61))
    Primes(225)=(P=(181,145,77))
    Primes(226)=(P=(137,96,125))
    Primes(227)=(P=(190,20,227))
    Primes(228)=(P=(201,46,87))
    Primes(229)=(P=(233,219,105))
    Primes(230)=(P=(1,220,182,99))
    Primes(231)=(P=(1,112,138,93))
    Primes(232)=(P=(1,131,112,235))
    Primes(233)=(P=(1,131,2,117))
    Primes(234)=(P=(1,70,162,249))
    Primes(235)=(P=(1,227,152,63))
    Primes(236)=(P=(1,177,88,51))
    Primes(237)=(P=(1,27,48,177))
    Primes(238)=(P=(1,56,80,75))
    Primes(239)=(P=(1,124,121,157))
    Primes(240)=(P=(2,230,210,55))
    Primes(241)=(P=(2,64,80,57))
    Primes(242)=(P=(2,203,99,147))
    Primes(243)=(P=(3,11,195,47))
    Primes(244)=(P=(3,101,143,75))
    Primes(245)=(P=(2,15,57,75))
    Primes(246)=(P=(3,49,206,229))
    Primes(247)=(P=(3,206,249,93))
    Primes(248)=(P=(2,247,42,95))
    Primes(249)=(P=(3,225,126,179))
    Primes(250)=(P=(4,45,114,175))
    Primes(251)=(P=(6,176,167,183))
    Primes(252)=(P=(6,106,67,215))
    Primes(253)=(P=(4,57,228,39))
    Primes(254)=(P=(5,120,111,51))
    Primes(255)=(P=(6,106,22,185))
    Primes(256)=(P=(5,184,234,241))
    Primes(257)=(P=(7,194,205,111))
    Primes(258)=(P=(4,129,199,107))
    Primes(259)=(P=(5,62,194,101))
    Primes(260)=(P=(9,184,69,97))
    Primes(261)=(P=(13,122,250,63))
    Primes(262)=(P=(15,89,34,59))
    Primes(263)=(P=(12,175,66,105))
    Primes(264)=(P=(8,58,192,19))
    Primes(265)=(P=(11,7,150,25))
    Primes(266)=(P=(14,91,236,63))
    Primes(267)=(P=(9,55,70,99))
    Primes(268)=(P=(12,4,254,47))
    Primes(269)=(P=(9,117,48,203))
    Primes(270)=(P=(25,183,122,71))
    Primes(271)=(P=(21,170,195,173))
    Primes(272)=(P=(25,33,118,255))
    Primes(273)=(P=(23,148,116,171))
    Primes(274)=(P=(24,56,182,75))
    Primes(275)=(P=(21,200,44,69))
    Primes(276)=(P=(18,6,42,175))
    Primes(277)=(P=(22,30,237,103))
    Primes(278)=(P=(21,212,71,127))
    Primes(279)=(P=(29,65,164,113))
    Primes(280)=(P=(54,124,139,95))
    Primes(281)=(P=(58,75,145,29))
    Primes(282)=(P=(54,137,219,9))
    Primes(283)=(P=(56,75,75,87))
    Primes(284)=(P=(38,62,119,103))
    Primes(285)=(P=(37,239,155,143))
    Primes(286)=(P=(53,119,121,95))
    Primes(287)=(P=(44,127,31,69))
    Primes(288)=(P=(48,177,91,141))
    Primes(289)=(P=(58,228,36,27))
    Primes(290)=(P=(71,65,123,205))
    Primes(291)=(P=(85,54,83,109))
    Primes(292)=(P=(127,196,218,21))
    Primes(293)=(P=(110,88,251,203))
    Primes(294)=(P=(113,132,95,127))
    Primes(295)=(P=(84,60,180,239))
    Primes(296)=(P=(81,154,65,197))
    Primes(297)=(P=(125,250,240,157))
    Primes(298)=(P=(93,253,72,175))
    Primes(299)=(P=(80,48,61,43))
    Primes(300)=(P=(233,196,25,105))
    Primes(301)=(P=(154,2,79,99))
    Primes(302)=(P=(151,60,196,179))
    Primes(303)=(P=(193,139,27,153))
    Primes(304)=(P=(174,74,233,171))
    Primes(305)=(P=(179,239,211,69))
    Primes(306)=(P=(142,120,68,49))
    Primes(307)=(P=(255,172,77,43))
    Primes(308)=(P=(158,141,85,223))
    Primes(309)=(P=(168,25,232,239))
    Primes(310)=(P=(1,235,216,169,65))
    Primes(311)=(P=(1,0,235,227,43))
    Primes(312)=(P=(1,210,71,147,73))
    Primes(313)=(P=(1,140,12,214,51))
    Primes(314)=(P=(1,239,89,3,227))
    Primes(315)=(P=(1,148,223,203,201))
    Primes(316)=(P=(1,220,133,222,67))
    Primes(317)=(P=(1,69,204,140,47))
    Primes(318)=(P=(1,191,160,36,129))
    Primes(319)=(P=(1,2,25,167,91))
    Primes(320)=(P=(3,251,77,119,83))
    Primes(321)=(P=(3,150,237,27,37))
    Primes(322)=(P=(3,53,239,194,43))
    Primes(323)=(P=(2,133,78,53,231))
    Primes(324)=(P=(2,107,75,80,163))
    Primes(325)=(P=(2,161,19,104,43))
    Primes(326)=(P=(2,171,104,183,117))
    Primes(327)=(P=(2,124,218,195,207))
    Primes(328)=(P=(2,178,209,147,111))
    Primes(329)=(P=(2,95,250,170,205))
    Primes(330)=(P=(5,51,141,46,143))
    Primes(331)=(P=(7,245,168,23,173))
    Primes(332)=(P=(7,73,27,205,85))
    Primes(333)=(P=(4,73,46,42,131))
    Primes(334)=(P=(7,228,96,21,199))
    Primes(335)=(P=(5,249,192,221,69))
    Primes(336)=(P=(6,201,2,225,237))
    Primes(337)=(P=(7,74,9,233,113))
    Primes(338)=(P=(4,56,13,222,177))
    Primes(339)=(P=(7,196,180,52,53))
    Primes(340)=(P=(9,99,117,25,183))
    Primes(341)=(P=(10,128,15,161,197))
    Primes(342)=(P=(12,145,223,40,203))
    Primes(343)=(P=(13,105,137,203,29))
    Primes(344)=(P=(11,75,181,232,205))
    Primes(345)=(P=(11,16,72,174,71))
    Primes(346)=(P=(14,209,141,116,49))
    Primes(347)=(P=(15,125,110,194,127))
    Primes(348)=(P=(15,233,9,171,239))
    Primes(349)=(P=(14,212,19,112,229))
    Primes(350)=(P=(24,228,125,139,167))
    Primes(351)=(P=(30,200,216,138,233))
    Primes(352)=(P=(22,139,18,217,181))
    Primes(353)=(P=(28,242,255,145,241))
    Primes(354)=(P=(29,43,156,54,161))
    Primes(355)=(P=(28,61,83,225,27))
    Primes(356)=(P=(18,122,92,252,27))
    Primes(357)=(P=(30,143,222,50,39))
    Primes(358)=(P=(30,200,6,99,9))
    Primes(359)=(P=(21,109,213,130,153))
    Primes(360)=(P=(49,166,121,168,143))
    Primes(361)=(P=(41,253,212,219,191))
    Primes(362)=(P=(53,190,76,144,169))
    Primes(363)=(P=(53,62,55,180,231))
    Primes(364)=(P=(50,19,32,49,169))
    Primes(365)=(P=(35,112,99,78,97))
    Primes(366)=(P=(47,249,193,191,89))
    Primes(367)=(P=(49,7,217,21,125))
    Primes(368)=(P=(50,36,21,172,143))
    Primes(369)=(P=(43,226,158,188,101))
    Primes(370)=(P=(127,234,51,18,19))
    Primes(371)=(P=(100,53,103,153,69))
    Primes(372)=(P=(106,205,251,214,165))
    Primes(373)=(P=(101,64,178,189,87))
    Primes(374)=(P=(74,85,168,113,129))
    Primes(375)=(P=(120,119,238,123,13))
    Primes(376)=(P=(95,72,46,49,31))
    Primes(377)=(P=(99,174,64,246,111))
    Primes(378)=(P=(66,113,209,239,199))
    Primes(379)=(P=(115,83,241,241,233))
    Primes(380)=(P=(182,56,69,222,67))
    Primes(381)=(P=(129,67,193,46,187))
    Primes(382)=(P=(233,123,119,81,195))
    Primes(383)=(P=(146,207,240,181,125))
    Primes(384)=(P=(146,45,188,85,113))
    Primes(385)=(P=(207,28,112,55,115))
    Primes(386)=(P=(210,32,197,17,83))
    Primes(387)=(P=(253,115,170,60,103))
    Primes(388)=(P=(167,208,216,13,165))
    Primes(389)=(P=(192,189,26,249,215))
    Primes(390)=(P=(1,80,158,108,118,19))
    Primes(391)=(P=(1,165,176,238,105,189))
    Primes(392)=(P=(1,127,215,160,3,51))
    Primes(393)=(P=(1,48,184,70,112,241))
    Primes(394)=(P=(1,58,117,50,117,81))
    Primes(395)=(P=(1,77,178,194,108,19))
    Primes(396)=(P=(1,210,242,223,111,39))
    Primes(397)=(P=(1,217,133,97,10,59))
    Primes(398)=(P=(1,147,218,81,134,47))
    Primes(399)=(P=(1,169,212,194,75,37))
    Primes(400)=(P=(3,165,175,229,107,237))
    Primes(401)=(P=(3,132,189,50,111,167))
    Primes(402)=(P=(2,192,189,7,61,205))
    Primes(403)=(P=(3,14,48,111,169,151))
    Primes(404)=(P=(3,218,88,129,168,251))
    Primes(405)=(P=(2,69,6,240,189,231))
    Primes(406)=(P=(2,98,87,215,11,161))
    Primes(407)=(P=(2,130,182,74,116,49))
    Primes(408)=(P=(2,171,245,70,182,247))
    Primes(409)=(P=(2,100,171,205,113,223))
    Primes(410)=(P=(4,230,16,151,36,105))
    Primes(411)=(P=(4,189,223,160,126,101))
    Primes(412)=(P=(4,32,143,29,109,107))
    Primes(413)=(P=(6,138,254,32,102,177))
    Primes(414)=(P=(4,97,219,239,183,105))
    Primes(415)=(P=(6,195,133,181,224,165))
    Primes(416)=(P=(4,158,12,115,6,63))
    Primes(417)=(P=(6,227,1,244,74,211))
    Primes(418)=(P=(6,137,74,7,176,129))
    Primes(419)=(P=(5,216,70,169,152,109))
    Primes(420)=(P=(13,211,219,111,141,143))
    Primes(421)=(P=(15,28,41,146,76,241))
    Primes(422)=(P=(9,187,73,219,128,181))
    Primes(423)=(P=(12,81,85,75,127,69))
    Primes(424)=(P=(12,212,28,167,52,85))
    Primes(425)=(P=(13,131,211,141,5,143))
    Primes(426)=(P=(13,37,110,47,62,237))
    Primes(427)=(P=(15,39,164,14,165,51))
    Primes(428)=(P=(13,53,84,44,245,229))
    Primes(429)=(P=(15,85,5,17,116,45))
    Primes(430)=(P=(18,49,106,36,163,1))
    Primes(431)=(P=(22,47,106,199,246,101))
    Primes(432)=(P=(30,68,232,161,182,123))
    Primes(433)=(P=(24,106,217,90,238,91))
    Primes(434)=(P=(28,172,25,33,85,61))
    Primes(435)=(P=(18,157,172,54,111,209))
    Primes(436)=(P=(24,77,70,20,219,77))
    Primes(437)=(P=(24,137,54,175,43,91))
    Primes(438)=(P=(22,104,241,163,220,191))
    Primes(439)=(P=(30,17,62,223,65,247))
    Primes(440)=(P=(45,135,240,217,171,139))
    Primes(441)=(P=(40,124,250,104,174,255))
    Primes(442)=(P=(34,45,120,228,235,51))
    Primes(443)=(P=(43,210,5,184,225,85))
    Primes(444)=(P=(39,229,93,88,11,111))
    Primes(445)=(P=(33,129,135,218,199,83))
    Primes(446)=(P=(43,226,40,16,216,31))
    Primes(447)=(P=(57,111,7,250,174,119))
    Primes(448)=(P=(46,89,64,111,153,189))
    Primes(449)=(P=(62,151,178,230,58,135))
    Primes(450)=(P=(90,10,246,248,248,191))
    Primes(451)=(P=(112,58,214,174,246,113))
    Primes(452)=(P=(74,145,86,57,88,233))
    Primes(453)=(P=(119,139,178,153,87,223))
    Primes(454)=(P=(82,124,135,55,12,29))
    Primes(455)=(P=(111,245,49,11,103,245))
    Primes(456)=(P=(76,150,102,223,130,11))
    Primes(457)=(P=(106,31,215,171,226,147))
    Primes(458)=(P=(79,152,79,75,77,121))
    Primes(459)=(P=(84,80,207,48,180,233))
    Primes(460)=(P=(138,44,250,58,100,191))
    Primes(461)=(P=(139,253,236,255,168,75))
    Primes(462)=(P=(186,103,107,38,254,195))
    Primes(463)=(P=(205,222,133,51,97,175))
    Primes(464)=(P=(135,36,117,209,197,39))
    Primes(465)=(P=(181,181,44,15,98,253))
    Primes(466)=(P=(254,121,182,100,193,1))
    Primes(467)=(P=(186,146,150,63,6,237))
    Primes(468)=(P=(201,118,184,197,29,235))
    Primes(469)=(P=(201,7,103,150,180,251))
    Primes(470)=(P=(1,14,242,194,149,224,95))
    Primes(471)=(P=(1,227,112,90,30,0,97))
    Primes(472)=(P=(1,227,176,215,140,119,101))
    Primes(473)=(P=(1,32,203,109,148,142,137))
    Primes(474)=(P=(1,241,217,112,61,50,141))
    Primes(475)=(P=(1,137,82,67,248,153,195))
    Primes(476)=(P=(1,236,75,218,71,216,171))
    Primes(477)=(P=(1,102,159,107,226,161,185))
    Primes(478)=(P=(1,250,183,47,213,214,153))
    Primes(479)=(P=(1,59,242,20,24,78,237))
    Primes(480)=(P=(2,52,157,103,232,50,185))
    Primes(481)=(P=(3,40,31,21,238,110,155))
    Primes(482)=(P=(2,21,146,229,147,201,101))
    Primes(483)=(P=(3,160,116,90,8,215,229))
    Primes(484)=(P=(2,1,214,182,105,37,171))
    Primes(485)=(P=(2,121,192,98,56,51,19))
    Primes(486)=(P=(2,128,116,192,165,91,69))
    Primes(487)=(P=(2,57,180,16,80,162,221))
    Primes(488)=(P=(3,42,231,201,138,116,95))
    Primes(489)=(P=(3,123,137,227,223,202,97))
    Primes(490)=(P=(4,143,209,234,127,56,201))
    Primes(491)=(P=(4,4,89,217,133,138,251))
    Primes(492)=(P=(4,127,154,96,238,107,101))
    Primes(493)=(P=(6,32,94,245,223,4,165))
    Primes(494)=(P=(7,225,162,165,58,166,149))
    Primes(495)=(P=(5,100,56,253,105,35,147))
    Primes(496)=(P=(4,190,112,245,113,195,159))
    Primes(497)=(P=(5,118,47,144,125,36,63))
    Primes(498)=(P=(4,101,4,84,214,99,111))
    Primes(499)=(P=(5,218,75,250,185,111,75))
    Primes(500)=(P=(9,124,103,2,6,251,197))
    Primes(501)=(P=(15,128,118,163,249,153,45))
    Primes(502)=(P=(10,76,56,136,189,111,171))
    Primes(503)=(P=(9,53,27,147,172,51,103))
    Primes(504)=(P=(11,212,169,242,19,177,41))
    Primes(505)=(P=(15,114,7,19,13,237,79))
    Primes(506)=(P=(11,18,243,246,62,11,211))
    Primes(507)=(P=(15,79,187,215,243,48,205))
    Primes(508)=(P=(12,96,180,111,179,245,3))
    Primes(509)=(P=(11,57,191,185,69,7,33))
    Primes(510)=(P=(18,229,25,140,38,21,17))
    Primes(511)=(P=(21,10,156,168,142,34,103))
    Primes(512)=(P=(31,121,66,53,211,150,141))
    Primes(513)=(P=(26,240,81,152,37,2,253))
    Primes(514)=(P=(30,68,173,40,74,70,231))
    Primes(515)=(P=(16,149,126,128,158,167,197))
    Primes(516)=(P=(22,29,227,100,248,28,227))
    Primes(517)=(P=(19,137,97,116,44,16,245))
    Primes(518)=(P=(27,30,158,183,32,5,241))
    Primes(519)=(P=(29,135,115,162,219,193,163))
    Primes(520)=(P=(56,127,98,82,190,186,237))
    Primes(521)=(P=(37,115,68,106,89,130,41))
    Primes(522)=(P=(50,179,81,25,1,1,75))
    Primes(523)=(P=(44,73,3,76,96,13,57))
    Primes(524)=(P=(47,25,33,155,80,211,195))
    Primes(525)=(P=(60,196,234,238,23,43,57))
    Primes(526)=(P=(55,133,177,178,87,55,133))
    Primes(527)=(P=(35,85,1,40,212,47,13))
    Primes(528)=(P=(55,90,246,157,207,124,155))
    Primes(529)=(P=(62,167,191,150,228,75,1))
    Primes(530)=(P=(71,123,99,203,31,200,211))
    Primes(531)=(P=(99,206,133,10,33,77,89))
    Primes(532)=(P=(88,191,176,57,143,156,37))
    Primes(533)=(P=(82,143,193,158,72,234,125))
    Primes(534)=(P=(114,184,24,82,112,141,59))
    Primes(535)=(P=(97,176,37,79,226,219,235))
    Primes(536)=(P=(107,81,68,164,73,80,143))
    Primes(537)=(P=(96,208,96,63,216,88,195))
    Primes(538)=(P=(86,50,32,57,63,151,225))
    Primes(539)=(P=(118,60,10,121,112,117,121))
    Primes(540)=(P=(203,124,139,226,124,93,13))
    Primes(541)=(P=(197,185,94,142,103,206,67))
    Primes(542)=(P=(182,189,178,181,146,41,77))
    Primes(543)=(P=(203,109,132,193,20,13,241))
    Primes(544)=(P=(132,139,146,12,80,123,125))
    Primes(545)=(P=(226,74,13,45,160,21,137))
    Primes(546)=(P=(150,252,182,157,129,247,25))
    Primes(547)=(P=(165,212,52,247,136,12,215))
    Primes(548)=(P=(234,228,92,77,63,246,39))
    Primes(549)=(P=(159,117,134,2,2,145,27))
    Primes(550)=(P=(1,38,102,105,174,219,239,9))
    Primes(551)=(P=(1,253,138,48,149,27,219,229))
    Primes(552)=(P=(1,76,139,80,111,118,188,125))
    Primes(553)=(P=(1,30,108,214,20,132,110,121))
    Primes(554)=(P=(1,141,137,92,125,42,235,23))
    Primes(555)=(P=(1,127,223,114,89,226,6,71))
    Primes(556)=(P=(1,196,248,115,206,86,124,121))
    Primes(557)=(P=(1,69,29,87,176,86,162,133))
    Primes(558)=(P=(1,171,22,211,90,235,75,141))
    Primes(559)=(P=(1,103,228,152,126,21,186,25))
    Primes(560)=(P=(3,116,24,114,240,101,248,5))
    Primes(561)=(P=(2,199,137,239,160,72,19,215))
    Primes(562)=(P=(3,38,232,168,19,165,56,43))
    Primes(563)=(P=(3,211,195,239,187,71,44,57))
    Primes(564)=(P=(3,76,146,11,72,220,233,143))
    Primes(565)=(P=(2,128,169,209,64,231,95,159))
    Primes(566)=(P=(2,241,195,249,67,133,148,67))
    Primes(567)=(P=(3,134,19,61,80,227,69,45))
    Primes(568)=(P=(3,200,246,216,111,155,66,25))
    Primes(569)=(P=(2,151,192,28,189,72,244,75))
    Primes(570)=(P=(5,177,122,31,126,222,43,55))
    Primes(571)=(P=(4,146,249,94,140,252,22,27))
    Primes(572)=(P=(4,211,199,228,202,10,70,85))
    Primes(573)=(P=(4,83,163,41,194,30,69,63))
    Primes(574)=(P=(7,136,22,85,91,157,207,191))
    Primes(575)=(P=(5,134,29,40,141,20,21,97))
    Primes(576)=(P=(7,18,88,72,253,99,55,21))
    Primes(577)=(P=(4,177,148,9,232,212,22,25))
    Primes(578)=(P=(6,61,10,62,114,67,27,71))
    Primes(579)=(P=(4,236,205,240,25,128,122,71))
    Primes(580)=(P=(13,52,62,74,207,151,239,73))
    Primes(581)=(P=(9,224,33,159,133,226,144,165))
    Primes(582)=(P=(10,54,61,132,182,97,36,69))
    Primes(583)=(P=(14,24,67,154,22,149,132,7))
    Primes(584)=(P=(9,252,94,205,43,29,162,185))
    Primes(585)=(P=(12,239,115,140,1,152,97,227))
    Primes(586)=(P=(11,206,84,33,75,27,148,53))
    Primes(587)=(P=(10,215,78,94,73,37,198,139))
    Primes(588)=(P=(9,198,105,242,186,189,185,139))
    Primes(589)=(P=(15,156,19,69,198,89,109,49))
    Primes(590)=(P=(27,60,104,11,9,169,197,105))
    Primes(591)=(P=(24,104,235,198,182,246,165,113))
    Primes(592)=(P=(19,50,14,86,165,77,195,37))
    Primes(593)=(P=(19,221,192,80,20,245,99,107))
    Primes(594)=(P=(17,34,189,53,13,171,7,123))
    Primes(595)=(P=(27,104,194,164,174,118,86,19))
    Primes(596)=(P=(17,215,53,112,144,153,12,31))
    Primes(597)=(P=(19,51,54,188,47,100,18,65))
    Primes(598)=(P=(31,75,88,45,182,66,52,215))
    Primes(599)=(P=(20,125,180,151,226,187,105,49))
    Primes(600)=(P=(49,9,236,4,228,1,3,77))
    Primes(601)=(P=(51,197,208,84,137,180,59,1))
    Primes(602)=(P=(51,216,227,224,88,255,18,147))
    Primes(603)=(P=(63,6,115,78,189,226,193,37))
    Primes(604)=(P=(44,177,147,180,51,163,240,149))
    Primes(605)=(P=(32,48,250,166,51,3,174,85))
    Primes(606)=(P=(34,209,147,119,233,128,13,19))
    Primes(607)=(P=(57,66,130,50,249,68,246,143))
    Primes(608)=(P=(41,196,125,42,101,105,142,239))
    Primes(609)=(P=(36,180,40,139,136,252,224,107))
    Primes(610)=(P=(112,103,48,187,17,71,65,161))
    Primes(611)=(P=(95,230,201,15,247,177,206,141))
    Primes(612)=(P=(117,47,110,38,144,251,167,189))
    Primes(613)=(P=(72,76,68,144,133,70,37,23))
    Primes(614)=(P=(105,122,177,115,143,217,210,17))
    Primes(615)=(P=(89,255,86,67,253,226,155,163))
    Primes(616)=(P=(120,165,183,82,152,74,23,55))
    Primes(617)=(P=(69,52,187,74,164,162,174,29))
    Primes(618)=(P=(64,24,112,96,21,105,74,171))
    Primes(619)=(P=(71,145,11,186,14,154,66,141))
    Primes(620)=(P=(147,195,39,89,166,188,162,107))
    Primes(621)=(P=(129,73,209,78,83,11,195,61))
    Primes(622)=(P=(143,59,228,225,75,168,106,173))
    Primes(623)=(P=(168,84,208,150,249,37,4,193))
    Primes(624)=(P=(140,126,76,219,175,140,192,53))
    Primes(625)=(P=(225,169,179,196,235,39,130,251))
    Primes(626)=(P=(171,211,29,135,255,1,152,25))
    Primes(627)=(P=(184,58,201,227,3,108,28,233))
    Primes(628)=(P=(174,58,41,241,3,46,130,85))
    Primes(629)=(P=(137,109,127,58,250,68,207,165))
    Primes(630)=(P=(1,182,146,196,128,107,84,28,251))
    Primes(631)=(P=(1,192,171,71,166,235,167,166,155))
    Primes(632)=(P=(1,167,75,47,111,133,19,41,115))
    Primes(633)=(P=(1,181,159,85,252,5,194,55,179))
    Primes(634)=(P=(1,249,246,58,0,38,146,240,191))
    Primes(635)=(P=(1,238,206,2,85,199,206,39,111))
    Primes(636)=(P=(1,22,187,57,141,36,236,60,63))
    Primes(637)=(P=(1,212,51,229,237,51,62,4,27))
    Primes(638)=(P=(1,1,254,202,131,53,253,212,167))
    Primes(639)=(P=(1,222,105,17,84,96,217,244,233))
    Primes(640)=(P=(3,112,163,156,243,111,153,107,111))
    Primes(641)=(P=(3,8,168,115,239,205,8,195,243))
    Primes(642)=(P=(3,236,225,241,57,103,17,52,175))
    Primes(643)=(P=(3,115,240,202,64,109,1,179,219))
    Primes(644)=(P=(3,211,120,88,174,56,37,28,5))
    Primes(645)=(P=(3,43,92,244,239,190,2,203,201))
    Primes(646)=(P=(3,212,255,10,125,189,40,219,121))
    Primes(647)=(P=(2,152,57,173,0,68,128,163,111))
    Primes(648)=(P=(3,217,66,81,133,59,50,21,61))
    Primes(649)=(P=(2,5,125,131,209,182,81,207,89))
    Primes(650)=(P=(4,198,78,238,92,5,82,16,165))
    Primes(651)=(P=(4,111,201,107,17,151,127,240,15))
    Primes(652)=(P=(5,118,1,108,51,67,150,44,183))
    Primes(653)=(P=(6,85,160,69,31,138,160,230,7))
    Primes(654)=(P=(4,139,135,45,149,148,120,94,5))
    Primes(655)=(P=(4,170,113,124,71,75,186,229,145))
    Primes(656)=(P=(7,21,65,184,89,180,143,115,59))
    Primes(657)=(P=(6,190,104,119,150,97,147,63,97))
    Primes(658)=(P=(4,28,181,143,48,233,3,206,221))
    Primes(659)=(P=(7,174,112,1,226,192,204,185,83))
    Primes(660)=(P=(14,26,179,254,166,138,254,123,75))
    Primes(661)=(P=(10,60,148,78,243,241,166,131,187))
    Primes(662)=(P=(8,112,91,24,144,222,247,241,209))
    Primes(663)=(P=(14,82,57,138,161,225,86,161,19))
    Primes(664)=(P=(11,242,190,28,53,175,67,76,147))
    Primes(665)=(P=(11,186,96,235,43,83,46,203,89))
    Primes(666)=(P=(14,112,249,167,42,126,254,130,185))
    Primes(667)=(P=(14,240,38,212,88,45,21,70,123))
    Primes(668)=(P=(11,15,166,195,63,238,214,241,79))
    Primes(669)=(P=(10,163,147,240,161,56,142,182,197))
    Primes(670)=(P=(29,33,102,181,126,85,138,139,131))
    Primes(671)=(P=(24,206,11,90,152,81,253,75,51))
    Primes(672)=(P=(20,171,233,95,125,21,159,88,235))
    Primes(673)=(P=(29,244,33,207,108,79,1,78,87))
    Primes(674)=(P=(20,255,23,219,50,128,123,118,125))
    Primes(675)=(P=(21,178,72,81,99,216,119,108,13))
    Primes(676)=(P=(28,5,234,12,49,23,50,145,47))
    Primes(677)=(P=(24,137,212,164,86,201,163,66,133))
    Primes(678)=(P=(17,242,125,83,91,43,77,13,51))
    Primes(679)=(P=(17,217,87,33,67,169,19,39,131))
    Primes(680)=(P=(60,101,55,189,183,81,64,62,37))
    Primes(681)=(P=(59,179,184,227,190,249,249,244,61))
    Primes(682)=(P=(47,95,178,25,12,232,157,236,211))
    Primes(683)=(P=(56,109,8,90,25,215,55,228,203))
    Primes(684)=(P=(50,48,83,203,46,32,123,174,169))
    Primes(685)=(P=(32,22,47,27,112,176,249,24,149))
    Primes(686)=(P=(43,147,194,88,238,242,23,77,35))
    Primes(687)=(P=(52,162,64,252,15,239,149,134,239))
    Primes(688)=(P=(55,182,149,253,49,103,154,68,51))
    Primes(689)=(P=(60,216,60,203,176,73,22,65,153))
    Primes(690)=(P=(83,212,36,213,13,220,8,94,89))
    Primes(691)=(P=(72,208,10,135,66,132,249,98,157))
    Primes(692)=(P=(92,102,70,125,97,97,115,189,185))
    Primes(693)=(P=(82,134,217,33,87,203,235,207,55))
    Primes(694)=(P=(102,153,62,73,249,237,208,163,131))
    Primes(695)=(P=(75,186,29,65,16,197,37,122,129))
    Primes(696)=(P=(125,254,253,208,20,128,90,228,171))
    Primes(697)=(P=(79,68,131,124,22,25,76,229,39))
    Primes(698)=(P=(97,213,246,13,58,48,2,238,101))
    Primes(699)=(P=(73,64,52,174,74,47,254,22,159))
    Primes(700)=(P=(177,126,115,225,45,205,182,227,191))
    Primes(701)=(P=(219,234,41,31,206,120,215,126,195))
    Primes(702)=(P=(244,90,45,245,207,195,251,91,49))
    Primes(703)=(P=(230,219,102,227,247,219,31,203,89))
    Primes(704)=(P=(187,185,240,93,69,209,21,230,45))
    Primes(705)=(P=(133,45,114,36,167,164,128,218,79))
    Primes(706)=(P=(221,4,74,56,205,21,198,245,69))
    Primes(707)=(P=(238,95,168,173,86,189,146,249,163))
    Primes(708)=(P=(158,166,105,120,125,230,188,30,65))
    Primes(709)=(P=(169,148,247,73,100,209,194,190,141))
    Primes(710)=(P=(1,52,90,33,140,44,188,4,160,49))
    Primes(711)=(P=(1,123,189,54,133,5,7,49,52,51))
    Primes(712)=(P=(1,88,114,16,131,146,53,148,29,17))
    Primes(713)=(P=(1,146,101,38,207,66,188,124,249,33))
    Primes(714)=(P=(1,238,212,138,23,67,50,127,120,31))
    Primes(715)=(P=(1,230,195,100,21,103,191,62,227,21))
    Primes(716)=(P=(1,172,29,218,82,245,178,191,59,243))
    Primes(717)=(P=(1,196,233,96,69,0,123,88,168,57))
    Primes(718)=(P=(1,82,168,106,81,190,247,174,61,167))
    Primes(719)=(P=(1,152,13,217,249,90,128,218,152,167))
    Primes(720)=(P=(3,116,161,154,137,175,33,36,55,119))
    Primes(721)=(P=(2,183,162,114,195,120,184,87,46,81))
    Primes(722)=(P=(3,27,222,112,70,40,130,68,112,37))
    Primes(723)=(P=(2,78,197,200,25,105,41,33,89,93))
    Primes(724)=(P=(3,92,74,77,1,191,105,48,113,99))
    Primes(725)=(P=(2,140,24,182,148,147,142,31,213,109))
    Primes(726)=(P=(2,221,125,232,60,168,25,55,213,163))
    Primes(727)=(P=(2,71,243,190,178,230,69,222,61,1))
    Primes(728)=(P=(2,179,130,170,140,160,44,246,56,179))
    Primes(729)=(P=(2,187,34,245,152,134,129,39,18,247))
    Primes(730)=(P=(4,205,46,253,247,152,24,192,171,139))
    Primes(731)=(P=(4,225,102,164,69,51,148,221,255,103))
    Primes(732)=(P=(6,57,25,101,78,228,128,210,203,207))
    Primes(733)=(P=(4,229,62,25,242,223,244,41,38,139))
    Primes(734)=(P=(7,87,215,226,12,17,67,234,206,43))
    Primes(735)=(P=(5,3,211,66,233,95,85,212,237,79))
    Primes(736)=(P=(4,140,137,79,218,238,247,134,209,27))
    Primes(737)=(P=(6,55,209,212,103,245,36,10,99,97))
    Primes(738)=(P=(7,99,48,62,206,158,187,221,133,113))
    Primes(739)=(P=(7,200,233,87,144,248,106,67,39,11))
    Primes(740)=(P=(10,138,119,192,52,109,36,210,57,249))
    Primes(741)=(P=(12,247,82,2,78,12,128,73,241,131))
    Primes(742)=(P=(8,179,12,126,186,59,159,154,124,15))
    Primes(743)=(P=(13,72,58,7,87,183,42,10,240,109))
    Primes(744)=(P=(8,222,187,213,252,135,249,175,119,7))
    Primes(745)=(P=(13,108,226,235,205,58,81,252,193,115))
    Primes(746)=(P=(9,93,129,253,103,122,159,226,113,171))
    Primes(747)=(P=(12,47,227,22,170,206,161,155,167,169))
    Primes(748)=(P=(8,14,100,103,152,206,4,77,129,189))
    Primes(749)=(P=(15,252,245,129,59,65,143,186,70,253))
    Primes(750)=(P=(24,69,60,243,229,40,226,158,171,233))
    Primes(751)=(P=(22,120,246,83,202,171,167,209,17,61))
    Primes(752)=(P=(28,149,11,94,108,147,18,150,74,17))
    Primes(753)=(P=(16,195,116,32,127,73,88,0,59,75))
    Primes(754)=(P=(23,64,1,115,241,172,79,133,13,187))
    Primes(755)=(P=(25,145,239,219,45,213,33,14,167,237))
    Primes(756)=(P=(27,3,173,68,179,160,201,227,110,3))
    Primes(757)=(P=(28,227,233,159,218,106,2,206,179,225))
    Primes(758)=(P=(19,123,168,148,103,62,144,162,227,175))
    Primes(759)=(P=(24,43,240,13,186,175,222,195,211,217))
    Primes(760)=(P=(41,34,44,33,31,51,112,160,187,151))
    Primes(761)=(P=(36,222,92,126,114,159,140,93,30,31))
    Primes(762)=(P=(48,28,77,197,214,4,156,59,174,235))
    Primes(763)=(P=(42,130,81,43,132,170,140,121,12,51))
    Primes(764)=(P=(52,254,233,161,64,137,133,90,8,51))
    Primes(765)=(P=(48,191,230,10,22,39,131,209,106,165))
    Primes(766)=(P=(46,191,91,239,6,27,61,55,89,69))
    Primes(767)=(P=(37,176,197,111,86,109,187,31,80,185))
    Primes(768)=(P=(56,32,241,62,107,104,58,18,208,127))
    Primes(769)=(P=(46,120,78,193,189,132,118,184,14,137))
    Primes(770)=(P=(109,86,98,207,151,58,36,38,11,77))
    Primes(771)=(P=(98,211,120,97,100,83,196,175,192,149))
    Primes(772)=(P=(117,228,220,127,38,47,106,149,152,255))
    Primes(773)=(P=(104,229,202,92,105,91,241,120,244,205))
    Primes(774)=(P=(64,125,173,114,93,20,69,115,166,187))
    Primes(775)=(P=(101,172,46,136,248,57,17,95,254,1))
    Primes(776)=(P=(66,124,113,208,117,48,142,143,206,167))
    Primes(777)=(P=(122,13,92,165,90,31,175,8,180,37))
    Primes(778)=(P=(101,24,127,214,76,56,39,81,160,195))
    Primes(779)=(P=(76,37,68,184,157,120,226,56,200,39))
    Primes(780)=(P=(174,46,137,170,10,254,212,0,33,45))
    Primes(781)=(P=(202,147,21,227,239,71,174,237,204,219))
    Primes(782)=(P=(252,157,185,228,171,125,170,209,187,97))
    Primes(783)=(P=(229,197,123,216,216,191,37,188,136,13))
    Primes(784)=(P=(199,229,180,51,47,176,215,161,73,191))
    Primes(785)=(P=(175,111,69,106,67,90,203,26,128,239))
    Primes(786)=(P=(128,247,244,235,115,140,221,175,124,215))
    Primes(787)=(P=(132,24,130,20,2,46,40,168,211,5))
    Primes(788)=(P=(180,226,83,204,131,185,21,131,101,107))
    Primes(789)=(P=(141,79,145,26,9,86,95,25,120,223))
    Primes(790)=(P=(1,80,19,24,70,171,245,40,58,232,51))
    Primes(791)=(P=(1,7,57,223,195,74,68,190,138,132,189))
    Primes(792)=(P=(1,148,6,178,168,155,223,84,135,25,231))
    Primes(793)=(P=(1,144,226,234,190,205,75,21,214,105,141))
    Primes(794)=(P=(1,207,96,218,42,241,116,75,39,83,221))
    Primes(795)=(P=(1,113,8,168,135,218,121,157,193,180,25))
    Primes(796)=(P=(1,158,60,13,84,182,55,160,158,168,163))
    Primes(797)=(P=(1,101,35,185,246,226,75,53,227,93,187))
    Primes(798)=(P=(1,118,225,26,243,101,154,131,79,68,137))
    Primes(799)=(P=(1,188,92,98,201,208,246,30,31,16,57))
    Primes(800)=(P=(3,196,70,58,1,243,201,236,103,224,73))
    Primes(801)=(P=(2,124,0,91,210,18,183,55,176,104,61))
    Primes(802)=(P=(3,92,144,81,178,204,60,86,61,225,35))
    Primes(803)=(P=(3,202,176,97,68,31,190,46,183,140,123))
    Primes(804)=(P=(2,12,125,145,23,56,86,74,72,90,183))
    Primes(805)=(P=(3,124,184,10,73,99,25,80,234,160,71))
    Primes(806)=(P=(3,60,209,226,78,75,205,255,129,81,187))
    Primes(807)=(P=(3,142,115,58,105,124,8,74,87,166,209))
    Primes(808)=(P=(2,3,86,253,164,37,78,206,201,9,3))
    Primes(809)=(P=(2,2,71,67,58,198,141,187,155,13,65))
    Primes(810)=(P=(7,146,93,1,240,70,219,173,31,8,51))
    Primes(811)=(P=(5,198,18,194,244,217,255,223,142,41,141))
    Primes(812)=(P=(4,70,39,81,34,239,217,97,3,163,227))
    Primes(813)=(P=(6,33,42,40,21,68,30,177,160,97,45))
    Primes(814)=(P=(6,18,244,216,198,29,140,35,56,120,35))
    Primes(815)=(P=(7,61,231,239,216,81,64,83,209,40,73))
    Primes(816)=(P=(6,237,151,59,177,128,184,153,93,86,249))
    Primes(817)=(P=(6,157,2,115,58,243,88,59,14,199,95))
    Primes(818)=(P=(5,239,155,114,194,64,211,133,208,31,175))
    Primes(819)=(P=(5,245,234,208,75,65,104,38,123,120,117))
    Primes(820)=(P=(12,161,216,229,8,199,127,153,95,162,179))
    Primes(821)=(P=(13,77,107,45,182,119,53,83,207,237,103))
    Primes(822)=(P=(9,180,52,230,64,251,56,70,235,68,233))
    Primes(823)=(P=(10,138,218,25,231,48,94,31,179,61,151))
    Primes(824)=(P=(12,248,143,190,84,107,184,42,229,73,249))
    Primes(825)=(P=(14,147,148,43,91,234,131,189,63,111,85))
    Primes(826)=(P=(10,239,92,20,134,8,126,13,10,20,211))
    Primes(827)=(P=(13,129,155,160,93,203,118,73,208,50,221))
    Primes(828)=(P=(10,72,36,107,74,150,153,125,143,27,227))
    Primes(829)=(P=(15,29,216,30,45,98,71,229,122,245,191))
    Primes(830)=(P=(31,212,12,85,97,133,82,217,158,226,159))
    Primes(831)=(P=(25,103,184,71,167,215,40,23,165,209,249))
    Primes(832)=(P=(21,184,41,202,12,99,243,180,233,37,69))
    Primes(833)=(P=(17,137,75,116,116,107,100,65,89,161,89))
    Primes(834)=(P=(18,171,88,156,244,50,11,214,139,178,89))
    Primes(835)=(P=(23,116,93,135,161,91,78,39,89,248,33))
    Primes(836)=(P=(22,164,128,225,114,183,56,146,151,20,35))
    Primes(837)=(P=(25,191,111,13,147,48,68,229,244,224,237))
    Primes(838)=(P=(20,225,198,155,167,164,97,50,170,166,201))
    Primes(839)=(P=(16,151,222,158,148,5,97,58,123,175,49))
    Primes(840)=(P=(60,34,126,215,4,115,192,100,111,185,245))
    Primes(841)=(P=(35,51,46,224,115,103,228,32,173,124,181))
    Primes(842)=(P=(53,58,160,48,173,25,73,233,205,162,39))
    Primes(843)=(P=(63,4,187,181,128,43,156,30,237,1,181))
    Primes(844)=(P=(59,134,113,138,22,39,110,84,158,60,131))
    Primes(845)=(P=(39,205,129,108,127,61,104,129,255,167,129))
    Primes(846)=(P=(44,22,245,129,58,113,221,171,156,248,137))
    Primes(847)=(P=(52,30,196,91,101,81,94,241,6,37,75))
    Primes(848)=(P=(40,189,62,49,72,63,32,97,242,164,173))
    Primes(849)=(P=(34,146,186,52,164,127,85,6,241,150,227))
    Primes(850)=(P=(75,193,215,26,143,60,113,61,157,178,35))
    Primes(851)=(P=(118,253,99,212,98,97,166,52,54,235,169))
    Primes(852)=(P=(70,206,161,195,175,237,81,121,175,152,103))
    Primes(853)=(P=(93,250,182,166,248,69,45,155,118,48,235))
    Primes(854)=(P=(116,88,121,176,139,254,150,239,44,152,203))
    Primes(855)=(P=(103,165,196,152,112,16,144,74,63,201,105))
    Primes(856)=(P=(123,141,240,251,37,249,199,77,171,201,203))
    Primes(857)=(P=(90,120,7,250,172,75,41,46,43,182,185))
    Primes(858)=(P=(98,213,171,30,18,34,89,193,124,244,15))
    Primes(859)=(P=(118,34,247,244,76,100,164,10,207,22,195))
    Primes(860)=(P=(227,19,2,128,164,42,37,4,66,137,181))
    Primes(861)=(P=(203,23,86,74,74,115,213,62,244,64,173))
    Primes(862)=(P=(133,123,48,66,180,190,94,217,114,65,73))
    Primes(863)=(P=(217,37,50,137,64,26,87,192,138,95,155))
    Primes(864)=(P=(139,64,44,12,104,180,47,143,233,154,93))
    Primes(865)=(P=(156,186,228,242,41,46,184,218,202,234,227))
    Primes(866)=(P=(147,201,178,185,126,209,120,49,86,98,235))
    Primes(867)=(P=(171,249,50,232,248,186,95,164,87,94,115))
    Primes(868)=(P=(243,28,141,70,218,192,181,186,72,134,147))
    Primes(869)=(P=(138,212,67,122,115,247,37,25,52,101,245))
    Primes(870)=(P=(1,240,71,113,244,82,173,189,180,200,231,153))
    Primes(871)=(P=(1,135,136,179,11,40,184,29,214,251,45,163))
    Primes(872)=(P=(1,27,224,183,138,90,36,125,192,16,133,61))
    Primes(873)=(P=(1,227,121,238,117,104,171,68,60,222,81,37))
    Primes(874)=(P=(1,200,193,28,11,34,98,180,161,229,228,93))
    Primes(875)=(P=(1,5,174,171,80,83,163,121,112,8,5,65))
    Primes(876)=(P=(1,240,203,91,167,46,7,55,218,30,165,5))
    Primes(877)=(P=(1,7,251,126,47,166,26,72,161,33,45,149))
    Primes(878)=(P=(1,169,251,24,199,175,61,91,131,252,138,99))
    Primes(879)=(P=(1,109,175,82,161,8,49,186,17,163,99,131))
    Primes(880)=(P=(3,205,247,36,114,83,3,152,168,96,78,11))
    Primes(881)=(P=(2,4,116,223,143,90,133,236,218,205,157,251))
    Primes(882)=(P=(2,170,129,84,246,138,77,36,115,46,237,171))
    Primes(883)=(P=(3,89,32,65,75,156,128,135,147,66,48,239))
    Primes(884)=(P=(2,17,39,114,95,11,3,186,186,29,41,175))
    Primes(885)=(P=(3,178,66,146,131,98,102,79,123,149,84,103))
    Primes(886)=(P=(3,37,69,152,98,237,55,227,241,103,147,9))
    Primes(887)=(P=(2,110,2,125,20,125,151,249,152,144,170,233))
    Primes(888)=(P=(3,57,220,12,88,179,203,79,220,189,97,175))
    Primes(889)=(P=(3,242,122,70,129,149,220,44,138,129,184,87))
    Primes(890)=(P=(6,48,28,53,249,132,31,251,56,28,71,179))
    Primes(891)=(P=(7,198,28,155,246,220,131,245,155,81,122,219))
    Primes(892)=(P=(6,164,41,66,98,30,232,129,68,169,180,133))
    Primes(893)=(P=(5,231,50,125,95,13,159,149,207,167,143,17))
    Primes(894)=(P=(6,133,104,51,226,40,166,128,236,106,98,195))
    Primes(895)=(P=(6,154,98,163,252,7,160,250,160,65,78,31))
    Primes(896)=(P=(5,255,251,0,53,106,7,176,253,175,63,113))
    Primes(897)=(P=(6,99,234,127,130,6,179,199,36,91,178,33))
    Primes(898)=(P=(5,195,53,110,110,182,175,215,231,150,113,107))
    Primes(899)=(P=(5,93,238,246,207,238,164,10,176,32,9,113))
    Primes(900)=(P=(9,244,178,63,43,210,215,240,87,75,86,49))
    Primes(901)=(P=(9,238,230,95,235,141,199,38,237,76,102,147))
    Primes(902)=(P=(8,21,55,190,46,11,221,12,181,46,237,183))
    Primes(903)=(P=(15,42,62,210,206,129,104,13,138,133,108,227))
    Primes(904)=(P=(12,232,173,235,120,10,68,121,162,218,205,171))
    Primes(905)=(P=(8,239,172,197,172,17,45,246,61,122,57,225))
    Primes(906)=(P=(12,133,212,16,178,217,173,226,184,249,126,43))
    Primes(907)=(P=(8,83,71,63,90,35,151,189,36,222,204,169))
    Primes(908)=(P=(10,118,218,149,121,151,107,4,82,103,186,205))
    Primes(909)=(P=(14,57,79,92,36,165,101,78,142,243,226,65))
    Primes(910)=(P=(29,191,187,86,127,94,43,52,176,173,229,171))
    Primes(911)=(P=(19,145,165,57,60,32,133,199,29,136,65,221))
    Primes(912)=(P=(16,154,134,160,165,5,81,88,185,156,148,141))
    Primes(913)=(P=(18,215,128,168,51,250,152,170,219,40,235,227))
    Primes(914)=(P=(21,136,53,249,77,29,221,126,35,211,217,69))
    Primes(915)=(P=(22,223,66,83,57,156,38,221,106,253,249,177))
    Primes(916)=(P=(21,206,210,97,33,162,139,202,54,144,236,147))
    Primes(917)=(P=(19,136,74,232,4,27,162,117,142,98,253,183))
    Primes(918)=(P=(19,114,171,14,94,57,161,49,26,101,2,91))
    Primes(919)=(P=(18,115,168,154,34,122,206,46,155,245,250,249))
    Primes(920)=(P=(54,172,121,59,141,147,35,232,2,247,27,99))
    Primes(921)=(P=(63,175,21,40,63,92,134,255,12,52,150,115))
    Primes(922)=(P=(63,136,190,60,91,48,47,81,187,43,57,115))
    Primes(923)=(P=(41,49,254,72,163,218,25,57,241,8,37,111))
    Primes(924)=(P=(60,225,206,42,229,44,183,144,214,204,146,45))
    Primes(925)=(P=(42,109,219,15,154,134,73,212,61,42,85,233))
    Primes(926)=(P=(35,176,189,128,114,184,122,179,44,254,174,253))
    Primes(927)=(P=(61,70,228,152,2,240,214,248,203,172,136,33))
    Primes(928)=(P=(53,245,154,37,201,53,21,213,74,224,9,107))
    Primes(929)=(P=(39,162,192,162,15,188,187,59,190,209,7,173))
    Primes(930)=(P=(68,101,127,5,242,8,30,73,125,140,1,77))
    Primes(931)=(P=(71,116,204,172,235,5,115,119,230,242,64,55))
    Primes(932)=(P=(69,13,229,169,170,169,99,72,206,9,81,171))
    Primes(933)=(P=(78,116,14,73,49,138,139,96,98,208,29,19))
    Primes(934)=(P=(78,159,28,167,120,54,88,160,8,1,58,223))
    Primes(935)=(P=(108,102,194,6,121,234,1,20,181,135,45,177))
    Primes(936)=(P=(115,181,213,239,237,52,181,235,144,226,40,59))
    Primes(937)=(P=(78,142,161,175,8,82,58,247,54,81,0,143))
    Primes(938)=(P=(118,221,162,80,255,200,125,193,216,134,21,103))
    Primes(939)=(P=(67,85,9,166,10,23,143,218,54,6,146,119))
    Primes(940)=(P=(190,51,107,223,198,33,221,66,63,49,122,121))
    Primes(941)=(P=(239,89,102,189,249,182,109,165,148,214,150,115))
    Primes(942)=(P=(237,36,74,214,187,175,26,190,82,246,250,109))
    Primes(943)=(P=(206,20,22,19,120,4,72,99,99,83,199,31))
    Primes(944)=(P=(131,194,23,64,212,98,158,178,145,26,11,193))
    Primes(945)=(P=(141,190,230,180,21,17,94,221,202,129,21,211))
    Primes(946)=(P=(170,167,183,166,116,247,31,159,180,41,126,93))
    Primes(947)=(P=(230,145,168,182,136,171,159,97,192,221,75,253))
    Primes(948)=(P=(228,42,10,252,177,197,176,25,109,132,206,55))
    Primes(949)=(P=(136,2,105,97,172,74,228,202,106,116,175,239))
    Primes(950)=(P=(1,178,123,211,87,159,113,69,185,232,142,14,219))
    Primes(951)=(P=(1,60,104,87,121,47,114,131,227,220,76,125,9))
    Primes(952)=(P=(1,174,36,181,114,162,99,252,70,236,124,249,233))
    Primes(953)=(P=(1,80,193,11,250,178,142,60,116,218,3,171,211))
    Primes(954)=(P=(1,54,208,160,49,143,164,71,192,94,253,162,83))
    Primes(955)=(P=(1,213,78,19,150,129,102,252,240,244,21,62,47))
    Primes(956)=(P=(1,177,182,4,187,10,54,31,15,122,78,99,193))
    Primes(957)=(P=(1,151,60,125,79,53,196,178,210,11,130,220,79))
    Primes(958)=(P=(1,207,220,199,169,254,140,170,248,242,57,23,169))
    Primes(959)=(P=(1,229,126,192,131,234,33,211,65,238,87,196,1))
    Primes(960)=(P=(3,190,8,228,172,243,240,104,106,70,222,48,143))
    Primes(961)=(P=(2,80,25,27,200,56,187,221,34,87,111,25,9))
    Primes(962)=(P=(2,107,97,209,247,33,68,222,17,194,20,143,127))
    Primes(963)=(P=(3,237,59,36,120,87,44,82,235,25,204,197,245))
    Primes(964)=(P=(3,237,185,202,38,43,41,236,204,253,49,218,245))
    Primes(965)=(P=(3,250,214,11,60,150,152,220,213,67,84,94,85))
    Primes(966)=(P=(2,79,212,214,141,173,154,134,55,110,134,116,245))
    Primes(967)=(P=(3,8,54,170,175,48,110,9,63,240,142,210,239))
    Primes(968)=(P=(2,250,29,133,58,208,161,149,66,151,78,60,231))
    Primes(969)=(P=(3,189,109,127,74,152,186,160,133,62,145,181,227))
    Primes(970)=(P=(7,129,68,148,107,67,5,184,100,156,20,37,35))
    Primes(971)=(P=(7,96,230,154,237,11,10,48,243,227,52,133,101))
    Primes(972)=(P=(5,73,127,94,8,236,229,145,122,235,161,103,11))
    Primes(973)=(P=(7,209,87,121,234,117,254,61,120,71,3,220,147))
    Primes(974)=(P=(4,111,94,135,214,92,118,4,59,188,93,88,13))
    Primes(975)=(P=(7,150,161,183,178,93,72,244,104,165,40,128,13))
    Primes(976)=(P=(7,8,227,15,34,140,227,74,87,56,187,104,11))
    Primes(977)=(P=(6,179,5,100,247,4,175,115,152,237,228,22,83))
    Primes(978)=(P=(6,68,169,220,128,194,179,54,69,36,48,6,139))
    Primes(979)=(P=(5,34,101,47,127,56,50,232,133,41,128,85,33))
    Primes(980)=(P=(15,69,48,39,221,178,172,235,117,60,208,57,245))
    Primes(981)=(P=(10,175,93,73,142,239,158,130,19,130,217,61,99))
    Primes(982)=(P=(11,142,251,231,235,172,198,229,102,152,184,242,109))
    Primes(983)=(P=(14,234,43,213,75,255,184,0,96,252,123,54,241))
    Primes(984)=(P=(13,234,60,173,100,83,242,88,228,120,248,131,187))
    Primes(985)=(P=(8,69,216,246,183,118,27,183,155,136,83,102,147))
    Primes(986)=(P=(13,36,44,243,205,173,152,235,12,120,2,62,127))
    Primes(987)=(P=(15,7,190,16,92,178,121,178,10,183,2,233,217))
    Primes(988)=(P=(13,58,101,55,115,71,209,82,74,137,177,2,3))
    Primes(989)=(P=(11,45,142,79,212,16,162,5,10,184,155,147,21))
    Primes(990)=(P=(30,171,139,8,151,131,188,171,42,188,96,166,65))
    Primes(991)=(P=(30,153,6,93,35,253,192,206,115,99,117,154,181))
    Primes(992)=(P=(26,200,26,43,236,222,155,94,76,200,131,89,133))
    Primes(993)=(P=(21,22,45,67,253,116,45,132,46,219,120,220,7))
    Primes(994)=(P=(18,79,140,31,98,108,157,50,162,250,97,248,69))
    Primes(995)=(P=(23,156,84,243,174,136,115,244,197,62,129,204,115))
    Primes(996)=(P=(30,158,154,65,127,73,164,3,141,164,245,99,43))
    Primes(997)=(P=(17,63,146,86,47,199,124,128,213,238,242,86,5))
    Primes(998)=(P=(25,25,135,152,163,42,59,114,242,103,219,182,245))
    Primes(999)=(P=(21,218,81,44,199,189,183,186,41,52,109,234,91))
    Primes(1000)=(P=(63,168,55,49,131,95,155,54,95,57,47,132,25))
    Primes(1001)=(P=(63,38,199,45,38,111,71,199,90,101,219,190,239))
    Primes(1002)=(P=(62,255,222,96,251,148,216,11,159,126,181,112,19))
    Primes(1003)=(P=(60,19,187,17,73,176,210,202,201,80,62,128,203))
    Primes(1004)=(P=(47,200,186,199,245,128,85,101,173,53,43,54,177))
    Primes(1005)=(P=(41,28,147,211,59,164,110,122,127,51,192,54,151))
    Primes(1006)=(P=(41,35,66,252,165,61,76,226,209,192,42,8,105))
    Primes(1007)=(P=(55,18,80,231,242,246,52,247,57,235,236,6,111))
    Primes(1008)=(P=(60,133,200,254,105,123,136,226,227,168,87,45,253))
    Primes(1009)=(P=(47,123,212,123,126,209,26,152,241,76,153,12,91))
    Primes(1010)=(P=(84,41,184,23,168,232,161,6,98,111,187,145,113))
    Primes(1011)=(P=(118,129,189,135,223,241,132,125,195,110,85,98,231))
    Primes(1012)=(P=(121,50,227,45,192,159,127,208,62,143,119,170,55))
    Primes(1013)=(P=(86,245,102,54,140,45,58,118,225,210,25,137,27))
    Primes(1014)=(P=(127,189,61,34,22,254,176,146,238,114,198,91,61))
    Primes(1015)=(P=(67,120,85,150,165,94,126,230,43,234,147,221,209))
    Primes(1016)=(P=(83,161,42,18,54,228,190,174,198,101,69,69,127))
    Primes(1017)=(P=(102,184,19,26,50,195,15,163,46,125,213,195,141))
    Primes(1018)=(P=(73,42,17,149,43,102,162,95,26,137,205,67,249))
    Primes(1019)=(P=(65,197,78,19,158,171,32,98,49,193,63,236,125))
    Primes(1020)=(P=(178,251,46,189,237,255,87,68,60,55,24,210,249))
    Primes(1021)=(P=(200,50,9,140,92,118,76,240,170,21,82,207,253))
    Primes(1022)=(P=(154,135,127,226,209,66,190,110,193,144,33,95,129))
    Primes(1023)=(P=(251,50,105,115,40,198,254,190,178,44,0,140,111))
    Primes(1024)=(P=(215,222,131,165,248,11,164,188,208,171,251,16,177))
    Primes(1025)=(P=(168,9,82,42,81,195,161,152,187,89,8,169,59))
    Primes(1026)=(P=(233,164,125,42,31,146,101,233,203,188,45,208,113))
    Primes(1027)=(P=(133,103,166,122,25,203,66,233,114,147,22,212,51))
    Primes(1028)=(P=(173,240,152,182,15,174,213,9,143,163,142,203,19))
    Primes(1029)=(P=(211,74,217,0,152,171,124,66,178,134,175,62,235))
    Primes(1030)=(P=(1,172,236,73,169,164,149,173,248,168,227,220,131,1))
    Primes(1031)=(P=(1,216,171,127,135,1,190,254,39,185,179,223,204,57))
    Primes(1032)=(P=(1,178,110,166,137,201,201,97,147,122,46,103,188,5))
    Primes(1033)=(P=(1,181,154,157,196,54,178,88,231,173,127,193,108,21))
    Primes(1034)=(P=(1,221,44,195,108,21,8,46,137,76,113,56,10,105))
    Primes(1035)=(P=(1,58,168,36,73,178,160,182,137,103,255,157,4,241))
    Primes(1036)=(P=(1,103,113,224,230,133,226,235,11,199,194,80,127,141))
    Primes(1037)=(P=(1,191,221,18,223,121,138,107,111,138,194,78,103,247))
    Primes(1038)=(P=(1,183,95,91,6,237,74,55,162,85,185,12,174,237))
    Primes(1039)=(P=(1,201,31,189,130,105,242,141,13,232,238,54,140,165))
    Primes(1040)=(P=(3,212,30,85,38,5,198,28,141,18,139,164,3,225))
    Primes(1041)=(P=(2,138,56,239,154,187,98,21,153,238,205,146,32,165))
    Primes(1042)=(P=(3,242,63,130,155,231,183,254,164,140,92,184,103,37))
    Primes(1043)=(P=(3,249,56,162,199,53,65,222,86,81,96,158,211,83))
    Primes(1044)=(P=(3,86,220,42,190,80,31,43,157,205,31,230,99,171))
    Primes(1045)=(P=(2,55,140,39,156,44,5,184,142,206,5,197,3,41))
    Primes(1046)=(P=(2,101,240,255,134,206,226,49,25,193,82,233,31,225))
    Primes(1047)=(P=(2,137,213,137,80,89,90,156,49,50,114,206,66,133))
    Primes(1048)=(P=(2,116,167,49,4,220,2,22,231,143,236,17,140,57))
    Primes(1049)=(P=(3,81,133,99,237,41,52,181,157,186,10,73,217,107))
    Primes(1050)=(P=(7,1,131,177,216,109,30,175,97,209,6,200,93,231))
    Primes(1051)=(P=(5,171,99,98,81,116,56,112,239,146,243,81,235,141))
    Primes(1052)=(P=(7,86,112,167,76,59,220,247,79,99,59,70,225,151))
    Primes(1053)=(P=(6,187,101,166,82,158,104,166,15,7,241,138,107,183))
    Primes(1054)=(P=(7,3,189,104,38,29,104,92,9,212,65,80,39,53))
    Primes(1055)=(P=(7,64,210,88,238,206,219,220,123,90,151,202,193,205))
    Primes(1056)=(P=(6,87,74,174,215,168,2,89,142,172,202,197,236,77))
    Primes(1057)=(P=(4,152,37,44,58,96,244,129,133,6,138,10,194,73))
    Primes(1058)=(P=(6,44,114,250,222,224,96,17,233,90,100,177,21,43))
    Primes(1059)=(P=(7,211,50,215,253,238,248,182,201,251,136,30,93,113))
    Primes(1060)=(P=(9,53,246,216,53,227,161,13,47,252,128,116,242,41))
    Primes(1061)=(P=(14,194,83,202,45,84,49,98,127,178,75,94,4,5))
    Primes(1062)=(P=(9,96,140,6,65,98,55,43,193,54,147,12,45,79))
    Primes(1063)=(P=(12,252,206,194,17,234,176,63,204,119,175,158,57,9))
    Primes(1064)=(P=(15,144,167,92,30,5,170,23,40,195,98,157,52,151))
    Primes(1065)=(P=(11,247,115,91,50,36,83,152,206,208,190,65,241,77))
    Primes(1066)=(P=(11,208,194,132,171,36,147,174,206,54,46,21,110,237))
    Primes(1067)=(P=(13,173,191,156,18,112,232,48,140,209,207,135,109,41))
    Primes(1068)=(P=(11,72,131,224,195,81,0,73,91,189,100,66,9,131))
    Primes(1069)=(P=(12,39,215,149,9,233,114,82,180,153,189,230,201,1))
    Primes(1070)=(P=(23,213,44,78,217,141,239,255,224,81,167,31,246,133))
    Primes(1071)=(P=(26,38,74,142,249,105,244,43,156,119,105,56,23,13))
    Primes(1072)=(P=(24,226,37,103,232,192,206,142,8,24,215,173,142,113))
    Primes(1073)=(P=(26,244,121,95,7,9,44,233,243,138,138,242,129,175))
    Primes(1074)=(P=(24,233,123,253,121,159,195,13,31,127,30,174,57,19))
    Primes(1075)=(P=(18,50,124,71,251,118,113,131,191,192,7,220,161,215))
    Primes(1076)=(P=(24,91,74,170,191,97,0,195,99,183,134,126,54,85))
    Primes(1077)=(P=(21,47,62,206,188,122,162,19,243,118,138,186,197,105))
    Primes(1078)=(P=(17,236,226,224,211,158,158,39,4,109,58,188,39,185))
    Primes(1079)=(P=(26,81,76,89,73,112,98,56,89,56,239,94,151,61))
    Primes(1080)=(P=(32,14,40,65,35,42,191,202,162,246,92,33,236,171))
    Primes(1081)=(P=(55,117,87,250,54,54,72,135,64,207,9,239,102,53))
    Primes(1082)=(P=(45,193,32,25,203,55,46,13,20,11,179,249,45,25))
    Primes(1083)=(P=(62,71,255,209,193,14,154,8,31,84,66,131,150,65))
    Primes(1084)=(P=(37,90,5,119,129,128,210,186,50,174,108,216,183,149))
    Primes(1085)=(P=(36,116,248,159,104,1,205,103,152,96,163,121,132,205))
    Primes(1086)=(P=(36,197,110,198,16,93,175,224,84,219,191,70,6,233))
    Primes(1087)=(P=(38,67,113,48,91,166,112,28,229,235,246,35,40,5))
    Primes(1088)=(P=(44,99,17,142,249,143,44,55,48,67,120,81,171,249))
    Primes(1089)=(P=(35,122,243,23,248,59,207,68,67,125,30,206,50,21))
    Primes(1090)=(P=(90,230,151,17,25,103,71,13,111,143,188,17,10,155))
    Primes(1091)=(P=(81,170,56,160,129,16,64,176,157,72,81,141,166,83))
    Primes(1092)=(P=(127,3,194,245,96,244,31,10,86,106,127,58,194,103))
    Primes(1093)=(P=(111,241,233,26,91,223,1,255,195,91,77,28,250,249))
    Primes(1094)=(P=(79,154,21,96,177,233,21,237,227,153,129,108,239,87))
    Primes(1095)=(P=(114,76,226,108,253,193,210,254,163,134,179,126,242,213))
    Primes(1096)=(P=(79,14,201,190,97,5,37,63,33,93,30,79,0,157))
    Primes(1097)=(P=(84,108,224,221,130,222,162,77,176,18,176,127,132,161))
    Primes(1098)=(P=(97,232,4,192,133,145,147,58,219,213,96,115,48,219))
    Primes(1099)=(P=(112,133,147,44,213,91,145,6,55,11,3,1,221,97))
    Primes(1100)=(P=(228,134,94,100,65,76,98,193,201,81,110,103,128,185))
    Primes(1101)=(P=(168,151,50,187,112,189,21,158,135,70,157,3,1,99))
    Primes(1102)=(P=(248,88,96,21,79,113,232,124,164,103,120,28,34,39))
    Primes(1103)=(P=(156,120,223,140,245,215,82,117,210,252,5,79,219,153))
    Primes(1104)=(P=(181,53,170,132,140,172,232,27,113,202,99,254,144,233))
    Primes(1105)=(P=(221,72,174,167,98,209,86,246,143,94,141,12,213,201))
    Primes(1106)=(P=(249,226,24,205,7,45,66,165,90,101,14,179,64,151))
    Primes(1107)=(P=(226,202,164,224,228,85,108,224,84,21,253,227,121,169))
    Primes(1108)=(P=(193,12,129,4,234,146,78,134,97,103,82,131,100,143))
    Primes(1109)=(P=(176,167,221,233,14,185,26,81,60,100,55,115,93,11))
    Primes(1110)=(P=(1,162,243,177,55,151,42,108,28,184,244,149,235,228,197))
    Primes(1111)=(P=(1,168,193,136,255,41,98,58,121,245,91,246,156,142,147))
    Primes(1112)=(P=(1,185,239,61,78,197,193,237,204,82,47,207,30,69,181))
    Primes(1113)=(P=(1,93,186,98,128,159,176,76,37,111,52,222,215,140,33))
    Primes(1114)=(P=(1,67,243,207,91,197,228,144,39,97,191,117,51,221,205))
    Primes(1115)=(P=(1,50,188,157,247,89,56,221,168,38,144,118,127,14,163))
    Primes(1116)=(P=(1,31,7,49,234,147,101,165,45,153,77,135,40,157,105))
    Primes(1117)=(P=(1,3,237,136,95,128,143,45,2,239,83,132,165,76,179))
    Primes(1118)=(P=(1,219,244,214,149,76,217,3,194,60,77,74,134,12,25))
    Primes(1119)=(P=(1,180,222,16,174,176,144,163,163,42,131,28,18,32,161))
    Primes(1120)=(P=(3,107,224,251,200,254,139,153,85,165,217,86,145,94,225))
    Primes(1121)=(P=(2,40,251,45,114,229,11,181,85,104,40,86,135,109,205))
    Primes(1122)=(P=(3,102,3,234,99,93,24,231,40,253,190,40,155,125,107))
    Primes(1123)=(P=(2,168,100,102,3,105,147,141,129,6,94,145,235,22,67))
    Primes(1124)=(P=(3,140,38,43,249,118,245,120,103,44,150,121,199,29,155))
    Primes(1125)=(P=(3,147,249,44,80,149,239,3,53,136,247,119,150,29,13))
    Primes(1126)=(P=(2,111,41,215,55,113,167,253,189,64,255,239,66,199,247))
    Primes(1127)=(P=(2,19,211,81,211,156,23,198,82,129,141,133,92,232,241))
    Primes(1128)=(P=(2,252,173,201,22,88,27,208,134,229,128,93,105,244,195))
    Primes(1129)=(P=(2,147,76,7,67,176,18,37,43,145,221,135,161,239,237))
    Primes(1130)=(P=(5,219,171,82,209,169,87,165,128,36,4,153,190,212,233))
    Primes(1131)=(P=(6,110,195,90,37,32,127,245,108,207,196,106,41,79,193))
    Primes(1132)=(P=(7,107,139,175,179,109,162,81,201,21,214,86,27,30,149))
    Primes(1133)=(P=(4,106,156,10,186,157,90,12,216,236,114,211,103,207,161))
    Primes(1134)=(P=(5,57,123,14,218,85,88,162,229,33,117,193,197,201,59))
    Primes(1135)=(P=(5,47,40,14,51,3,12,238,177,22,115,86,216,11,41))
    Primes(1136)=(P=(5,194,211,65,61,209,106,94,67,249,76,85,85,61,155))
    Primes(1137)=(P=(4,50,97,108,169,187,65,66,57,71,189,203,79,234,25))
    Primes(1138)=(P=(6,114,9,175,201,163,221,120,120,190,80,221,221,68,27))
    Primes(1139)=(P=(6,228,234,58,194,244,1,120,250,247,116,53,105,137,213))
    Primes(1140)=(P=(10,111,250,197,71,81,58,76,91,193,215,181,222,95,145))
    Primes(1141)=(P=(8,52,126,235,140,145,4,67,2,39,140,42,122,101,251))
    Primes(1142)=(P=(9,18,150,240,240,207,167,207,87,213,47,183,243,125,47))
    Primes(1143)=(P=(14,71,130,202,248,204,126,2,10,87,30,84,210,137,133))
    Primes(1144)=(P=(14,85,161,161,13,12,18,8,194,47,149,251,166,169,141))
    Primes(1145)=(P=(9,76,234,171,220,3,72,253,14,233,65,137,110,42,183))
    Primes(1146)=(P=(13,83,173,32,133,157,38,220,141,36,8,209,226,181,89))
    Primes(1147)=(P=(15,249,150,59,175,197,4,75,87,254,140,197,128,30,87))
    Primes(1148)=(P=(15,193,129,225,229,149,18,189,50,254,123,28,243,195,163))
    Primes(1149)=(P=(15,75,208,145,187,119,208,237,127,79,88,239,140,140,37))
    Primes(1150)=(P=(22,203,156,96,177,84,208,67,64,233,143,0,26,175,73))
    Primes(1151)=(P=(21,46,253,154,228,66,87,23,25,8,235,27,217,18,85))
    Primes(1152)=(P=(18,68,132,247,32,240,241,170,204,17,51,50,152,139,133))
    Primes(1153)=(P=(29,18,162,254,45,189,72,111,132,204,112,73,85,27,199))
    Primes(1154)=(P=(21,232,172,14,2,129,232,23,25,238,161,139,214,124,247))
    Primes(1155)=(P=(29,25,23,118,187,215,43,225,227,22,157,87,25,222,109))
    Primes(1156)=(P=(31,241,216,194,246,199,190,155,174,145,180,62,184,239,123))
    Primes(1157)=(P=(27,102,152,168,234,84,72,240,138,187,101,131,197,210,209))
    Primes(1158)=(P=(16,80,191,5,116,10,100,88,216,74,93,245,215,186,127))
    Primes(1159)=(P=(28,115,221,147,142,166,44,175,102,159,8,181,224,206,145))
    Primes(1160)=(P=(40,247,103,185,94,154,224,12,250,244,113,228,139,25,25))
    Primes(1161)=(P=(43,162,38,231,57,94,55,65,123,39,140,158,245,35,131))
    Primes(1162)=(P=(33,33,88,130,214,86,144,95,111,45,3,63,157,119,237))
    Primes(1163)=(P=(38,82,152,69,122,8,16,222,234,194,0,182,38,28,57))
    Primes(1164)=(P=(57,58,244,84,113,130,157,55,118,255,47,12,200,212,161))
    Primes(1165)=(P=(38,242,238,188,42,136,106,232,151,92,121,224,92,101,35))
    Primes(1166)=(P=(63,114,31,84,135,29,200,230,42,129,81,71,221,149,73))
    Primes(1167)=(P=(37,0,80,99,176,96,167,172,198,179,39,237,58,230,193))
    Primes(1168)=(P=(52,163,168,150,168,194,31,197,105,116,61,118,29,173,109))
    Primes(1169)=(P=(55,122,101,55,255,177,81,187,184,151,52,142,133,226,193))
    Primes(1170)=(P=(83,96,192,139,177,99,44,45,55,45,71,100,146,37,137))
    Primes(1171)=(P=(74,126,127,34,49,202,19,225,13,223,71,205,35,234,87))
    Primes(1172)=(P=(73,222,186,187,48,216,56,96,160,27,34,160,48,36,249))
    Primes(1173)=(P=(77,226,136,118,184,11,238,70,161,205,93,201,217,119,93))
    Primes(1174)=(P=(126,219,19,157,113,171,208,14,214,208,124,198,134,163,19))
    Primes(1175)=(P=(116,61,159,66,123,90,156,217,217,156,104,127,79,101,195))
    Primes(1176)=(P=(103,230,148,139,153,3,234,252,96,71,198,87,111,166,221))
    Primes(1177)=(P=(125,50,97,107,52,91,224,59,16,190,35,164,19,14,121))
    Primes(1178)=(P=(93,56,185,7,131,240,209,14,168,39,73,197,98,89,5))
    Primes(1179)=(P=(104,167,64,93,114,240,172,213,6,56,173,248,218,43,7))
    Primes(1180)=(P=(191,39,92,59,2,0,138,206,102,236,83,221,252,44,181))
    Primes(1181)=(P=(204,58,44,180,173,60,243,220,1,34,242,11,110,209,67))
    Primes(1182)=(P=(227,127,192,130,20,128,246,192,185,82,236,133,12,7,137))
    Primes(1183)=(P=(144,220,134,189,128,206,238,52,70,91,239,246,5,189,65))
    Primes(1184)=(P=(175,67,148,158,244,129,125,174,105,68,203,185,228,198,197))
    Primes(1185)=(P=(178,18,148,76,65,182,240,114,66,172,208,123,120,245,39))
    Primes(1186)=(P=(145,80,69,69,26,247,106,246,13,85,124,106,115,120,137))
    Primes(1187)=(P=(138,78,128,89,241,104,92,135,93,230,12,194,119,172,247))
    Primes(1188)=(P=(132,222,203,132,93,213,137,190,110,2,15,73,45,93,133))
    Primes(1189)=(P=(199,238,69,155,204,131,30,17,201,61,247,40,155,202,237))
    Primes(1190)=(P=(1,183,111,34,212,6,207,162,60,240,202,178,242,57,204,29))
    Primes(1191)=(P=(1,233,250,179,245,115,62,133,166,93,242,166,75,182,3,77))
    Primes(1192)=(P=(1,174,144,50,67,183,91,193,196,239,223,211,76,128,250,67))
    Primes(1193)=(P=(1,125,10,226,134,110,120,33,212,159,188,159,244,7,146,99))
    Primes(1194)=(P=(1,116,218,41,99,158,35,88,25,197,195,229,230,55,35,215))
    Primes(1195)=(P=(1,16,118,105,47,127,128,156,213,61,47,233,15,10,174,225))
    Primes(1196)=(P=(1,95,69,246,123,209,42,254,194,117,212,99,142,189,188,161))
    Primes(1197)=(P=(1,104,233,248,80,172,167,75,203,96,180,14,36,246,67,87))
    Primes(1198)=(P=(1,9,255,98,157,239,0,202,99,97,156,177,183,9,45,39))
    Primes(1199)=(P=(1,139,186,163,183,44,22,134,63,50,20,93,138,48,155,27))
    Primes(1200)=(P=(2,128,89,91,146,231,103,251,211,163,33,23,88,138,176,3))
    Primes(1201)=(P=(2,90,156,212,253,53,103,197,211,173,109,125,44,182,224,73))
    Primes(1202)=(P=(2,62,23,111,58,232,163,211,93,94,96,182,34,219,182,9))
    Primes(1203)=(P=(2,15,93,229,170,98,141,16,155,52,36,197,34,165,215,183))
    Primes(1204)=(P=(2,57,63,236,135,191,185,78,139,72,134,224,103,87,216,77))
    Primes(1205)=(P=(2,88,96,60,90,9,86,54,12,241,227,136,142,66,169,101))
    Primes(1206)=(P=(3,204,189,237,192,73,82,2,172,58,131,59,143,222,248,147))
    Primes(1207)=(P=(2,243,116,164,131,68,101,174,217,32,213,253,251,78,80,131))
    Primes(1208)=(P=(3,72,103,11,19,197,128,238,175,206,39,59,116,95,92,93))
    Primes(1209)=(P=(3,254,12,2,233,46,138,15,72,5,202,142,53,27,210,183))
    Primes(1210)=(P=(5,224,64,183,198,244,115,28,19,179,197,55,140,193,182,157))
    Primes(1211)=(P=(6,114,99,107,188,182,144,112,168,143,206,189,103,1,80,245))
    Primes(1212)=(P=(6,116,65,23,153,136,54,222,89,172,215,189,101,229,67,199))
    Primes(1213)=(P=(4,9,186,239,112,56,144,54,86,94,2,211,126,54,201,11))
    Primes(1214)=(P=(5,64,2,134,214,0,102,211,24,34,238,81,4,54,181,105))
    Primes(1215)=(P=(7,163,192,111,194,215,31,131,17,81,137,1,19,199,91,33))
    Primes(1216)=(P=(7,33,88,53,180,189,76,209,62,227,169,175,244,91,166,177))
    Primes(1217)=(P=(7,2,219,109,4,103,203,158,187,239,230,108,131,97,89,123))
    Primes(1218)=(P=(4,166,102,88,221,216,68,209,140,145,161,112,70,192,141,97))
    Primes(1219)=(P=(7,248,189,87,121,149,209,115,3,60,178,62,218,4,97,121))
    Primes(1220)=(P=(9,142,75,12,142,47,204,137,14,146,103,65,229,202,220,81))
    Primes(1221)=(P=(15,194,74,5,14,198,165,108,118,204,14,244,230,198,243,197))
    Primes(1222)=(P=(13,17,137,26,84,160,105,227,104,7,46,208,135,208,232,255))
    Primes(1223)=(P=(11,36,252,237,142,244,88,29,170,184,131,61,138,194,87,127))
    Primes(1224)=(P=(11,216,115,56,113,21,27,221,147,179,93,0,132,119,105,3))
    Primes(1225)=(P=(15,85,244,134,112,200,63,79,73,89,228,214,44,45,232,169))
    Primes(1226)=(P=(11,181,106,193,127,57,219,165,185,23,145,115,251,188,88,195))
    Primes(1227)=(P=(15,148,131,97,74,75,214,28,204,160,195,39,27,23,223,205))
    Primes(1228)=(P=(13,209,179,79,22,105,181,88,129,40,46,37,120,230,86,219))
    Primes(1229)=(P=(8,51,88,107,236,250,29,21,131,46,40,18,67,109,152,43))
    Primes(1230)=(P=(18,90,75,51,32,79,86,136,252,201,153,206,24,69,7,133))
    Primes(1231)=(P=(28,248,144,154,212,148,93,118,151,39,132,66,233,80,115,251))
    Primes(1232)=(P=(30,165,83,107,36,232,245,85,19,214,229,49,13,161,183,217))
    Primes(1233)=(P=(22,138,10,112,158,163,68,196,6,53,107,144,42,108,242,85))
    Primes(1234)=(P=(26,62,248,224,17,185,66,208,141,87,93,94,104,176,153,79))
    Primes(1235)=(P=(30,247,110,217,236,78,7,172,170,222,229,29,169,30,51,21))
    Primes(1236)=(P=(22,122,239,216,195,193,184,125,151,35,132,33,66,0,228,85))
    Primes(1237)=(P=(19,114,234,142,195,93,219,8,8,230,25,67,87,72,98,67))
    Primes(1238)=(P=(25,23,171,95,200,216,106,28,56,208,124,53,176,110,70,51))
    Primes(1239)=(P=(24,104,155,26,18,34,105,42,221,128,172,83,77,74,25,219))
    Primes(1240)=(P=(46,103,33,163,74,203,102,87,177,96,56,41,50,170,156,217))
    Primes(1241)=(P=(60,44,27,111,56,219,177,161,1,51,181,129,149,101,187,193))
    Primes(1242)=(P=(47,117,185,49,53,142,184,190,79,102,220,46,219,55,232,149))
    Primes(1243)=(P=(61,180,179,237,165,235,234,246,189,127,132,131,19,102,15,5))
    Primes(1244)=(P=(52,77,174,17,231,134,106,57,102,176,88,234,232,232,174,61))
    Primes(1245)=(P=(52,209,94,136,65,150,222,86,155,128,250,200,94,34,87,119))
    Primes(1246)=(P=(62,44,224,193,162,146,80,51,12,249,111,127,97,183,32,145))
    Primes(1247)=(P=(40,145,27,57,32,20,243,26,73,100,5,29,125,60,116,43))
    Primes(1248)=(P=(32,189,141,90,205,44,145,184,158,239,139,116,152,220,14,183))
    Primes(1249)=(P=(59,3,128,252,87,101,171,192,75,74,48,139,220,91,7,199))
    Primes(1250)=(P=(117,110,16,41,205,184,233,127,132,23,203,23,80,192,33,157))
    Primes(1251)=(P=(88,234,122,100,36,184,57,17,105,142,158,30,148,90,72,111))
    Primes(1252)=(P=(83,209,227,95,115,250,42,114,110,161,27,174,224,86,26,189))
    Primes(1253)=(P=(102,99,124,169,211,94,36,222,37,142,191,169,74,181,32,51))
    Primes(1254)=(P=(74,241,179,241,134,72,182,117,77,85,26,109,117,196,10,23))
    Primes(1255)=(P=(86,2,11,125,166,105,203,14,198,148,80,65,165,235,2,247))
    Primes(1256)=(P=(124,253,37,12,226,244,218,24,192,69,57,61,37,127,138,33))
    Primes(1257)=(P=(75,235,17,220,204,191,138,60,104,69,208,117,18,239,135,59))
    Primes(1258)=(P=(243,170,250,231,244,79,20,98,183,253,45,214,16,74,118,229))
    Primes(1259)=(P=(214,1,175,198,181,146,188,235,225,186,128,195,82,68,148,193))
    Primes(1260)=(P=(173,143,12,137,208,68,7,85,93,22,221,176,100,14,0,55))
    Primes(1261)=(P=(200,41,243,91,131,116,26,72,122,99,213,20,24,68,178,119))
    Primes(1262)=(P=(163,172,194,237,52,50,86,107,125,253,61,112,24,130,189,207))
    Primes(1263)=(P=(170,223,56,25,28,57,44,215,202,57,73,239,121,139,86,87))
    Primes(1264)=(P=(153,118,85,170,7,57,199,70,78,81,179,245,206,29,169,51))
    Primes(1265)=(P=(209,186,224,89,31,148,190,170,160,165,85,180,172,128,27,195))
    Primes(1266)=(P=(130,238,124,63,112,134,0,110,6,49,103,64,176,197,252,23))
    Primes(1267)=(P=(192,241,87,10,47,148,53,12,212,231,149,108,98,123,48,187))
    Primes(1268)=(P=(224,131,247,119,141,116,26,32,147,67,197,218,168,137,44,195))
    Primes(1269)=(P=(175,178,230,249,202,185,151,211,151,22,96,169,198,45,41,71))

    KAT_AES={(
        /*
         * From FIPS-197.
         */
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "69c4e0d86a7b0430d8cdb78070b4c55a",

        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "dda97ca4864cdfe06eaf70a0ec0d7191",

        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",

        /*
         * From NIST validation suite (ECBVarTxt128.rsp).
         */
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "3ad78e726c1ec02b7ebfe92b23d9ec34",

        "00000000000000000000000000000000",
        "c0000000000000000000000000000000",
        "aae5939c8efdf2f04e60b9fe7117b2c2",

        "00000000000000000000000000000000",
        "e0000000000000000000000000000000",
        "f031d4d74f5dcbf39daaf8ca3af6e527",

        "00000000000000000000000000000000",
        "f0000000000000000000000000000000",
        "96d9fd5cc4f07441727df0f33e401a36",

        "00000000000000000000000000000000",
        "f8000000000000000000000000000000",
        "30ccdb044646d7e1f3ccea3dca08b8c0",

        "00000000000000000000000000000000",
        "fc000000000000000000000000000000",
        "16ae4ce5042a67ee8e177b7c587ecc82",

        "00000000000000000000000000000000",
        "fe000000000000000000000000000000",
        "b6da0bb11a23855d9c5cb1b4c6412e0a",

        "00000000000000000000000000000000",
        "ff000000000000000000000000000000",
        "db4f1aa530967d6732ce4715eb0ee24b",

        "00000000000000000000000000000000",
        "ff800000000000000000000000000000",
        "a81738252621dd180a34f3455b4baa2f",

        "00000000000000000000000000000000",
        "ffc00000000000000000000000000000",
        "77e2b508db7fd89234caf7939ee5621a",

        "00000000000000000000000000000000",
        "ffe00000000000000000000000000000",
        "b8499c251f8442ee13f0933b688fcd19",

        "00000000000000000000000000000000",
        "fff00000000000000000000000000000",
        "965135f8a81f25c9d630b17502f68e53",

        "00000000000000000000000000000000",
        "fff80000000000000000000000000000",
        "8b87145a01ad1c6cede995ea3670454f",

        "00000000000000000000000000000000",
        "fffc0000000000000000000000000000",
        "8eae3b10a0c8ca6d1d3b0fa61e56b0b2",

        "00000000000000000000000000000000",
        "fffe0000000000000000000000000000",
        "64b4d629810fda6bafdf08f3b0d8d2c5",

        "00000000000000000000000000000000",
        "ffff0000000000000000000000000000",
        "d7e5dbd3324595f8fdc7d7c571da6c2a",

        "00000000000000000000000000000000",
        "ffff8000000000000000000000000000",
        "f3f72375264e167fca9de2c1527d9606",

        "00000000000000000000000000000000",
        "ffffc000000000000000000000000000",
        "8ee79dd4f401ff9b7ea945d86666c13b",

        "00000000000000000000000000000000",
        "ffffe000000000000000000000000000",
        "dd35cea2799940b40db3f819cb94c08b",

        "00000000000000000000000000000000",
        "fffff000000000000000000000000000",
        "6941cb6b3e08c2b7afa581ebdd607b87",

        "00000000000000000000000000000000",
        "fffff800000000000000000000000000",
        "2c20f439f6bb097b29b8bd6d99aad799",

        "00000000000000000000000000000000",
        "fffffc00000000000000000000000000",
        "625d01f058e565f77ae86378bd2c49b3",

        "00000000000000000000000000000000",
        "fffffe00000000000000000000000000",
        "c0b5fd98190ef45fbb4301438d095950",

        "00000000000000000000000000000000",
        "ffffff00000000000000000000000000",
        "13001ff5d99806efd25da34f56be854b",

        "00000000000000000000000000000000",
        "ffffff80000000000000000000000000",
        "3b594c60f5c8277a5113677f94208d82",

        "00000000000000000000000000000000",
        "ffffffc0000000000000000000000000",
        "e9c0fc1818e4aa46bd2e39d638f89e05",

        "00000000000000000000000000000000",
        "ffffffe0000000000000000000000000",
        "f8023ee9c3fdc45a019b4e985c7e1a54",

        "00000000000000000000000000000000",
        "fffffff0000000000000000000000000",
        "35f40182ab4662f3023baec1ee796b57",

        "00000000000000000000000000000000",
        "fffffff8000000000000000000000000",
        "3aebbad7303649b4194a6945c6cc3694",

        "00000000000000000000000000000000",
        "fffffffc000000000000000000000000",
        "a2124bea53ec2834279bed7f7eb0f938",

        "00000000000000000000000000000000",
        "fffffffe000000000000000000000000",
        "b9fb4399fa4facc7309e14ec98360b0a",

        "00000000000000000000000000000000",
        "ffffffff000000000000000000000000",
        "c26277437420c5d634f715aea81a9132",

        "00000000000000000000000000000000",
        "ffffffff800000000000000000000000",
        "171a0e1b2dd424f0e089af2c4c10f32f",

        "00000000000000000000000000000000",
        "ffffffffc00000000000000000000000",
        "7cadbe402d1b208fe735edce00aee7ce",

        "00000000000000000000000000000000",
        "ffffffffe00000000000000000000000",
        "43b02ff929a1485af6f5c6d6558baa0f",

        "00000000000000000000000000000000",
        "fffffffff00000000000000000000000",
        "092faacc9bf43508bf8fa8613ca75dea",

        "00000000000000000000000000000000",
        "fffffffff80000000000000000000000",
        "cb2bf8280f3f9742c7ed513fe802629c",

        "00000000000000000000000000000000",
        "fffffffffc0000000000000000000000",
        "215a41ee442fa992a6e323986ded3f68",

        "00000000000000000000000000000000",
        "fffffffffe0000000000000000000000",
        "f21e99cf4f0f77cea836e11a2fe75fb1",

        "00000000000000000000000000000000",
        "ffffffffff0000000000000000000000",
        "95e3a0ca9079e646331df8b4e70d2cd6",

        "00000000000000000000000000000000",
        "ffffffffff8000000000000000000000",
        "4afe7f120ce7613f74fc12a01a828073",

        "00000000000000000000000000000000",
        "ffffffffffc000000000000000000000",
        "827f000e75e2c8b9d479beed913fe678",

        "00000000000000000000000000000000",
        "ffffffffffe000000000000000000000",
        "35830c8e7aaefe2d30310ef381cbf691",

        "00000000000000000000000000000000",
        "fffffffffff000000000000000000000",
        "191aa0f2c8570144f38657ea4085ebe5",

        "00000000000000000000000000000000",
        "fffffffffff800000000000000000000",
        "85062c2c909f15d9269b6c18ce99c4f0",

        "00000000000000000000000000000000",
        "fffffffffffc00000000000000000000",
        "678034dc9e41b5a560ed239eeab1bc78",

        "00000000000000000000000000000000",
        "fffffffffffe00000000000000000000",
        "c2f93a4ce5ab6d5d56f1b93cf19911c1",

        "00000000000000000000000000000000",
        "ffffffffffff00000000000000000000",
        "1c3112bcb0c1dcc749d799743691bf82",

        "00000000000000000000000000000000",
        "ffffffffffff80000000000000000000",
        "00c55bd75c7f9c881989d3ec1911c0d4",

        "00000000000000000000000000000000",
        "ffffffffffffc0000000000000000000",
        "ea2e6b5ef182b7dff3629abd6a12045f",

        "00000000000000000000000000000000",
        "ffffffffffffe0000000000000000000",
        "22322327e01780b17397f24087f8cc6f",

        "00000000000000000000000000000000",
        "fffffffffffff0000000000000000000",
        "c9cacb5cd11692c373b2411768149ee7",

        "00000000000000000000000000000000",
        "fffffffffffff8000000000000000000",
        "a18e3dbbca577860dab6b80da3139256",

        "00000000000000000000000000000000",
        "fffffffffffffc000000000000000000",
        "79b61c37bf328ecca8d743265a3d425c",

        "00000000000000000000000000000000",
        "fffffffffffffe000000000000000000",
        "d2d99c6bcc1f06fda8e27e8ae3f1ccc7",

        "00000000000000000000000000000000",
        "ffffffffffffff000000000000000000",
        "1bfd4b91c701fd6b61b7f997829d663b",

        "00000000000000000000000000000000",
        "ffffffffffffff800000000000000000",
        "11005d52f25f16bdc9545a876a63490a",

        "00000000000000000000000000000000",
        "ffffffffffffffc00000000000000000",
        "3a4d354f02bb5a5e47d39666867f246a",

        "00000000000000000000000000000000",
        "ffffffffffffffe00000000000000000",
        "d451b8d6e1e1a0ebb155fbbf6e7b7dc3",

        "00000000000000000000000000000000",
        "fffffffffffffff00000000000000000",
        "6898d4f42fa7ba6a10ac05e87b9f2080",

        "00000000000000000000000000000000",
        "fffffffffffffff80000000000000000",
        "b611295e739ca7d9b50f8e4c0e754a3f",

        "00000000000000000000000000000000",
        "fffffffffffffffc0000000000000000",
        "7d33fc7d8abe3ca1936759f8f5deaf20",

        "00000000000000000000000000000000",
        "fffffffffffffffe0000000000000000",
        "3b5e0f566dc96c298f0c12637539b25c",

        "00000000000000000000000000000000",
        "ffffffffffffffff0000000000000000",
        "f807c3e7985fe0f5a50e2cdb25c5109e",

        "00000000000000000000000000000000",
        "ffffffffffffffff8000000000000000",
        "41f992a856fb278b389a62f5d274d7e9",

        "00000000000000000000000000000000",
        "ffffffffffffffffc000000000000000",
        "10d3ed7a6fe15ab4d91acbc7d0767ab1",

        "00000000000000000000000000000000",
        "ffffffffffffffffe000000000000000",
        "21feecd45b2e675973ac33bf0c5424fc",

        "00000000000000000000000000000000",
        "fffffffffffffffff000000000000000",
        "1480cb3955ba62d09eea668f7c708817",

        "00000000000000000000000000000000",
        "fffffffffffffffff800000000000000",
        "66404033d6b72b609354d5496e7eb511",

        "00000000000000000000000000000000",
        "fffffffffffffffffc00000000000000",
        "1c317a220a7d700da2b1e075b00266e1",

        "00000000000000000000000000000000",
        "fffffffffffffffffe00000000000000",
        "ab3b89542233f1271bf8fd0c0f403545",

        "00000000000000000000000000000000",
        "ffffffffffffffffff00000000000000",
        "d93eae966fac46dca927d6b114fa3f9e",

        "00000000000000000000000000000000",
        "ffffffffffffffffff80000000000000",
        "1bdec521316503d9d5ee65df3ea94ddf",

        "00000000000000000000000000000000",
        "ffffffffffffffffffc0000000000000",
        "eef456431dea8b4acf83bdae3717f75f",

        "00000000000000000000000000000000",
        "ffffffffffffffffffe0000000000000",
        "06f2519a2fafaa596bfef5cfa15c21b9",

        "00000000000000000000000000000000",
        "fffffffffffffffffff0000000000000",
        "251a7eac7e2fe809e4aa8d0d7012531a",

        "00000000000000000000000000000000",
        "fffffffffffffffffff8000000000000",
        "3bffc16e4c49b268a20f8d96a60b4058",

        "00000000000000000000000000000000",
        "fffffffffffffffffffc000000000000",
        "e886f9281999c5bb3b3e8862e2f7c988",

        "00000000000000000000000000000000",
        "fffffffffffffffffffe000000000000",
        "563bf90d61beef39f48dd625fcef1361",

        "00000000000000000000000000000000",
        "ffffffffffffffffffff000000000000",
        "4d37c850644563c69fd0acd9a049325b",

        "00000000000000000000000000000000",
        "ffffffffffffffffffff800000000000",
        "b87c921b91829ef3b13ca541ee1130a6",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffc00000000000",
        "2e65eb6b6ea383e109accce8326b0393",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffe00000000000",
        "9ca547f7439edc3e255c0f4d49aa8990",

        "00000000000000000000000000000000",
        "fffffffffffffffffffff00000000000",
        "a5e652614c9300f37816b1f9fd0c87f9",

        "00000000000000000000000000000000",
        "fffffffffffffffffffff80000000000",
        "14954f0b4697776f44494fe458d814ed",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffc0000000000",
        "7c8d9ab6c2761723fe42f8bb506cbcf7",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffe0000000000",
        "db7e1932679fdd99742aab04aa0d5a80",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffff0000000000",
        "4c6a1c83e568cd10f27c2d73ded19c28",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffff8000000000",
        "90ecbe6177e674c98de412413f7ac915",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffc000000000",
        "90684a2ac55fe1ec2b8ebd5622520b73",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffe000000000",
        "7472f9a7988607ca79707795991035e6",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffff000000000",
        "56aff089878bf3352f8df172a3ae47d8",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffff800000000",
        "65c0526cbe40161b8019a2a3171abd23",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffc00000000",
        "377be0be33b4e3e310b4aabda173f84f",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffe00000000",
        "9402e9aa6f69de6504da8d20c4fcaa2f",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffff00000000",
        "123c1f4af313ad8c2ce648b2e71fb6e1",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffff80000000",
        "1ffc626d30203dcdb0019fb80f726cf4",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffc0000000",
        "76da1fbe3a50728c50fd2e621b5ad885",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffe0000000",
        "082eb8be35f442fb52668e16a591d1d6",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffff0000000",
        "e656f9ecf5fe27ec3e4a73d00c282fb3",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffff8000000",
        "2ca8209d63274cd9a29bb74bcd77683a",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffc000000",
        "79bf5dce14bb7dd73a8e3611de7ce026",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffe000000",
        "3c849939a5d29399f344c4a0eca8a576",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffff000000",
        "ed3c0a94d59bece98835da7aa4f07ca2",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffff800000",
        "63919ed4ce10196438b6ad09d99cd795",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffc00000",
        "7678f3a833f19fea95f3c6029e2bc610",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffe00000",
        "3aa426831067d36b92be7c5f81c13c56",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffff00000",
        "9272e2d2cdd11050998c845077a30ea0",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffff80000",
        "088c4b53f5ec0ff814c19adae7f6246c",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffc0000",
        "4010a5e401fdf0a0354ddbcc0d012b17",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffe0000",
        "a87a385736c0a6189bd6589bd8445a93",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffff0000",
        "545f2b83d9616dccf60fa9830e9cd287",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffff8000",
        "4b706f7f92406352394037a6d4f4688d",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffc000",
        "b7972b3941c44b90afa7b264bfba7387",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffe000",
        "6f45732cf10881546f0fd23896d2bb60",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffff000",
        "2e3579ca15af27f64b3c955a5bfc30ba",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffff800",
        "34a2c5a91ae2aec99b7d1b5fa6780447",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffc00",
        "a4d6616bd04f87335b0e53351227a9ee",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffe00",
        "7f692b03945867d16179a8cefc83ea3f",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffff00",
        "3bd141ee84a0e6414a26e7a4f281f8a2",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffff80",
        "d1788f572d98b2b16ec5d5f3922b99bc",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffc0",
        "0833ff6f61d98a57b288e8c3586b85a6",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffe0",
        "8568261797de176bf0b43becc6285afb",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff0",
        "f9b0fda0c4a898f5b9e6f661c4ce4d07",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff8",
        "8ade895913685c67c5269f8aae42983e",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffc",
        "39bde67d5c8ed8a8b1c37eb8fa9f5ac0",

        "00000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffe",
        "5c005e72c1418c44f569f2ea33ba54f3",

        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "3f5b8cc9ea855a0afa7347d23e8d664e",

        /*
         * From NIST validation suite (ECBVarTxt192.rsp).
         */
        "000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "6cd02513e8d4dc986b4afe087a60bd0c",

        "000000000000000000000000000000000000000000000000",
        "c0000000000000000000000000000000",
        "2ce1f8b7e30627c1c4519eada44bc436",

        "000000000000000000000000000000000000000000000000",
        "e0000000000000000000000000000000",
        "9946b5f87af446f5796c1fee63a2da24",

        "000000000000000000000000000000000000000000000000",
        "f0000000000000000000000000000000",
        "2a560364ce529efc21788779568d5555",

        "000000000000000000000000000000000000000000000000",
        "f8000000000000000000000000000000",
        "35c1471837af446153bce55d5ba72a0a",

        "000000000000000000000000000000000000000000000000",
        "fc000000000000000000000000000000",
        "ce60bc52386234f158f84341e534cd9e",

        "000000000000000000000000000000000000000000000000",
        "fe000000000000000000000000000000",
        "8c7c27ff32bcf8dc2dc57c90c2903961",

        "000000000000000000000000000000000000000000000000",
        "ff000000000000000000000000000000",
        "32bb6a7ec84499e166f936003d55a5bb",

        "000000000000000000000000000000000000000000000000",
        "ff800000000000000000000000000000",
        "a5c772e5c62631ef660ee1d5877f6d1b",

        "000000000000000000000000000000000000000000000000",
        "ffc00000000000000000000000000000",
        "030d7e5b64f380a7e4ea5387b5cd7f49",

        "000000000000000000000000000000000000000000000000",
        "ffe00000000000000000000000000000",
        "0dc9a2610037009b698f11bb7e86c83e",

        "000000000000000000000000000000000000000000000000",
        "fff00000000000000000000000000000",
        "0046612c766d1840c226364f1fa7ed72",

        "000000000000000000000000000000000000000000000000",
        "fff80000000000000000000000000000",
        "4880c7e08f27befe78590743c05e698b",

        "000000000000000000000000000000000000000000000000",
        "fffc0000000000000000000000000000",
        "2520ce829a26577f0f4822c4ecc87401",

        "000000000000000000000000000000000000000000000000",
        "fffe0000000000000000000000000000",
        "8765e8acc169758319cb46dc7bcf3dca",

        "000000000000000000000000000000000000000000000000",
        "ffff0000000000000000000000000000",
        "e98f4ba4f073df4baa116d011dc24a28",

        "000000000000000000000000000000000000000000000000",
        "ffff8000000000000000000000000000",
        "f378f68c5dbf59e211b3a659a7317d94",

        "000000000000000000000000000000000000000000000000",
        "ffffc000000000000000000000000000",
        "283d3b069d8eb9fb432d74b96ca762b4",

        "000000000000000000000000000000000000000000000000",
        "ffffe000000000000000000000000000",
        "a7e1842e8a87861c221a500883245c51",

        "000000000000000000000000000000000000000000000000",
        "fffff000000000000000000000000000",
        "77aa270471881be070fb52c7067ce732",

        "000000000000000000000000000000000000000000000000",
        "fffff800000000000000000000000000",
        "01b0f476d484f43f1aeb6efa9361a8ac",

        "000000000000000000000000000000000000000000000000",
        "fffffc00000000000000000000000000",
        "1c3a94f1c052c55c2d8359aff2163b4f",

        "000000000000000000000000000000000000000000000000",
        "fffffe00000000000000000000000000",
        "e8a067b604d5373d8b0f2e05a03b341b",

        "000000000000000000000000000000000000000000000000",
        "ffffff00000000000000000000000000",
        "a7876ec87f5a09bfea42c77da30fd50e",

        "000000000000000000000000000000000000000000000000",
        "ffffff80000000000000000000000000",
        "0cf3e9d3a42be5b854ca65b13f35f48d",

        "000000000000000000000000000000000000000000000000",
        "ffffffc0000000000000000000000000",
        "6c62f6bbcab7c3e821c9290f08892dda",

        "000000000000000000000000000000000000000000000000",
        "ffffffe0000000000000000000000000",
        "7f5e05bd2068738196fee79ace7e3aec",

        "000000000000000000000000000000000000000000000000",
        "fffffff0000000000000000000000000",
        "440e0d733255cda92fb46e842fe58054",

        "000000000000000000000000000000000000000000000000",
        "fffffff8000000000000000000000000",
        "aa5d5b1c4ea1b7a22e5583ac2e9ed8a7",

        "000000000000000000000000000000000000000000000000",
        "fffffffc000000000000000000000000",
        "77e537e89e8491e8662aae3bc809421d",

        "000000000000000000000000000000000000000000000000",
        "fffffffe000000000000000000000000",
        "997dd3e9f1598bfa73f75973f7e93b76",

        "000000000000000000000000000000000000000000000000",
        "ffffffff000000000000000000000000",
        "1b38d4f7452afefcb7fc721244e4b72e",

        "000000000000000000000000000000000000000000000000",
        "ffffffff800000000000000000000000",
        "0be2b18252e774dda30cdda02c6906e3",

        "000000000000000000000000000000000000000000000000",
        "ffffffffc00000000000000000000000",
        "d2695e59c20361d82652d7d58b6f11b2",

        "000000000000000000000000000000000000000000000000",
        "ffffffffe00000000000000000000000",
        "902d88d13eae52089abd6143cfe394e9",

        "000000000000000000000000000000000000000000000000",
        "fffffffff00000000000000000000000",
        "d49bceb3b823fedd602c305345734bd2",

        "000000000000000000000000000000000000000000000000",
        "fffffffff80000000000000000000000",
        "707b1dbb0ffa40ef7d95def421233fae",

        "000000000000000000000000000000000000000000000000",
        "fffffffffc0000000000000000000000",
        "7ca0c1d93356d9eb8aa952084d75f913",

        "000000000000000000000000000000000000000000000000",
        "fffffffffe0000000000000000000000",
        "f2cbf9cb186e270dd7bdb0c28febc57d",

        "000000000000000000000000000000000000000000000000",
        "ffffffffff0000000000000000000000",
        "c94337c37c4e790ab45780bd9c3674a0",

        "000000000000000000000000000000000000000000000000",
        "ffffffffff8000000000000000000000",
        "8e3558c135252fb9c9f367ed609467a1",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffc000000000000000000000",
        "1b72eeaee4899b443914e5b3a57fba92",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffe000000000000000000000",
        "011865f91bc56868d051e52c9efd59b7",

        "000000000000000000000000000000000000000000000000",
        "fffffffffff000000000000000000000",
        "e4771318ad7a63dd680f6e583b7747ea",

        "000000000000000000000000000000000000000000000000",
        "fffffffffff800000000000000000000",
        "61e3d194088dc8d97e9e6db37457eac5",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffc00000000000000000000",
        "36ff1ec9ccfbc349e5d356d063693ad6",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffe00000000000000000000",
        "3cc9e9a9be8cc3f6fb2ea24088e9bb19",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffff00000000000000000000",
        "1ee5ab003dc8722e74905d9a8fe3d350",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffff80000000000000000000",
        "245339319584b0a412412869d6c2eada",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffc0000000000000000000",
        "7bd496918115d14ed5380852716c8814",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffe0000000000000000000",
        "273ab2f2b4a366a57d582a339313c8b1",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffff0000000000000000000",
        "113365a9ffbe3b0ca61e98507554168b",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffff8000000000000000000",
        "afa99c997ac478a0dea4119c9e45f8b1",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffc000000000000000000",
        "9216309a7842430b83ffb98638011512",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffe000000000000000000",
        "62abc792288258492a7cb45145f4b759",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffff000000000000000000",
        "534923c169d504d7519c15d30e756c50",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffff800000000000000000",
        "fa75e05bcdc7e00c273fa33f6ee441d2",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffc00000000000000000",
        "7d350fa6057080f1086a56b17ec240db",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffe00000000000000000",
        "f34e4a6324ea4a5c39a661c8fe5ada8f",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffff00000000000000000",
        "0882a16f44088d42447a29ac090ec17e",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffff80000000000000000",
        "3a3c15bfc11a9537c130687004e136ee",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffc0000000000000000",
        "22c0a7678dc6d8cf5c8a6d5a9960767c",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffe0000000000000000",
        "b46b09809d68b9a456432a79bdc2e38c",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffff0000000000000000",
        "93baaffb35fbe739c17c6ac22eecf18f",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffff8000000000000000",
        "c8aa80a7850675bc007c46df06b49868",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffc000000000000000",
        "12c6f3877af421a918a84b775858021d",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffe000000000000000",
        "33f123282c5d633924f7d5ba3f3cab11",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffff000000000000000",
        "a8f161002733e93ca4527d22c1a0c5bb",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffff800000000000000",
        "b72f70ebf3e3fda23f508eec76b42c02",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffc00000000000000",
        "6a9d965e6274143f25afdcfc88ffd77c",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffe00000000000000",
        "a0c74fd0b9361764ce91c5200b095357",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffff00000000000000",
        "091d1fdc2bd2c346cd5046a8c6209146",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffff80000000000000",
        "e2a37580116cfb71856254496ab0aca8",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffc0000000000000",
        "e0b3a00785917c7efc9adba322813571",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffe0000000000000",
        "733d41f4727b5ef0df4af4cf3cffa0cb",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffff0000000000000",
        "a99ebb030260826f981ad3e64490aa4f",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffff8000000000000",
        "73f34c7d3eae5e80082c1647524308ee",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffc000000000000",
        "40ebd5ad082345b7a2097ccd3464da02",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffe000000000000",
        "7cc4ae9a424b2cec90c97153c2457ec5",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffff000000000000",
        "54d632d03aba0bd0f91877ebdd4d09cb",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffff800000000000",
        "d3427be7e4d27cd54f5fe37b03cf0897",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffc00000000000",
        "b2099795e88cc158fd75ea133d7e7fbe",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffe00000000000",
        "a6cae46fb6fadfe7a2c302a34242817b",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffff00000000000",
        "026a7024d6a902e0b3ffccbaa910cc3f",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffff80000000000",
        "156f07767a85a4312321f63968338a01",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffc0000000000",
        "15eec9ebf42b9ca76897d2cd6c5a12e2",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffe0000000000",
        "db0d3a6fdcc13f915e2b302ceeb70fd8",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffff0000000000",
        "71dbf37e87a2e34d15b20e8f10e48924",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffff8000000000",
        "c745c451e96ff3c045e4367c833e3b54",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffc000000000",
        "340da09c2dd11c3b679d08ccd27dd595",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffe000000000",
        "8279f7c0c2a03ee660c6d392db025d18",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffff000000000",
        "a4b2c7d8eba531ff47c5041a55fbd1ec",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffff800000000",
        "74569a2ca5a7bd5131ce8dc7cbfbf72f",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffc00000000",
        "3713da0c0219b63454035613b5a403dd",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffe00000000",
        "8827551ddcc9df23fa72a3de4e9f0b07",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffff00000000",
        "2e3febfd625bfcd0a2c06eb460da1732",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffff80000000",
        "ee82e6ba488156f76496311da6941deb",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffc0000000",
        "4770446f01d1f391256e85a1b30d89d3",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffe0000000",
        "af04b68f104f21ef2afb4767cf74143c",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffff0000000",
        "cf3579a9ba38c8e43653173e14f3a4c6",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffff8000000",
        "b3bba904f4953e09b54800af2f62e7d4",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffc000000",
        "fc4249656e14b29eb9c44829b4c59a46",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffe000000",
        "9b31568febe81cfc2e65af1c86d1a308",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffff000000",
        "9ca09c25f273a766db98a480ce8dfedc",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffff800000",
        "b909925786f34c3c92d971883c9fbedf",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffc00000",
        "82647f1332fe570a9d4d92b2ee771d3b",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffe00000",
        "3604a7e80832b3a99954bca6f5b9f501",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffff00000",
        "884607b128c5de3ab39a529a1ef51bef",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffff80000",
        "670cfa093d1dbdb2317041404102435e",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffc0000",
        "7a867195f3ce8769cbd336502fbb5130",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffe0000",
        "52efcf64c72b2f7ca5b3c836b1078c15",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffff0000",
        "4019250f6eefb2ac5ccbcae044e75c7e",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffff8000",
        "022c4f6f5a017d292785627667ddef24",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffc000",
        "e9c21078a2eb7e03250f71000fa9e3ed",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffe000",
        "a13eaeeb9cd391da4e2b09490b3e7fad",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffff000",
        "c958a171dca1d4ed53e1af1d380803a9",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffff800",
        "21442e07a110667f2583eaeeee44dc8c",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffc00",
        "59bbb353cf1dd867a6e33737af655e99",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffe00",
        "43cd3b25375d0ce41087ff9fe2829639",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffff00",
        "6b98b17e80d1118e3516bd768b285a84",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffff80",
        "ae47ed3676ca0c08deea02d95b81db58",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffc0",
        "34ec40dc20413795ed53628ea748720b",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffe0",
        "4dc68163f8e9835473253542c8a65d46",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff0",
        "2aabb999f43693175af65c6c612c46fb",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff8",
        "e01f94499dac3547515c5b1d756f0f58",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffc",
        "9d12435a46480ce00ea349f71799df9a",

        "000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffe",
        "cef41d16d266bdfe46938ad7884cc0cf",

        "000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "b13db4da1f718bc6904797c82bcf2d32",

        /*
         * From NIST validation suite (ECBVarTxt256.rsp).
         */
        "0000000000000000000000000000000000000000000000000000000000000000",
        "80000000000000000000000000000000",
        "ddc6bf790c15760d8d9aeb6f9a75fd4e",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "c0000000000000000000000000000000",
        "0a6bdc6d4c1e6280301fd8e97ddbe601",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "e0000000000000000000000000000000",
        "9b80eefb7ebe2d2b16247aa0efc72f5d",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "f0000000000000000000000000000000",
        "7f2c5ece07a98d8bee13c51177395ff7",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "f8000000000000000000000000000000",
        "7818d800dcf6f4be1e0e94f403d1e4c2",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fc000000000000000000000000000000",
        "e74cd1c92f0919c35a0324123d6177d3",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fe000000000000000000000000000000",
        "8092a4dcf2da7e77e93bdd371dfed82e",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ff000000000000000000000000000000",
        "49af6b372135acef10132e548f217b17",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ff800000000000000000000000000000",
        "8bcd40f94ebb63b9f7909676e667f1e7",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffc00000000000000000000000000000",
        "fe1cffb83f45dcfb38b29be438dbd3ab",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffe00000000000000000000000000000",
        "0dc58a8d886623705aec15cb1e70dc0e",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fff00000000000000000000000000000",
        "c218faa16056bd0774c3e8d79c35a5e4",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fff80000000000000000000000000000",
        "047bba83f7aa841731504e012208fc9e",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffc0000000000000000000000000000",
        "dc8f0e4915fd81ba70a331310882f6da",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffe0000000000000000000000000000",
        "1569859ea6b7206c30bf4fd0cbfac33c",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffff0000000000000000000000000000",
        "300ade92f88f48fa2df730ec16ef44cd",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffff8000000000000000000000000000",
        "1fe6cc3c05965dc08eb0590c95ac71d0",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffc000000000000000000000000000",
        "59e858eaaa97fec38111275b6cf5abc0",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffe000000000000000000000000000",
        "2239455e7afe3b0616100288cc5a723b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffff000000000000000000000000000",
        "3ee500c5c8d63479717163e55c5c4522",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffff800000000000000000000000000",
        "d5e38bf15f16d90e3e214041d774daa8",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffc00000000000000000000000000",
        "b1f4066e6f4f187dfe5f2ad1b17819d0",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffe00000000000000000000000000",
        "6ef4cc4de49b11065d7af2909854794a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffff00000000000000000000000000",
        "ac86bc606b6640c309e782f232bf367f",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffff80000000000000000000000000",
        "36aff0ef7bf3280772cf4cac80a0d2b2",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffc0000000000000000000000000",
        "1f8eedea0f62a1406d58cfc3ecea72cf",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffe0000000000000000000000000",
        "abf4154a3375a1d3e6b1d454438f95a6",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffff0000000000000000000000000",
        "96f96e9d607f6615fc192061ee648b07",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffff8000000000000000000000000",
        "cf37cdaaa0d2d536c71857634c792064",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffc000000000000000000000000",
        "fbd6640c80245c2b805373f130703127",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffe000000000000000000000000",
        "8d6a8afe55a6e481badae0d146f436db",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff000000000000000000000000",
        "6a4981f2915e3e68af6c22385dd06756",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff800000000000000000000000",
        "42a1136e5f8d8d21d3101998642d573b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffc00000000000000000000000",
        "9b471596dc69ae1586cee6158b0b0181",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffe00000000000000000000000",
        "753665c4af1eff33aa8b628bf8741cfd",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffff00000000000000000000000",
        "9a682acf40be01f5b2a4193c9a82404d",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffff80000000000000000000000",
        "54fafe26e4287f17d1935f87eb9ade01",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffc0000000000000000000000",
        "49d541b2e74cfe73e6a8e8225f7bd449",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffe0000000000000000000000",
        "11a45530f624ff6f76a1b3826626ff7b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffff0000000000000000000000",
        "f96b0c4a8bc6c86130289f60b43b8fba",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffff8000000000000000000000",
        "48c7d0e80834ebdc35b6735f76b46c8b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffc000000000000000000000",
        "2463531ab54d66955e73edc4cb8eaa45",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffe000000000000000000000",
        "ac9bd8e2530469134b9d5b065d4f565b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffff000000000000000000000",
        "3f5f9106d0e52f973d4890e6f37e8a00",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffff800000000000000000000",
        "20ebc86f1304d272e2e207e59db639f0",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffc00000000000000000000",
        "e67ae6426bf9526c972cff072b52252c",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffe00000000000000000000",
        "1a518dddaf9efa0d002cc58d107edfc8",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffff00000000000000000000",
        "ead731af4d3a2fe3b34bed047942a49f",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffff80000000000000000000",
        "b1d4efe40242f83e93b6c8d7efb5eae9",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffc0000000000000000000",
        "cd2b1fec11fd906c5c7630099443610a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffe0000000000000000000",
        "a1853fe47fe29289d153161d06387d21",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffff0000000000000000000",
        "4632154179a555c17ea604d0889fab14",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffff8000000000000000000",
        "dd27cac6401a022e8f38f9f93e774417",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffc000000000000000000",
        "c090313eb98674f35f3123385fb95d4d",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffe000000000000000000",
        "cc3526262b92f02edce548f716b9f45c",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffff000000000000000000",
        "c0838d1a2b16a7c7f0dfcc433c399c33",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffff800000000000000000",
        "0d9ac756eb297695eed4d382eb126d26",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffc00000000000000000",
        "56ede9dda3f6f141bff1757fa689c3e1",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffe00000000000000000",
        "768f520efe0f23e61d3ec8ad9ce91774",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffff00000000000000000",
        "b1144ddfa75755213390e7c596660490",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffff80000000000000000",
        "1d7c0c4040b355b9d107a99325e3b050",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffc0000000000000000",
        "d8e2bb1ae8ee3dcf5bf7d6c38da82a1a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffe0000000000000000",
        "faf82d178af25a9886a47e7f789b98d7",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffff0000000000000000",
        "9b58dbfd77fe5aca9cfc190cd1b82d19",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffff8000000000000000",
        "77f392089042e478ac16c0c86a0b5db5",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffc000000000000000",
        "19f08e3420ee69b477ca1420281c4782",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffe000000000000000",
        "a1b19beee4e117139f74b3c53fdcb875",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffff000000000000000",
        "a37a5869b218a9f3a0868d19aea0ad6a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffff800000000000000",
        "bc3594e865bcd0261b13202731f33580",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffc00000000000000",
        "811441ce1d309eee7185e8c752c07557",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffe00000000000000",
        "959971ce4134190563518e700b9874d1",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffff00000000000000",
        "76b5614a042707c98e2132e2e805fe63",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffff80000000000000",
        "7d9fa6a57530d0f036fec31c230b0cc6",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffc0000000000000",
        "964153a83bf6989a4ba80daa91c3e081",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffe0000000000000",
        "a013014d4ce8054cf2591d06f6f2f176",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffff0000000000000",
        "d1c5f6399bf382502e385eee1474a869",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffff8000000000000",
        "0007e20b8298ec354f0f5fe7470f36bd",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffc000000000000",
        "b95ba05b332da61ef63a2b31fcad9879",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffe000000000000",
        "4620a49bd967491561669ab25dce45f4",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffff000000000000",
        "12e71214ae8e04f0bb63d7425c6f14d5",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffff800000000000",
        "4cc42fc1407b008fe350907c092e80ac",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffc00000000000",
        "08b244ce7cbc8ee97fbba808cb146fda",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffe00000000000",
        "39b333e8694f21546ad1edd9d87ed95b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffff00000000000",
        "3b271f8ab2e6e4a20ba8090f43ba78f3",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffff80000000000",
        "9ad983f3bf651cd0393f0a73cccdea50",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffc0000000000",
        "8f476cbff75c1f725ce18e4bbcd19b32",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffe0000000000",
        "905b6267f1d6ab5320835a133f096f2a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffff0000000000",
        "145b60d6d0193c23f4221848a892d61a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffff8000000000",
        "55cfb3fb6d75cad0445bbc8dafa25b0f",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffc000000000",
        "7b8e7098e357ef71237d46d8b075b0f5",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffe000000000",
        "2bf27229901eb40f2df9d8398d1505ae",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffff000000000",
        "83a63402a77f9ad5c1e931a931ecd706",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffff800000000",
        "6f8ba6521152d31f2bada1843e26b973",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffc00000000",
        "e5c3b8e30fd2d8e6239b17b44bd23bbd",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffe00000000",
        "1ac1f7102c59933e8b2ddc3f14e94baa",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffff00000000",
        "21d9ba49f276b45f11af8fc71a088e3d",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffff80000000",
        "649f1cddc3792b4638635a392bc9bade",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffc0000000",
        "e2775e4b59c1bc2e31a2078c11b5a08c",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffe0000000",
        "2be1fae5048a25582a679ca10905eb80",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffff0000000",
        "da86f292c6f41ea34fb2068df75ecc29",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffff8000000",
        "220df19f85d69b1b562fa69a3c5beca5",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffc000000",
        "1f11d5d0355e0b556ccdb6c7f5083b4d",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffe000000",
        "62526b78be79cb384633c91f83b4151b",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffff000000",
        "90ddbcb950843592dd47bbef00fdc876",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffff800000",
        "2fd0e41c5b8402277354a7391d2618e2",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffc00000",
        "3cdf13e72dee4c581bafec70b85f9660",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffe00000",
        "afa2ffc137577092e2b654fa199d2c43",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffff00000",
        "8d683ee63e60d208e343ce48dbc44cac",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffff80000",
        "705a4ef8ba2133729c20185c3d3a4763",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffc0000",
        "0861a861c3db4e94194211b77ed761b9",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffe0000",
        "4b00c27e8b26da7eab9d3a88dec8b031",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffff0000",
        "5f397bf03084820cc8810d52e5b666e9",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffff8000",
        "63fafabb72c07bfbd3ddc9b1203104b8",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffc000",
        "683e2140585b18452dd4ffbb93c95df9",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffe000",
        "286894e48e537f8763b56707d7d155c8",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffff000",
        "a423deabc173dcf7e2c4c53e77d37cd1",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffff800",
        "eb8168313e1cfdfdb5e986d5429cf172",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffc00",
        "27127daafc9accd2fb334ec3eba52323",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffe00",
        "ee0715b96f72e3f7a22a5064fc592f4c",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffff00",
        "29ee526770f2a11dcfa989d1ce88830f",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffff80",
        "0493370e054b09871130fe49af730a5a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffc0",
        "9b7b940f6c509f9e44a4ee140448ee46",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffe0",
        "2915be4a1ecfdcbe3e023811a12bb6c7",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff0",
        "7240e524bc51d8c4d440b1be55d1062c",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffff8",
        "da63039d38cb4612b2dc36ba26684b93",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffc",
        "0f59cb5a4b522e2ac56c1a64f558ad9a",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffe",
        "7bfe9d876c6d63c1d035da8fe21c409d",

        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "acdace8078a32b1a182bfa4987ca1347",
    )}

    KAT_AES_CBC={(
        /*
         * From NIST validation suite "Multiblock Message Test"
         * (cbcmmt128.rsp).
         */
        "1f8e4973953f3fb0bd6b16662e9a3c17",
        "2fe2b333ceda8f98f4a99b40d2cd34a8",
        "45cf12964fc824ab76616ae2f4bf0822",
        "0f61c4d44c5147c03c195ad7e2cc12b2",

        "0700d603a1c514e46b6191ba430a3a0c",
        "aad1583cd91365e3bb2f0c3430d065bb",
        "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91",
        "c4dc61d9725967a3020104a9738f23868527ce839aab1752fd8bdb95a82c4d00",

        "3348aa51e9a45c2dbe33ccc47f96e8de",
        "19153c673160df2b1d38c28060e59b96",
        "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763d5e1847a6ad5d54127a399ab07ee3599",
        "d5aed6c9622ec451a15db12819952b6752501cf05cdbf8cda34a457726ded97818e1f127a28d72db5652749f0c6afee5",

        "b7f3c9576e12dd0db63e8f8fac2b9a39",
        "c80f095d8bb1a060699f7c19974a1aa0",
        "9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e",
        "19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467",

        "b6f9afbfe5a1562bba1368fc72ac9d9c",
        "3f9d5ebe250ee7ce384b0d00ee849322",
        "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdbd4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc89a8c431188e9e482d8553982cf304d1",
        "10ea27b19e16b93af169c4a88e06e35c99d8b420980b058e34b4b8f132b13766f72728202b089f428fecdb41c79f8aa0d0ef68f5786481cca29e2126f69bc14160f1ae2187878ba5c49cf3961e1b7ee9",

        "bbe7b7ba07124ff1ae7c3416fe8b465e",
        "7f65b5ee3630bed6b84202d97fb97a1e",
        "2aad0c2c4306568bad7447460fd3dac054346d26feddbc9abd9110914011b4794be2a9a00a519a51a5b5124014f4ed2735480db21b434e99a911bb0b60fe0253763725b628d5739a5117b7ee3aefafc5b4c1bf446467e7bf5f78f31ff7caf187",
        "3b8611bfc4973c5cd8e982b073b33184cd26110159172e44988eb5ff5661a1e16fad67258fcbfee55469267a12dc374893b4e3533d36f5634c3095583596f135aa8cd1138dc898bc5651ee35a92ebf89ab6aeb5366653bc60a70e0074fc11efe",

        "89a553730433f7e6d67d16d373bd5360",
        "f724558db3433a523f4e51a5bea70497",
        "807bc4ea684eedcfdcca30180680b0f1ae2814f35f36d053c5aea6595a386c1442770f4d7297d8b91825ee7237241da8925dd594ccf676aecd46ca2068e8d37a3a0ec8a7d5185a201e663b5ff36ae197110188a23503763b8218826d23ced74b31e9f6e2d7fbfa6cb43420c7807a8625",
        "406af1429a478c3d07e555c5287a60500d37fc39b68e5bbb9bafd6ddb223828561d6171a308d5b1a4551e8a5e7d572918d25c968d3871848d2f16635caa9847f38590b1df58ab5efb985f2c66cfaf86f61b3f9c0afad6c963c49cee9b8bc81a2ddb06c967f325515a4849eec37ce721a",

        "c491ca31f91708458e29a925ec558d78",
        "9ef934946e5cd0ae97bd58532cb49381",
        "cb6a787e0dec56f9a165957f81af336ca6b40785d9e94093c6190e5152649f882e874d79ac5e167bd2a74ce5ae088d2ee854f6539e0a94796b1e1bd4c9fcdbc79acbef4d01eeb89776d18af71ae2a4fc47dd66df6c4dbe1d1850e466549a47b636bcc7c2b3a62495b56bb67b6d455f1eebd9bfefecbca6c7f335cfce9b45cb9d",
        "7b2931f5855f717145e00f152a9f4794359b1ffcb3e55f594e33098b51c23a6c74a06c1d94fded7fd2ae42c7db7acaef5844cb33aeddc6852585ed0020a6699d2cb53809cefd169148ce42292afab063443978306c582c18b9ce0da3d084ce4d3c482cfd8fcf1a85084e89fb88b40a084d5e972466d07666126fb761f84078f2",

        "f6e87d71b0104d6eb06a68dc6a71f498",
        "1c245f26195b76ebebc2edcac412a2f8",
        "f82bef3c73a6f7f80db285726d691db6bf55eec25a859d3ba0e0445f26b9bb3b16a3161ed1866e4dd8f2e5f8ecb4e46d74a7a78c20cdfc7bcc9e479ba7a0caba9438238ad0c01651d5d98de37f03ddce6e6b4bd4ab03cf9e8ed818aedfa1cf963b932067b97d776dce1087196e7e913f7448e38244509f0caf36bd8217e15336d35c149fd4e41707893fdb84014f8729",
        "b09512f3eff9ed0d85890983a73dadbb7c3678d52581be64a8a8fc586f490f2521297a478a0598040ebd0f5509fafb0969f9d9e600eaef33b1b93eed99687b167f89a5065aac439ce46f3b8d22d30865e64e45ef8cd30b6984353a844a11c8cd60dba0e8866b3ee30d24b3fa8a643b328353e06010fa8273c8fd54ef0a2b6930e5520aae5cd5902f9b86a33592ca4365",

        "2c14413751c31e2730570ba3361c786b",
        "1dbbeb2f19abb448af849796244a19d7",
        "40d930f9a05334d9816fe204999c3f82a03f6a0457a8c475c94553d1d116693adc618049f0a769a2eed6a6cb14c0143ec5cccdbc8dec4ce560cfd206225709326d4de7948e54d603d01b12d7fed752fb23f1aa4494fbb00130e9ded4e77e37c079042d828040c325b1a5efd15fc842e44014ca4374bf38f3c3fc3ee327733b0c8aee1abcd055772f18dc04603f7b2c1ea69ff662361f2be0a171bbdcea1e5d3f",
        "6be8a12800455a320538853e0cba31bd2d80ea0c85164a4c5c261ae485417d93effe2ebc0d0a0b51d6ea18633d210cf63c0c4ddbc27607f2e81ed9113191ef86d56f3b99be6c415a4150299fb846ce7160b40b63baf1179d19275a2e83698376d28b92548c68e06e6d994e2c1501ed297014e702cdefee2f656447706009614d801de1caaf73f8b7fa56cf1ba94b631933bbe577624380850f117435a0355b2b",

        /*
         * From NIST validation suite "Multiblock Message Test"
         * (cbcmmt192.rsp).
         */
        "ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c",
        "531ce78176401666aa30db94ec4a30eb",
        "c51fc276774dad94bcdc1d2891ec8668",
        "70dd95a14ee975e239df36ff4aee1d5d",

        "eab3b19c581aa873e1981c83ab8d83bbf8025111fb2e6b21",
        "f3d6667e8d4d791e60f7505ba383eb05",
        "9d4e4cccd1682321856df069e3f1c6fa391a083a9fb02d59db74c14081b3acc4",
        "51d44779f90d40a80048276c035cb49ca2a47bcb9b9cf7270b9144793787d53f",

        "16c93bb398f1fc0cf6d68fc7a5673cdf431fa147852b4a2d",
        "eaaeca2e07ddedf562f94df63f0a650f",
        "c5ce958613bf741718c17444484ebaf1050ddcacb59b9590178cbe69d7ad7919608cb03af13bbe04f3506b718a301ea0",
        "ed6a50e0c6921d52d6647f75d67b4fd56ace1fedb8b5a6a997b4d131640547d22c5d884a75e6752b5846b5b33a5181f4",

        "067bb17b4df785697eaccf961f98e212cb75e6797ce935cb",
        "8b59c9209c529ca8391c9fc0ce033c38",
        "db3785a889b4bd387754da222f0e4c2d2bfe0d79e05bc910fba941beea30f1239eacf0068f4619ec01c368e986fca6b7c58e490579d29611bd10087986eff54f",
        "d5f5589760bf9c762228fde236de1fa2dd2dad448db3fa9be0c4196efd46a35c84dd1ac77d9db58c95918cb317a6430a08d2fb6a8e8b0f1c9b72c7a344dc349f",

        "0fd39de83e0be77a79c8a4a612e3dd9c8aae2ce35e7a2bf8",
        "7e1d629b84f93b079be51f9a5f5cb23c",
        "38fbda37e28fa86d9d83a4345e419dea95d28c7818ff25925db6ac3aedaf0a86154e20a4dfcc5b1b4192895393e5eb5846c88bdbd41ecf7af3104f410eaee470f5d9017ed460475f626953035a13db1f",
        "edadae2f9a45ff3473e02d904c94d94a30a4d92da4deb6bcb4b0774472694571842039f21c496ef93fd658842c735f8a81fcd0aa578442ab893b18f606aed1bab11f81452dd45e9b56adf2eccf4ea095",

        "e3fecc75f0075a09b383dfd389a3d33cc9b854b3b254c0f4",
        "36eab883afef936cc38f63284619cd19",
        "931b2f5f3a5820d53a6beaaa6431083a3488f4eb03b0f5b57ef838e1579623103bd6e6800377538b2e51ef708f3c4956432e8a8ee6a34e190642b26ad8bdae6c2af9a6c7996f3b6004d2671e41f1c9f40ee03d1c4a52b0a0654a331f15f34dce",
        "75395974bd32b3665654a6c8e396b88ae34b123575872a7ab687d8e76b46df911a8a590cd01d2f5c330be3a6626e9dd3aa5e10ed14e8ff829811b6fed50f3f533ca4385a1cbca78f5c4744e50f2f8359165c2485d1324e76c3eae76a0ccac629",

        "f9c27565eb07947c8cb51b79248430f7b1066c3d2fdc3d13",
        "2bd67cc89ab7948d644a49672843cbd9",
        "6abcc270173cf114d44847e911a050db57ba7a2e2c161c6f37ccb6aaa4677bddcaf50cad0b5f8758fcf7c0ebc650ceb5cd52cafb8f8dd3edcece55d9f1f08b9fa8f54365cf56e28b9596a7e1dd1d3418e4444a7724add4cf79d527b183ec88de4be4eeff29c80a97e54f85351cb189ee",
        "ca282924a61187feb40520979106e5cc861957f23828dcb7285e0eaac8a0ca2a6b60503d63d6039f4693dba32fa1f73ae2e709ca94911f28a5edd1f30eaddd54680c43acc9c74cd90d8bb648b4e544275f47e514daa20697f66c738eb30337f017fca1a26da4d1a0cc0a0e98e2463070",

        "fb09cf9e00dbf883689d079c920077c0073c31890b55bab5",
        "e3c89bd097c3abddf64f4881db6dbfe2",
        "c1a37683fb289467dd1b2c89efba16bbd2ee24cf18d19d44596ded2682c79a2f711c7a32bf6a24badd32a4ee637c73b7a41da6258635650f91fb9ffa45bdfc3cb122136241b3deced8996aa51ea8d3e81c9d70e006a44bc0571ed48623a0d622a93fa9da290baaedf5d9e876c94620945ff8ecc83f27379ed55cf490c5790f27",
        "8158e21420f25b59d6ae943fa1cbf21f02e979f419dab0126a721b7eef55bee9ad97f5ccff7d239057bbc19a8c378142f7672f1d5e7e17d7bebcb0070e8355cace6660171a53b61816ae824a6ef69ce470b6ffd3b5bb4b438874d91d27854d3b6f25860d3868958de3307d62b1339bdddb8a318c0ce0f33c17caf0e9f6040820",

        "bca6fa3c67fd294e958f66fe8bd64f45f428f5bc8e9733a7",
        "92a47f2833f1450d1da41717bdc6e83c",
        "5becbc31d8bead6d36ae014a5863d14a431e6b55d29ea6baaa417271716db3a33b2e506b452086dfe690834ac2de30bc41254ec5401ec47d064237c7792fdcd7914d8af20eb114756642d519021a8c75a92f6bc53d326ae9a5b7e1b10a9756574692934d9939fc399e0c203f7edf8e7e6482eadd31a0400770e897b48c6bca2b404593045080e93377358c42a0f4dede",
        "926db248cc1ba20f0c57631a7c8aef094f791937b905949e3460240e8bfa6fa483115a1b310b6e4369caebc5262888377b1ddaa5800ea496a2bdff0f9a1031e7129c9a20e35621e7f0b8baca0d87030f2ae7ca8593c8599677a06fd4b26009ead08fecac24caa9cf2cad3b470c8227415a7b1e0f2eab3fad96d70a209c8bb26c627677e2531b9435ca6e3c444d195b5f",

        "162ad50ee64a0702aa551f571dedc16b2c1b6a1e4d4b5eee",
        "24408038161a2ccae07b029bb66355c1",
        "be8abf00901363987a82cc77d0ec91697ba3857f9e4f84bd79406c138d02698f003276d0449120bef4578d78fecabe8e070e11710b3f0a2744bd52434ec70015884c181ebdfd51c604a71c52e4c0e110bc408cd462b248a80b8a8ac06bb952ac1d7faed144807f1a731b7febcaf7835762defe92eccfc7a9944e1c702cffe6bc86733ed321423121085ac02df8962bcbc1937092eebf0e90a8b20e3dd8c244ae",
        "c82cf2c476dea8cb6a6e607a40d2f0391be82ea9ec84a537a6820f9afb997b76397d005424faa6a74dc4e8c7aa4a8900690f894b6d1dca80675393d2243adac762f159301e357e98b724762310cd5a7bafe1c2a030dba46fd93a9fdb89cc132ca9c17dc72031ec6822ee5a9d99dbca66c784c01b0885cbb62e29d97801927ec415a5d215158d325f9ee689437ad1b7684ad33c0d92739451ac87f39ff8c31b84",

        /*
         * From NIST validation suite "Multiblock Message Test"
         * (cbcmmt256.rsp).
         */
        "6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907",
        "851e8764776e6796aab722dbb644ace8",
        "6282b8c05c5c1530b97d4816ca434762",
        "6acc04142e100a65f51b97adf5172c41",

        "dce26c6b4cfb286510da4eecd2cffe6cdf430f33db9b5f77b460679bd49d13ae",
        "fdeaa134c8d7379d457175fd1a57d3fc",
        "50e9eee1ac528009e8cbcd356975881f957254b13f91d7c6662d10312052eb00",
        "2fa0df722a9fd3b64cb18fb2b3db55ff2267422757289413f8f657507412a64c",

        "fe8901fecd3ccd2ec5fdc7c7a0b50519c245b42d611a5ef9e90268d59f3edf33",
        "bd416cb3b9892228d8f1df575692e4d0",
        "8d3aa196ec3d7c9b5bb122e7fe77fb1295a6da75abe5d3a510194d3a8a4157d5c89d40619716619859da3ec9b247ced9",
        "608e82c7ab04007adb22e389a44797fed7de090c8c03ca8a2c5acd9e84df37fbc58ce8edb293e98f02b640d6d1d72464",

        "0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5",
        "c0cd2bebccbb6c49920bd5482ac756e8",
        "8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c",
        "05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594",

        "9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85",
        "11958dc6ab81e1c7f01631e9944e620f",
        "c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf53e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3052d8b21c5561c8b660e",
        "9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832ccdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc557e2b45b49ce05511e65",

        "73b8faf00b3302ac99855cf6f9e9e48518690a5906a4869d4dcf48d282faae2a",
        "b3cb97a80a539912b8c21f450d3b9395",
        "3adea6e06e42c4f041021491f2775ef6378cb08824165edc4f6448e232175b60d0345b9f9c78df6596ec9d22b7b9e76e8f3c76b32d5d67273f1d83fe7a6fc3dd3c49139170fa5701b3beac61b490f0a9e13f844640c4500f9ad3087adfb0ae10",
        "ac3d6dbafe2e0f740632fd9e820bf6044cd5b1551cbb9cc03c0b25c39ccb7f33b83aacfca40a3265f2bbff879153448acacb88fcfb3bb7b10fe463a68c0109f028382e3e557b1adf02ed648ab6bb895df0205d26ebbfa9a5fd8cebd8e4bee3dc",

        "9ddf3745896504ff360a51a3eb49c01b79fccebc71c3abcb94a949408b05b2c9",
        "e79026639d4aa230b5ccffb0b29d79bc",
        "cf52e5c3954c51b94c9e38acb8c9a7c76aebdaa9943eae0a1ce155a2efdb4d46985d935511471452d9ee64d2461cb2991d59fc0060697f9a671672163230f367fed1422316e52d29eceacb8768f56d9b80f6d278093c9a8acd3cfd7edd8ebd5c293859f64d2f8486ae1bd593c65bc014",
        "34df561bd2cfebbcb7af3b4b8d21ca5258312e7e2e4e538e35ad2490b6112f0d7f148f6aa8d522a7f3c61d785bd667db0e1dc4606c318ea4f26af4fe7d11d4dcff0456511b4aed1a0d91ba4a1fd6cd9029187bc5881a5a07fe02049d39368e83139b12825bae2c7be81e6f12c61bb5c5",

        "458b67bf212d20f3a57fce392065582dcefbf381aa22949f8338ab9052260e1d",
        "4c12effc5963d40459602675153e9649",
        "256fd73ce35ae3ea9c25dd2a9454493e96d8633fe633b56176dce8785ce5dbbb84dbf2c8a2eeb1e96b51899605e4f13bbc11b93bf6f39b3469be14858b5b720d4a522d36feed7a329c9b1e852c9280c47db8039c17c4921571a07d1864128330e09c308ddea1694e95c84500f1a61e614197e86a30ecc28df64ccb3ccf5437aa",
        "90b7b9630a2378f53f501ab7beff039155008071bc8438e789932cfd3eb1299195465e6633849463fdb44375278e2fdb1310821e6492cf80ff15cb772509fb426f3aeee27bd4938882fd2ae6b5bd9d91fa4a43b17bb439ebbe59c042310163a82a5fe5388796eee35a181a1271f00be29b852d8fa759bad01ff4678f010594cd",

        "d2412db0845d84e5732b8bbd642957473b81fb99ca8bff70e7920d16c1dbec89",
        "51c619fcf0b23f0c7925f400a6cacb6d",
        "026006c4a71a180c9929824d9d095b8faaa86fc4fa25ecac61d85ff6de92dfa8702688c02a282c1b8af4449707f22d75e91991015db22374c95f8f195d5bb0afeb03040ff8965e0e1339dba5653e174f8aa5a1b39fe3ac839ce307a4e44b4f8f1b0063f738ec18acdbff2ebfe07383e734558723e741f0a1836dafdf9de82210a9248bc113b3c1bc8b4e252ca01bd803",
        "0254b23463bcabec5a395eb74c8fb0eb137a07bc6f5e9f61ec0b057de305714f8fa294221c91a159c315939b81e300ee902192ec5f15254428d8772f79324ec43298ca21c00b370273ee5e5ed90e43efa1e05a5d171209fe34f9f29237dba2a6726650fd3b1321747d1208863c6c3c6b3e2d879ab5f25782f08ba8f2abbe63e0bedb4a227e81afb36bb6645508356d34",

        "48be597e632c16772324c8d3fa1d9c5a9ecd010f14ec5d110d3bfec376c5532b",
        "d6d581b8cf04ebd3b6eaa1b53f047ee1",
        "0c63d413d3864570e70bb6618bf8a4b9585586688c32bba0a5ecc1362fada74ada32c52acfd1aa7444ba567b4e7daaecf7cc1cb29182af164ae5232b002868695635599807a9a7f07a1f137e97b1e1c9dabc89b6a5e4afa9db5855edaa575056a8f4f8242216242bb0c256310d9d329826ac353d715fa39f80cec144d6424558f9f70b98c920096e0f2c855d594885a00625880e9dfb734163cecef72cf030b8",
        "fc5873e50de8faf4c6b84ba707b0854e9db9ab2e9f7d707fbba338c6843a18fc6facebaf663d26296fb329b4d26f18494c79e09e779647f9bafa87489630d79f4301610c2300c19dbf3148b7cac8c4f4944102754f332e92b6f7c5e75bc6179eb877a078d4719009021744c14f13fd2a55a2b9c44d18000685a845a4f632c7c56a77306efa66a24d05d088dcd7c13fe24fc447275965db9e4d37fbc9304448cd",
    )}

    KAT_AES_CTR={(
        /*
         * From RFC 3686.
         */
        "ae6852f8121067cc4bf7a5765577f39e",
        "000000300000000000000000",
        "53696e676c6520626c6f636b206d7367",
        "e4095d4fb7a7b3792d6175a3261311b8",

        "7e24067817fae0d743d6ce1f32539163",
        "006cb6dbc0543b59da48d90b",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28",

        "7691be035e5020a8ac6e618529f9a0dc",
        "00e0017b27777f3f4a1786f0",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
        "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f",

        "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515",
        "0000004836733c147d6d93cb",
        "53696e676c6520626c6f636b206d7367",
        "4b55384fe259c9c84e7935a003cbe928",

        "7c5cb2401b3dc33c19e7340819e0f69c678c3db8e6f6a91a",
        "0096b03b020c6eadc2cb500d",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "453243fc609b23327edfaafa7131cd9f8490701c5ad4a79cfc1fe0ff42f4fb00",

        "02bf391ee8ecb159b959617b0965279bf59b60a786d3e0fe",
        "0007bdfd5cbd60278dcc0912",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
        "96893fc55e5c722f540b7dd1ddf7e758d288bc95c69165884536c811662f2188abee0935",

        "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
        "00000060db5672c97aa8f0b2",
        "53696e676c6520626c6f636b206d7367",
        "145ad01dbf824ec7560863dc71e3e0c0",

        "f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884",
        "00faac24c1585ef15a43d875",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c",

        "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
        "001cc5b751a51d70a1c11148",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
        "eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8",
    )}
}
