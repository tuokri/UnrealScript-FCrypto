/*
 * Copyright (c) 2023 Tuomo Kriikkula <tuokri@tuta.io>
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

/*
 * Test utility client to perform certain GMP mpz
 * operations on a server and return the results.
 * This is used because I'm too lazy to re-implement
 * parts of GMP in UnrealScript. And it's faster and
 * easier to do it this way, anyway.
 *
 * NOTE: it's recommended to run the dedicated server or
 * game client with 60 or higher tick rate to make the client
 * execute the tests faster.
 *
 * See: FCrypto/DevUtils/gmp_server.py for more details.
 */
class FCryptoGMPClient extends TcpLink;

var private int ClientPort;

var private array<string> Responses;

var private int TransactionID;
var private array<string> TransactionStack;

var bool bDone;

struct PendingCheck
{
    var string TestName;
    var int TransactionID;
    var string GMPOperandName;
    var array<int> BigIntOperand;
};

var private array<PendingCheck> PendingChecks;
var private PendingCheck CurrentCheck;

var string TargetHost;
var int TargetPort;

var private array<string> R_Array;
var private string R_TID;
var private string R_GMPOperandName;
var private string R_Result;
var private array<byte> R_ResultBytes;

var private int Failures;
var private int LastFailuresLogged;

var private int ChecksDone;
var private int RequiredChecks;

const ID_PRIME = "PRIME";
const TID_PRIME = "TPRIME";

var delegate<OnRandPrimeReceived> RandPrimeDelegate;
delegate OnRandPrimeReceived(const out array<byte> P);

simulated event Tick(float DeltaTime)
{
    local int I;
    // local int J;
    // local int K;
    // local int LenResult;
    // local string ByteS;
    local int Fail;

    for (I = 0; I < Responses.Length; ++I)
    {
        if (Responses[I] == "SERVER_ERROR")
        {
            `fcerror("SERVER ERROR!");
            PendingChecks.Remove(0, 1); // TODO: should do checks in a loop?
            ++ChecksDone;
            ++Failures;
            continue;
        }

        ParseStringIntoArray(Responses[I], R_Array, " ", False);
        R_TID = R_Array[0];
        R_GMPOperandName = R_Array[1];
        R_Result = R_Array[2];

        if (Len(R_Result) < 3)
        {
            R_ResultBytes.Length = 1;
            R_ResultBytes[0] = class'WebAdminUtils'.static.FromHex(R_Result);
        }
        else
        {
            // LenResult = Len(R_Result);
            // if ((LenResult % 2) != 0)
            // {
            //     R_Result = "0" $ R_Result;
            //     ++LenResult;
            // }
            // K = 0;
            // J = 0;
            // R_ResultBytes.Length = LenResult / 2;
            // while (J < LenResult)
            // {
            //     ByteS = Mid(R_Result, J, 2);
            //     R_ResultBytes[K++] = class'WebAdminUtils'.static.FromHex(ByteS);
            //     J += 2;
            // }
            class'FCryptoBigInt'.static.BytesFromHex(R_ResultBytes, R_Result);
        }

        if (R_TID == ID_PRIME)
        {
            RandPrimeDelegate(R_ResultBytes);
            continue;
        }

        // `fclog(Responses[I]);
        // class'FCryptoTestMutator'.static.LogBytes(R_ResultBytes);

        CurrentCheck = PendingChecks[0];

        Fail = class'FCryptoTestMutator'.static.CheckEqz(
            CurrentCheck.BigIntOperand,
            R_ResultBytes
        );

        if (Fail > 0)
        {
            `fcwarn("CurrentCheck.TestName       :" @ CurrentCheck.TestName);
            `fcwarn("CurrentCheck.TID            :" @ CurrentCheck.TransactionID);
            `fcwarn("CurrentCheck.GMPOperandName :" @ CurrentCheck.GMPOperandName);
            `fcwarn("R_TID                       :" @ R_TID);
            `fcwarn("R_Result                    :" @ R_Result);
            `fcwarn("R_GMPOperandName            :" @ R_GMPOperandName);
            `fcwarn("Response                    :" @ Responses[I]);
            Failures += Fail;
        }

        PendingChecks.Remove(0, 1); // TODO: should do checks in a loop?
        ++ChecksDone;
    }

    if (I > 0)
    {
        Responses.Remove(0, I);
    }

    if (Failures > 0 && LastFailuresLogged < (Failures - 1))
    {
        `fcwarn("---" @ Failures @ "FAILURES DETECTED! ---");
        LastFailuresLogged = Failures;
    }

    if (ChecksDone > 0 && (ChecksDone % 25) == 0)
    {
        `fclog("---" @ ChecksDone @ "checks done so far. ---");
    }

    if (ChecksDone > 0 && (ChecksDone >= RequiredChecks))
    {
        `fclog("--- ALL CHECKS DONE" @ ChecksDone $ "/" $ RequiredChecks @ "---");
        ChecksDone = 0;
        RequiredChecks = 0;

        if (Failures > 0)
        {
            `fcwarn("---" @ Failures @ "FAILURES DETECTED! ---");
        }
    }

    super.Tick(DeltaTime);
}

final simulated function ConnectToServer()
{
    LinkMode = MODE_Line;
    ReceiveMode = RMODE_Event;
    InLineMode = LMODE_UNIX;
    OutLineMode = LMODE_UNIX;
    Resolve(TargetHost);
}

final simulated function Begin()
{
    ++TransactionID;
}

final simulated function End()
{
    local string Str;
    local int I;

    // Actually push the stuff here.
    Str = "T" $ TransactionID;
    for (I = 0; I < TransactionStack.Length; ++I)
    {
        Str @= "[" $ TransactionStack[I] $ "]";
    }

    // `fclog("sending" @ TransactionID);
    SendText(Str);
    TransactionStack.Length = 0;
}

final simulated function Var(string VarName, string Value)
{
    TransactionStack.AddItem("var" @ VarName @ "'" $ Value $ "'");
}

final simulated function Op(string Op, string Dst, string A, string B)
{
    TransactionStack.AddItem("op" @ Op @ Dst @ A @ B );
}

final simulated function Eq(string GMPOperandName, const out array<int> B,
    string TestName = "Unnamed")
{
    local PendingCheck Check;

    Check.TransactionID = TransactionID;
    Check.GMPOperandName = GMPOperandName;
    Check.BigIntOperand = B;

    PendingChecks.AddItem(Check);
    RequiredChecks = PendingChecks.Length;
}

final simulated function RandPrime(int Size)
{
    SendText(
        TID_PRIME
        @ "[var s '" $ ToHex(Size) $ "']"
        @ "[var x '0']"
        @ "[op rand_prime x s s]"
    );
}

event Resolved(IpAddr Addr)
{
    ClientPort = BindPort();
    if (ClientPort == 0)
    {
        `fcerror("failed to bind port");
        return;
    }

    Addr.Port = TargetPort;
    if (!Open(Addr))
    {
        `fcerror("open failed");
    }
}

event ResolveFailed()
{
    `fcerror("resolve failed");
    ConnectToServer();
}

event Opened()
{
    `fclog("opened");
}

event Closed()
{
    `fclog("closed");
    if (!bDone)
    {
        `fclog("not done, retrying connection...");
        ConnectToServer();
    }
}

event ReceivedLine(string Line)
{
    // `fclog(Line @ Responses.Length);
    Responses.AddItem(Line);
}

DefaultProperties
{
    bDone=False

    ChecksDone=0
    Failures=0
    LastFailuresLogged=0

    TargetHost="127.0.0.1"
    TargetPort=65432
    TransactionID=0

    InLineMode=LMODE_UNIX
    OutLineMode=LMODE_UNIX

    TickGroup=TG_DuringAsyncWork
}
