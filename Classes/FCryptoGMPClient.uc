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

class FCryptoGMPClient extends TcpLink;

var private int ClientPort;

var private array<string> QueuedOperations;
var private array<string> Responses;

var private int TransactionID;
var private array<string> TransactionStack;

var string TargetHost;
var int TargetPort;

// simulated event Tick(float DeltaTime)
// {
//     if (QueuedOperations.Length > 0)
//     {
//         SendText(QueuedOperations[QueuedOperations.Length - 1]);
//         QueuedOperations.Length = QueuedOperations.Length - 1;
//     }

//     super.Tick(DeltaTime);
// }

final simulated function ConnectToServer()
{
    LinkMode = MODE_Line;
    ReceiveMode = RMODE_Event;
    InLineMode = LMODE_UNIX;
    OutLineMode = LMODE_UNIX;
    Resolve(TargetHost);
}

final simulated function int GetNumQueuedOps()
{
    return QueuedOperations.Length;
}

final simulated function Begin()
{
    TransactionID++;
}

final simulated function End()
{
    // Actually push the stuff here.
}

final simulated function Var(string Name, string Value)
{

}

final simulated function Op(string Op, string A, string B)
{

}

final simulated function Eq(string A, string B)
{

}

final simulated function MpzAdd(string A, string B)
{
    QueuedOperations.AddItem("mpz_add" @ "'" $ A $ "'" @ "'" $ B $ "'");
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

event ReceivedLine(string Line)
{
    `fclog(Line);
    Responses.AddItem(Line);
}

DefaultProperties
{
    TargetHost="127.0.0.1"
    TargetPort=65432
    TransactionID=0

    InLineMode=LMODE_UNIX
    OutLineMode=LMODE_UNIX

    TickGroup=TG_DuringAsyncWork
}
