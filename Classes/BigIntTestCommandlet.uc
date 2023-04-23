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

/*
 * Run tests with:'VNGame.exe FCrypto.BigIntTestCommandlet'.
 * The script package has to be brewed with 'VNEditor.exe BrewContent FCrypto'
 * first for the game executable to be able to find the commandlet.
 *
 * TODO: DOES NOT WORK ATM, THE COMMANDLET IS NOT RAN FOR SOME REASON!
 */
class BigIntTestCommandlet extends Commandlet;

event int Main(string Params)
{
    `fclog("Executing BigInt tests...");

    Test_Add();

    return 0;
}

function Test_Add()
{
    local array<int> A;
    local array<int> B;
    local int Ctl;
    local int Cc;

    Ctl = 0;
    Cc = class'BigInt'.static.Add(A, B, Ctl);
    `fclog("Cc:" @ Cc);
}

DefaultProperties
{
    LogToConsole=True
}
