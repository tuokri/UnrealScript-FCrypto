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

// TODO: call this something else like FCryptoDetails
//       and put all "utility" structs here instead of
//       just (hash) contexts?
class FCryptoContext extends Object
    abstract
    notplaceable;

`include(FCrypto\Classes\FCryptoSHA2Constants.uci);

struct FCryptoHashContext
{
    // TODO: might need to use QWORD for this?
    // A 32-bit signed integer is probably enough
    // for our use cases though.
    var int Count;

    StructDefaultProperties
    {
        Count=0
    }
};

struct FCryptoSHA224Context extends FCryptoHashContext
{
    var byte Buf[64];
    var int Val[8];

    StructDefaultProperties
    {
        Val(0)=SHA224_IV_VAL0
        Val(1)=SHA224_IV_VAL1
        Val(2)=SHA224_IV_VAL2
        Val(3)=SHA224_IV_VAL3
        Val(4)=SHA224_IV_VAL4
        Val(5)=SHA224_IV_VAL5
        Val(6)=SHA224_IV_VAL6
        Val(7)=SHA224_IV_VAL7
    }
};
