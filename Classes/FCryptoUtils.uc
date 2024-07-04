/*
 * Copyright (c) 2024 Tuomo Kriikkula <tuokri@tuta.io>
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
class FCryptoUtils extends Object
    notplaceable;

`include(FCrypto\Classes\FCryptoMacros.uci);

var private int Year;
var private int Month;
var private int DayOfWeek;
var private int Day;
var private int Hour;
var private int Min;
var private int Sec;
var private int MSec;

// Warning: only takes MSec, Sec, Min and Hour into account.
simulated final function float GetSystemTimeStamp()
{
    GetSystemTime(Year, Month, DayOfWeek, Day, Hour, Min, Sec, MSec);
    return (Hour * 3600) + (Min * 60) + Sec + (MSec / 1000);
}

static final function bool FromHex(string HexString, out int Result)
{
    local int Res;
    local int i;
    local int t;
    local int s;

    if (Len(HexString) > 8)
    {
        Result = -1;
        return False;
    }

    HexString = Caps(HexString);
    s = 0;

    for (i = Len(HexString) - 1; i >= 0; --i)
    {
        t = Asc(Mid(HexString, i, 1));

        if (t >= 48 && t <= 57)
        {
            t -= 48;
        }
        else if (t >= 65 && t <= 70)
        {
            t -= 55;
        }
        else
        {
            Result = -1;
            return False;
        }

        if (s > 0)
        {
            t = t << s;
        }

        Res = Res | t;
        s += 4;
    }

    Result = Res;
    return True;
}
