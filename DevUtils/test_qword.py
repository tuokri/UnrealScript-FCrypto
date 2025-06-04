# MIT License
#
# Copyright (c) 2023-2024 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import pytest


# For testing FCryptoQWORD FCQWORD16.
class QWord16:
    def __init__(self, a: int = 0, b: int = 0, c: int = 0, d: int = 0):
        self.a = a
        self.b = b
        self.c = c
        self.d = d

    @property
    def value(self) -> int:
        # Return 64-bit unsigned integer.
        return self.d | (self.c << 16) | (self.b << 32) | (self.a << 48)


class QWord:
    def __init__(self, a: int = 0, b: int = 0):
        self.a = a
        self.b = b

    @staticmethod
    def from_QWord16(qw16: QWord16):
        return QWord(
            a=((qw16.a & 0xffff) << 16) | (qw16.b & 0xffff),
            b=((qw16.c & 0xffff) << 16) | (qw16.d & 0xffff),
        )

    @property
    def value(self) -> int:
        # Return 64-bit unsigned integer.
        return self.b | (self.a << 32)

    def __gt__(self, other: "QWord") -> bool:
        if gt_uint32(self.a, other.a):
            return True
        return gt_uint32(self.b, other.b)

    def __lt__(self, other: "QWord") -> bool:
        if lt_uint32(self.a, other.a):
            return True
        return lt_uint32(self.b, other.b)


# FCryptoQWORD::IsGt_AsUInt32
def gt_uint32(a: int, b: int) -> bool:
    ltb = ~a & b
    gtb = a & ~b

    ltb = ltb | (ltb >> 1)
    ltb = ltb | (ltb >> 2)
    ltb = ltb | (ltb >> 4)
    ltb = ltb | (ltb >> 8)
    ltb = ltb | (ltb >> 16)

    return bool(gtb & ~ltb)


# FCryptoQWORD::IsLt_AsUInt32
def lt_uint32(a: int, b: int) -> bool:
    ltb = ~a & b
    gtb = a & ~b

    gtb = gtb | (gtb >> 1)
    gtb = gtb | (gtb >> 2)
    gtb = gtb | (gtb >> 4)
    gtb = gtb | (gtb >> 8)
    gtb = gtb | (gtb >> 16)

    return bool(ltb & ~gtb)


# FCryptoQWORD::FCQWORD16_AddInt without carry return.
def qword16_add_int(qw: QWord16, x: int) -> QWord16:
    qw.d += x

    qw.c += (qw.d >> 16) & 0xffff
    qw.d = qw.d & 0xffff

    qw.b += (qw.c >> 16) & 0xffff
    qw.c = qw.c & 0xffff

    qw.a += (qw.b >> 16) & 0xffff
    qw.b = qw.b & 0xffff
    qw.a = qw.a & 0xffff

    return qw


# TODO: this is kinda shitty, but does the job.
# TODO: actually, it doesn't work correctly right now!
def qword16_sub_int(qw: QWord16, x: int) -> QWord16:
    borrow = 0x0
    tmp = qw.d - (x & 0xffff)
    if tmp < 0:
        qw.c -= 0x1
        borrow = 0xf
    else:
        borrow = 0x0
    qw.d = (qw.d + borrow) - (x & 0xffff)

    tmp = qw.c - ((x >> 16) & 0xffff)
    if (tmp < 0):
        qw.b -= 0x1
        borrow = 0xf
    else:
        borrow = 0x0
    qw.c = (qw.c + borrow) - ((x >> 16) & 0xffff)

    if qw.b < 0:
        qw.a -= 0x1
        qw.b += 0xf

    # TODO: a missing step here?

    return qw


# FCryptoQWORD::FCQWORD16_AddInt with carry return.
def qword16_add_int_rcarry(qw: QWord16, x: int) -> tuple[QWord16, int]:
    qw.d += x

    qw.c += (qw.d >> 16) & 0xffff
    qw.d = qw.d & 0xffff

    qw.b += (qw.c >> 16) & 0xffff
    qw.c = qw.c & 0xffff

    qw.a += (qw.b >> 16) & 0xffff
    qw.b = qw.b & 0xffff
    carry = (qw.a >> 16) & 0xffff
    qw.a = qw.a & 0xffff

    return qw, carry


# FCryptoQWORD::FCQWORD16_Mul
def qword16_mul(qw: QWord16, mul: QWord16) -> tuple[QWord16, int]:
    res = QWord16()

    tmp = qw.d * mul.d
    carry = (tmp >> 16) & 0xffff
    res.d = tmp & 0xffff

    tmp = carry + (qw.d * mul.c) + (qw.c * mul.d)
    carry = (tmp >> 16) & 0xffff
    res.c = tmp & 0xffff

    tmp = carry + (qw.d * mul.b) + (qw.c * mul.c) + (qw.b * mul.d)
    carry = (tmp >> 16) & 0xffff
    res.b = tmp & 0xffff

    tmp = (carry + (qw.d * mul.a) + (qw.c * mul.b)
           + (qw.b * mul.c) + (qw.a * mul.d))
    carry_hi16 = ((qw.a * mul.b) + (qw.b * mul.a)) << 16
    carry = carry_hi16 | (((tmp >> 16) & 0xffff)
                          + ((qw.a * mul.c) + (qw.b * mul.b) + (qw.c * mul.a)))
    res.a = tmp & 0xffff

    return res, carry


def test_qword16_add_math():
    qw_zero = QWord16()
    qw1 = QWord16(0x0000, 0x1010, 0xffff, 0xffff)
    qw2 = QWord16(0x0001, 0x3412, 0x0001, 0x0000)
    qw3 = QWord16(0x0000, 0x0000, 0x0001, 0x0001)
    qw4 = QWord16(0x0000, 0x0000, 0x04f0, 0x5bc8)
    qw5 = QWord16(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    qw6 = QWord16(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)

    assert qw1.value + 1000 == 0x0000_1011_0000_03e7
    assert qw2.value + 0xffff == 0x0001_3412_0001_ffff
    assert qw3.value + 0x0001 == 0x0000_0000_0001_0002
    assert qw5.value + 0x0001 == 0x0001_0000_0000_0000_0000
    assert qw_zero.value + 0x0000 == 0x0000_0000_0000_0000

    result = qw4.value + 859  # 0x4f05f23
    assert result == 0x0000_0000_04f0_5f23, f"result={result:_x}"

    assert qword16_add_int(qw1, 1000).value == 0x0000_1011_0000_03e7
    assert qword16_add_int(qw2, 0xffff).value == 0x0001_3412_0001_ffff
    assert qword16_add_int(qw3, 0x0001).value == 0x0000_0000_0001_0002
    assert qword16_add_int(qw4, 859).value == 0x0000_0000_04f0_5f23
    assert qword16_add_int(qw_zero, 0x0000).value == 0x0000_0000_0000_0000

    assert qword16_add_int(
        qw5, 0x0001).value == 0x0000_0000_0000_0000, f"qw5.value={qw5.value:_x}"

    result, carry = qword16_add_int_rcarry(qw6, 0x0001)
    assert carry == 0x0001
    assert result.value == 0x0000_0000_0000_0000, f"result={result.value:_x}"


def test_qword16_sub_math():
    qw1 = QWord16(0x0000, 0x0000, 0xFFFF, 0x0001)
    qw2 = QWord16(0x0000, 0x0000, 0x0002, 0x0222)
    qw3 = QWord16(0xFFFF, 0xFFFF, 0x0000, 0x0000)
    sub1 = 0x0002
    sub2 = 0x0222
    sub3 = 0xFFFF_FFFF

    result = qword16_sub_int(qw1, sub1)
    assert result.value == 0x0000_0000_FFFE_000E, f"result.value={
        result.value:_x}"

    result = qword16_sub_int(qw2, sub2)
    assert result.value == 0x0000_0000_0002_0000, f"result.value={
        result.value:_x}"

    # TODO: enable this when the algorithm is fixed!
    # result = qword16_sub_int(qw3, sub3)
    # assert result.value == 0xffff_fffe_0000_0001, f"result.value={
    #     result.value:_x}"


def test_qword16_mul_math():
    qw1 = QWord16(0x0000, 0x0000, 0x0002, 0x0022)
    qw2 = QWord16(0x0001, 0xabcd, 0x0002, 0x0022)
    qw3 = QWord16(0x0000, 0x0001, 0x1101, 0xfff1)
    qw4 = QWord16(0x1111, 0x1111, 0x1111, 0x1111)
    qw5 = QWord16(0x0001, 0x0002, 0x0003, 0x0404)
    qw6 = QWord16(0x0000, 0x0000, 0xffff, 0xffff)
    qw7 = QWord16(0x0000, 0x000f, 0xffff, 0xffff)
    qw8 = QWord16(0x0000, 0x00ff, 0xffff, 0xffff)
    qw9 = QWord16(0x0000, 0x0fff, 0xffff, 0xffff)
    qw10 = QWord16(0x0000, 0x9fff, 0xffff, 0xffff)
    qw11 = QWord16(0x0001, 0x9fff, 0xffff, 0xffff)
    qw12 = QWord16(0x0009, 0x9fff, 0xffff, 0xffff)
    qw13 = QWord16(0x0159, 0xffff, 0xffff, 0xffff)
    mul1 = QWord16(0x0000, 0x0000, 0x0001, 0xffff)
    mul2 = QWord16(0x0000, 0x0000, 0x0000, 0x0001)
    mul3 = QWord16(0x0000, 0x0000, 0x0001, 0x0000)
    mul4 = QWord16(0x0000, 0x0001, 0x0000, 0x0000)
    mul_zero = QWord16(0x0000, 0x0000, 0x0000, 0x0000)

    assert qw1.value == 0x0000_0000_0002_0022
    assert mul1.value == 0x0000_0000_0001_ffff

    assert qw1.value * mul1.value == 0x0000_0004_0041_ffde
    assert qw2.value * mul1.value == 0x0003_5798_5437_0041_ffde
    assert qw3.value * mul1.value == 0x0002_2202_eee0_000f
    assert qw4.value * mul2.value == 0x1111_1111_1111_1111
    assert qw4.value * mul3.value == 0x1111_1111_1111_1111_0000
    assert qw4.value * mul4.value == 0x1111_1111_1111_1111_0000_0000
    assert qw5.value * mul4.value == 0x0001_0002_0003_0404_0000_0000
    assert qw6.value * mul1.value == 0x0001_fffe_fffe_0001
    assert qw7.value * mul1.value == 0x001f_ffef_fffe_0001
    assert qw8.value * mul1.value == 0x01ff_feff_fffe_0001
    assert qw9.value * mul1.value == 0x1fff_efff_fffe_0001
    assert qw10.value * mul1.value == 0x0001_3fff_5fff_fffe_0001
    assert qw11.value * mul1.value == 0x0003_3ffe_5fff_fffe_0001
    assert qw12.value * mul1.value == 0x0013_3ff6_5fff_fffe_0001
    assert qw13.value * mul1.value == 0x02b3_fea5_ffff_fffe_0001
    assert qw1.value * mul_zero.value == 0x0000_0000_0000_0000
    assert qw2.value * mul_zero.value == 0x0000_0000_0000_0000

    res, carry = qword16_mul(qw1, mul1)
    assert res.value == 0x0000_0004_0041_ffde, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw2, mul1)
    assert res.value == 0x5798_5437_0041_ffde, f"res={res.value:_x}"
    assert carry == 0x3, f"carry={carry:_x}"

    res, carry = qword16_mul(qw4, mul2)
    assert res.value == 0x1111_1111_1111_1111, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw4, mul3)
    assert res.value == 0x1111_1111_1111_0000, f"res={res.value:_x}"
    assert carry == 0x1111, f"carry={carry:_x}"

    res, carry = qword16_mul(qw4, mul4)
    assert res.value == 0x1111_1111_0000_0000, f"res={res.value:_x}"
    assert carry == 0x1111_1111, f"carry={carry:_x}"

    res, carry = qword16_mul(qw5, mul4)
    assert res.value == 0x0003_0404_0000_0000, f"res={res.value:_x}"
    assert carry == 0x0001_0002, f"carry={carry:_x}"

    res, carry = qword16_mul(qw3, mul1)
    assert res.value == 0x0002_2202_eee0_000f, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw6, mul1)
    assert res.value == 0x0001_fffe_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw7, mul1)
    assert res.value == 0x001f_ffef_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw8, mul1)
    assert res.value == 0x01ff_feff_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw9, mul1)
    assert res.value == 0x1fff_efff_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0, f"carry={carry:_x}"

    res, carry = qword16_mul(qw10, mul1)
    assert res.value == 0x3fff_5fff_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0001, f"carry={carry:_x}"

    res, carry = qword16_mul(qw11, mul1)
    assert res.value == 0x3ffe_5fff_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0003, f"carry={carry:_x}"

    res, carry = qword16_mul(qw12, mul1)
    assert res.value == 0x3ff6_5fff_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x0013, f"carry={carry:_x}"

    res, carry = qword16_mul(qw13, mul1)
    assert res.value == 0xfea5_ffff_fffe_0001, f"res={res.value:_x}"
    assert carry == 0x02b3, f"carry={carry:_x}"


def test_qword16_unix_time():
    qw = QWord16()
    x = QWord16()

    time_now = 1729972973.8590236
    time_now_msec = time_now * 1000

    # Grab timestamp seconds the same way we do in UScript.
    unix_time = int(time_now)
    # Also get the milliseconds part.
    msec = int((time_now % 1) * 1000)

    qw.c = (unix_time >> 16) & 0xffff
    qw.d = unix_time & 0xffff
    x.d = 1000

    qw, carry = qword16_mul(qw, x)
    qw = qword16_add_int(qw, msec)

    assert carry == 0
    assert qw.value == pytest.approx(time_now_msec)

    assert qw.a == (int(time_now_msec) >> 48) & 0xffff
    assert qw.b == (int(time_now_msec) >> 32) & 0xffff
    assert qw.c == (int(time_now_msec) >> 16) & 0xffff
    assert qw.d == (int(time_now_msec) >> 0) & 0xffff

    hi32 = ((qw.a & 0xffff) << 16) | (qw.b & 0xffff)
    lo32 = ((qw.c & 0xffff) << 16) | (qw.d & 0xffff)

    assert ((hi32 << 32) | lo32) == qw.value

    qw_bytes = bytearray(6)
    qw_bytes[0] = (hi32 >> 8) & 0xff
    qw_bytes[1] = (hi32 >> 0) & 0xff
    qw_bytes[2] = (lo32 >> 24) & 0xff
    qw_bytes[3] = (lo32 >> 16) & 0xff
    qw_bytes[4] = (lo32 >> 8) & 0xff
    qw_bytes[5] = (lo32 >> 0) & 0xff

    assert int.from_bytes(qw_bytes, byteorder="big", signed=False) == qw.value

    # TODO: maybe also test this on UScript side!?
    uscript_qw = QWord16()
    uscript_x = QWord16()
    uscript_unix_time = 82861
    uscript_msec = 859

    uscript_qw.c = (uscript_unix_time >> 16) & 0xffff
    uscript_qw.d = uscript_unix_time & 0xffff
    uscript_x.d = 1000

    uscript_qw, carry = qword16_mul(uscript_qw, uscript_x)
    uscript_qw = qword16_add_int(uscript_qw, uscript_msec)

    assert carry == 0
    assert uscript_qw.value == ((uscript_unix_time * 1000) + uscript_msec)

    hi32 = ((uscript_qw.a & 0xffff) << 16) | (uscript_qw.b & 0xffff)
    lo32 = ((uscript_qw.c & 0xffff) << 16) | (uscript_qw.d & 0xffff)
    assert (hi32 << 32) | lo32 == uscript_qw.value

    uscript_qw_bytes = bytearray(6)
    uscript_qw_bytes[0] = (hi32 >> 8) & 0xff
    uscript_qw_bytes[1] = hi32 & 0xff
    uscript_qw_bytes[2] = (lo32 >> 24) & 0xff
    uscript_qw_bytes[3] = (lo32 >> 16) & 0xff
    uscript_qw_bytes[4] = (lo32 >> 8) & 0xff
    uscript_qw_bytes[5] = lo32 & 0xff

    assert int.from_bytes(
        uscript_qw_bytes, byteorder="big", signed=False) == 0x4f05f23

    assert uscript_qw_bytes[0] == 0x00
    assert uscript_qw_bytes[1] == 0x00
    assert uscript_qw_bytes[2] == 0x04
    assert uscript_qw_bytes[3] == 0xf0
    assert uscript_qw_bytes[4] == 0x5f
    assert uscript_qw_bytes[5] == 0x23


def test_qword_operators():
    qw1 = QWord(0xFFFF_FFFF, 0xFFFF_FFFF)
    qw2 = QWord(0x0000_0000, 0x0000_0000)
    qw3 = QWord(0x0000_0000, 0x0000_0001)
    qw4 = QWord(0x0000_0001, 0x0000_0000)

    assert qw1.value == 0xFFFF_FFFF_FFFF_FFFF
    assert qw2.value == 0x0000_0000_0000_0000
    assert qw3.value == 0x0000_0000_0000_0001
    assert qw4.value == 0x0000_0001_0000_0000

    qw1_16 = QWord16(0x0000, 0x0000, 0x0002, 0x0022)
    qw2_16 = QWord16(0x0001, 0xabcd, 0x0002, 0x0022)
    qw3_16 = QWord16(0x0000, 0x0001, 0x1101, 0xfff1)
    qw4_16 = QWord16(0x1111, 0x1111, 0x1111, 0x1111)

    assert QWord.from_QWord16(qw1_16).value == qw1_16.value
    assert QWord.from_QWord16(qw2_16).value == qw2_16.value
    assert QWord.from_QWord16(qw3_16).value == qw3_16.value
    assert QWord.from_QWord16(qw4_16).value == qw4_16.value

    assert qw1.value > qw2.value
    assert qw1.value > qw3.value
    assert qw1.value > qw4.value
    assert qw2.value < qw1.value
    assert qw3.value < qw1.value
    assert qw4.value < qw1.value

    assert qw1 > qw2
    assert qw1 > qw3
    assert qw1 > qw4
    assert not (qw1 > qw1)
    assert qw3 > qw2
    assert qw4 > qw2
    assert qw4 > qw3

    assert qw2 < qw1
    assert qw3 < qw1
    assert qw4 < qw1
    assert not (qw2 < qw2)
    assert qw2 < qw3
    assert qw3 < qw4
