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

"""Memory manipulation functions mirrored from UnrealScript."""

import numpy as np
from numpy import typing as npt


def memmove(
        dst: list[int],
        src: list[int],
        num_bytes: int,
        dst_offset: int = 0,
        src_offset: int = 0,
) -> list[int]:
    dst_bytes = [0] * num_bytes

    int_index = src_offset
    byte_index = 0
    shift = 8
    while byte_index < num_bytes:
        dst_bytes[byte_index] = (src[int_index] >> shift) & 0xff
        shift = (shift + 8) & 15
        int_index += byte_index & 1
        byte_index += 1

    shift = 8
    mask = 0xff << shift
    int_index = dst_offset
    for byte_index in range(num_bytes):
        dst_tmp = (dst[int_index] & ~mask) | ((dst_bytes[byte_index] & 0xff) << shift)
        dst[int_index] = dst_tmp

        shift = (shift + 8) & 15
        int_index += byte_index & 1
        mask = 0xff << shift

    return dst


def memmove_byte(
        src: npt.NDArray[np.uint8],
        dst: npt.NDArray[np.uint8],
        num_bytes: int,
        dst_offset: int = 0,
        src_offset: int = 0,
) -> npt.NDArray[np.uint8]:
    dst_bytes = np.zeros(num_bytes)
    byte_index = 0
    i = src_offset

    while byte_index < num_bytes:
        dst_bytes[byte_index] = src[i]
        byte_index += 1
        i += 1

    byte_index = dst_offset
    for i in range(num_bytes):
        dst[byte_index] = dst_bytes[i]
        byte_index += 1

    return dst


def test_memmove():
    arr = [0x4bc2, 0xcbea, 0xc810, 0xaa90, 0x9ab9, 0xbabd, 0x42a2, 0xa58c, 0xb873, 0x5da1]
    out = [0x4bc2, 0xaa90, 0x9ab9, 0xbabd, 0x42a2, 0xa58c, 0xb873, 0x5da1, 0xb873, 0x5da1]

    assert memmove(arr, arr, 14, 1, 3) == out


def test_memmove_byte():
    arr = np.array(
        [0x6f, 0x3a, 0xa1, 0x8a, 0x6e, 0x1c, 0xd3, 0x5a, 0x86, 0x98, 0xcb],
        dtype=np.uint8
    )
    out = np.array(
        [0x6f, 0x6e, 0x1c, 0xd3, 0x5a, 0x86, 0x98, 0x5a, 0x86, 0x98, 0xcb],
        dtype=np.uint8
    )

    assert np.array_equal(memmove_byte(arr, arr, 6, 1, 4), out)
