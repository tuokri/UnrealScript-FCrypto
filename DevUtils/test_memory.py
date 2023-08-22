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


def test_memmove():
    arr = [0x4bc2, 0xcbea, 0xc810, 0xaa90, 0x9ab9, 0xbabd, 0x42a2, 0xa58c, 0xb873, 0x5da1]
    out = [0x4bc2, 0xaa90, 0x9ab9, 0xbabd, 0x42a2, 0xa58c, 0xb873, 0x5da1, 0xb873, 0x5da1]

    assert memmove(arr, arr, 14, 1, 3) == out
