import itertools
from pathlib import Path
from typing import List


def strip_leading_zeros(word: str) -> str:
    """Strip leading 'zero words'.
    00 03 -> 03
    00 45 -> 45
    11 A5 -> 11 A5
    """
    w_split = [w for w in word.split(" ")]
    if len(w_split) == 1:
        return word
    words = []
    leading_zeros = (w_split[0] == "00")
    for ws in w_split:
        leading_zeros = leading_zeros and (ws == "00")
        if not leading_zeros:
            words.append(ws)
    words = [w for w in words if w]
    return " ".join(words)


def split_words(words: List[str]) -> str:
    """Split 2-byte words into 1-byte words.
    'FFFF AAAA' -> 'FF FF AA AA'
    """
    x = [[w[:2], w[2:]] for w in words]
    x_flat = itertools.chain.from_iterable(x)
    xx = " ".join(x_flat)
    return strip_leading_zeros(xx)


def bytes_to_uscript_array(words: str) -> str:
    x = [str(int(w, 16)) for w in words.split(" ")]
    return ",".join(x)


def main():
    primes_in = Path("primes.txt").read_text()
    p_lines = [p for p in primes_in.split("\n") if p]
    p_lines = [p.split(" ") for p in p_lines]
    p_lines = [split_words(p) for p in p_lines]
    p_lines = [
        f"    Primes({i})=(P=({bytes_to_uscript_array(p)}))"
        for i, p in enumerate(p_lines)
    ]
    Path("primes_out.txt").write_text("\n".join(p_lines))
    for pl in p_lines:
        print(pl)


if __name__ == "__main__":
    main()
