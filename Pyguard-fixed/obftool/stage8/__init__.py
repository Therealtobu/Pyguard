"""
Stage 8 – Outer Encryption Wrapper (JoJo Edition)
"""
from __future__ import annotations
import os, zlib, random, sys, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from common.jojo_namer import JoJoNameGenerator, make_emoji_map, encode_bytes_emoji

_K  = 0x1F
_ZL = list(b'zlib')
_FN = list(b'<w>')
_MD = list(b'exec')


def wrap(source: str, seed: int = 0) -> str:
    rng = random.Random(seed ^ 0xCAFED00D)

    compressed = zlib.compress(source.encode("utf-8"), level=9)

    key    = os.urandom(32)
    share1 = os.urandom(32)
    share2 = os.urandom(32)
    share3 = bytes(key[i] ^ share1[i] ^ share2[i] for i in range(32))

    encrypted = bytes(b ^ key[i % 32] for i, b in enumerate(compressed))

    arr_a = bytes(encrypted[i] for i in range(0, len(encrypted), 2))
    arr_b = bytes(encrypted[i] for i in range(1, len(encrypted), 2))

    emoji_map   = make_emoji_map(seed ^ 0xE0A1B2C3)
    emap_str    = "".join(emoji_map)
    ea = encode_bytes_emoji(arr_a, emoji_map)
    eb = encode_bytes_emoji(arr_b, emoji_map)

    ngen = JoJoNameGenerator(seed)
    v = [ngen.next() for _ in range(14)]

    zlib_enc = repr([b ^ _K for b in _ZL])
    fn_enc   = repr([b ^ _K for b in _FN])
    mode_enc = repr([b ^ _K for b in _MD])

    stub = [
        "# Protected by Pyguard V1",
        f"{v[0]}={repr(ea)}",
        f"{v[1]}={repr(eb)}",
        f"{v[2]}={repr(share1)}",
        f"{v[3]}={repr(share2)}",
        f"{v[4]}={repr(share3)}",
        f"{v[10]}={repr(emap_str)}",
        f"{v[11]}={{_e:_i for _i,_e in enumerate({v[10]})}}",
        f"{v[12]}=bytes([{v[11]}[_c] for _c in {v[0]}])",
        f"{v[13]}=bytes([{v[11]}[_c] for _c in {v[1]}])",
        (f"{v[5]}=bytes(_x for _p in zip({v[12]},{v[13]}) for _x in _p)"
         f"+(({v[12]} if len({v[12]})>len({v[13]}) else {v[13]})"
         f"[min(len({v[12]}),len({v[13]})):])" ),
        f"{v[6]}=bytes({v[2]}[_i]^{v[3]}[_i]^{v[4]}[_i] for _i in range(32))",
        f"{v[7]}=bytes({v[5]}[_i]^{v[6]}[_i%32] for _i in range(len({v[5]})))",
        f"def {v[8]}(_l,_k={_K}):return bytes([_b^_k for _b in _l]).decode()",
        f"{v[9]}=__import__({v[8]}({zlib_enc})).decompress({v[7]})",
        f"exec(compile({v[9]},{v[8]}({fn_enc}),{v[8]}({mode_enc})))",
    ]

    junk_tpls = ["_j{n}={a}^{b}", "_j{n}=({a}+{b})&0xFFFF", "_j{n}=({a}*{b})%65537", "_j{n}=not {a}"]

    result, jc = [], 0
    for line in stub:
        result.append(line)
        if line and not line.startswith("#") and not line[0].isspace() and rng.random() < 0.30:
            t = rng.choice(junk_tpls)
            result.append(t.format(n=jc, a=rng.randint(0,0xFFFF), b=rng.randint(1,0xFFFF)))
            jc += 1

    return "\n".join(result) + "\n"
