#!/usr/bin/env python3
# check_keccak_helper.py -- runs a helper bytecode (hex file) on a tiny EVM
# interpreter (the opcode subset the helpers use), compares both interfaces
# with a Python Keccak-f[1600] on random states, and reports the gas of one
# call (static opcode costs + memory expansion + calldata copy).
#
#   python3 pythonref/check_keccak_helper.py test/f1600_zknox.hex [test/f1600_resident.hex ...]
import random
import sys

MASK = (1 << 256) - 1
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
REP4 = 0x0000000000000001000000000000000100000000000000010000000000000001


def rotl(v, r):
    return ((v << r) | (v >> (64 - r))) & 0xFFFFFFFFFFFFFFFF if r else v


def keccak_f(a):
    a = a[:]
    for rnd in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y] ^ d[x], RHO[x][y])
        for y in range(5):
            for x in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= RC[rnd]
    return a


def run(code, calldata):
    stack, mem, pc, gas = [], bytearray(), 0, 0

    def expand(end):
        nonlocal gas
        if end > len(mem):
            words_old = (len(mem) + 31) // 32
            words_new = (end + 31) // 32
            gas += (3 * words_new + words_new * words_new // 512) - (3 * words_old + words_old * words_old // 512)
            mem.extend(b"\0" * (words_new * 32 - len(mem)))

    while True:
        op = code[pc]
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            stack.append(int.from_bytes(code[pc + 1 : pc + 1 + n], "big"))
            pc += 1 + n
            gas += 3
            continue
        pc += 1
        if op == 0x5F:
            stack.append(0); gas += 2
        elif 0x80 <= op <= 0x8F:
            stack.append(stack[-(op - 0x7F)]); gas += 3
        elif 0x90 <= op <= 0x9F:
            d = op - 0x8F
            stack[-1], stack[-1 - d] = stack[-1 - d], stack[-1]; gas += 3
        elif op == 0x50:
            stack.pop(); gas += 2
        elif op == 0x01:
            stack.append((stack.pop() + stack.pop()) & MASK); gas += 3
        elif op == 0x02:
            stack.append((stack.pop() * stack.pop()) & MASK); gas += 5
        elif op == 0x14:
            stack.append(1 if stack.pop() == stack.pop() else 0); gas += 3
        elif op == 0x15:
            stack.append(1 if stack.pop() == 0 else 0); gas += 3
        elif op == 0x16:
            stack.append(stack.pop() & stack.pop()); gas += 3
        elif op == 0x17:
            stack.append(stack.pop() | stack.pop()); gas += 3
        elif op == 0x18:
            stack.append(stack.pop() ^ stack.pop()); gas += 3
        elif op == 0x19:
            stack.append(stack.pop() ^ MASK); gas += 3
        elif op == 0x1B:
            s, v = stack.pop(), stack.pop(); stack.append((v << s) & MASK if s < 256 else 0); gas += 3
        elif op == 0x1C:
            s, v = stack.pop(), stack.pop(); stack.append(v >> s if s < 256 else 0); gas += 3
        elif op == 0x36:
            stack.append(len(calldata)); gas += 2
        elif op == 0x37:
            dst, off, n = stack.pop(), stack.pop(), stack.pop()
            expand(dst + n)
            src = calldata[off : off + n] + b"\0" * max(0, n - len(calldata[off : off + n]))
            mem[dst : dst + n] = src
            gas += 3 + 3 * ((n + 31) // 32)
        elif op == 0x51:
            a = stack.pop(); expand(a + 32); stack.append(int.from_bytes(mem[a : a + 32], "big")); gas += 3
        elif op == 0x52:
            a, v = stack.pop(), stack.pop(); expand(a + 32); mem[a : a + 32] = v.to_bytes(32, "big"); gas += 3
        elif op == 0x56:
            pc = stack.pop(); assert code[pc] == 0x5B; gas += 8
        elif op == 0x57:
            t, c = stack.pop(), stack.pop(); gas += 10
            if c:
                pc = t; assert code[pc] == 0x5B
        elif op == 0x5B:
            gas += 1
        elif op == 0xF3:
            a, n = stack.pop(), stack.pop(); expand(a + n)
            return bytes(mem[a : a + n]), gas
        elif op == 0xFD:
            return None, gas
        else:
            raise ValueError(f"opcode {op:#x} at {pc - 1}")


def check(path, trials=8, seed=1):
    code = bytes.fromhex(open(path).read().strip())
    rng = random.Random(seed)
    gas_clean = gas_res = None
    for t in range(trials):
        st = [rng.getrandbits(64) for _ in range(25)]
        exp = keccak_f(st)
        out, gas_clean = run(code, b"".join(v.to_bytes(32, "big") for v in st))
        assert out is not None and len(out) == 800, "clean call failed"
        got = [int.from_bytes(out[32 * k : 32 * k + 32], "big") for k in range(25)]
        assert got == exp, f"clean interface mismatch (trial {t})"
        out, gas_res = run(code, b"\0" * 32 + b"".join(((v * REP4) & MASK).to_bytes(32, "big") for v in st))
        assert out is not None and len(out) == 800, "resident call failed"
        got = [int.from_bytes(out[32 * k : 32 * k + 32], "big") for k in range(25)]
        assert got == [(v * REP4) & MASK for v in exp], f"resident interface mismatch (trial {t})"
    out, _ = run(code, b"\0" * 801)
    assert out is None, "801 bytes should revert"
    print(f"{path}: {len(code)} bytes, OK on {trials} states; gas clean {gas_clean}, resident {gas_res}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        check(p)
