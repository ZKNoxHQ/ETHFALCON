#!/usr/bin/env python3
# gen_keccak_helper.py -- a Keccak-f[1600] helper contract of our own, in the
# same "Q-form" as the Fireblocks helper (each 64-bit lane replicated four
# times in a 256-bit word, so that rotl_r(v) = or(shl(r, X), shr(64 - r, X))
# with no mask: copies 1..3 come out of the shl, copy 0 out of the shr) and
# with the same two calldata interfaces as test/f1600_resident.hex:
#
#   800 bytes  25 clean lanes in, 25 clean lanes out
#   801 bytes  25 replicated lanes (+ one ignored byte) in, replicated out
#   other      SHAKE256 of the calldata, first 136 bytes of output
#
# The 24 rounds are straight-line. The state lives in memory (two buffers,
# read from one and written to the other each round); the column parities,
# the theta words and the five lanes of the row being written are the only
# values on the stack, placed by a symbolic stack tracker that emits the
# DUP/SWAP it needs and refuses any depth beyond 16.
#
#   python3 pythonref/gen_keccak_helper.py > test/f1600_zknox.hex
#   python3 pythonref/check_keccak_helper.py test/f1600_zknox.hex   (mini-EVM check + gas)
#
# Options (environment):
#   RHO4=1   rotate rho with shr(64, shl(r, X)) (4 opcodes, loses one valid
#            copy per round) and re-replicate every lane every REREP rounds
import os
import sys

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
M64 = 0xFFFFFFFFFFFFFFFF

S0 = 0x320  # 25 words
S1 = 0x660

RHO4 = os.environ.get("RHO4", "1") == "1"
LC = os.environ.get("LC", "1") == "1"
# lanes stored complemented (x + 5y): a fixed point of the round on complement
# flags found by exhaustive search (pythonref notes): chi then needs 7 NOTs per
# round instead of 25
LC_LANES = (0, 5, 8, 14, 16, 20) if LC else ()


def _flags_before_chi(F):
    C = [F[x] ^ F[x + 5] ^ F[x + 10] ^ F[x + 15] ^ F[x + 20] for x in range(5)]
    D = [C[(x - 1) % 5] ^ C[(x + 1) % 5] for x in range(5)]
    F1 = [F[i] ^ D[i % 5] for i in range(25)]
    B = [0] * 25
    for x in range(5):
        for y in range(5):
            B[y + 5 * ((2 * x + 3 * y) % 5)] = F1[x + 5 * y]
    return B


def chi_plan():
    """per output lane (x + 5y): (operand fetched first, NOT it?, op byte) so that the
    stored lane carries the pattern's flag again; second operand is the other one"""
    F = [1 if i in LC_LANES else 0 for i in range(25)]
    B = _flags_before_chi(F)
    plan = {}
    nots = 0
    for y in range(5):
        for x in range(5):
            i = x + 5 * y
            f0, f1, f2 = B[i], B[(x + 1) % 5 + 5 * y], B[(x + 2) % 5 + 5 * y]
            want = F[i]
            if f1 == 1 and f2 == 0:
                assert want == f0
                plan[i] = ("b1", False, 0x16)  # b1' & b2
            elif f1 == 0 and f2 == 1:
                assert want == f0 ^ 1
                plan[i] = ("b1", False, 0x17)  # b1 | b2' (output complemented)
            elif f1 == 1:  # (1,1)
                nots += 1
                plan[i] = ("b2", True, 0x16) if want == f0 else ("b1", True, 0x17)
            else:  # (0,0)
                nots += 1
                plan[i] = ("b1", True, 0x16) if want == f0 else ("b2", True, 0x17)
    return plan, nots


CHI_PLAN, CHI_NOTS = chi_plan()
CHI_ORDER = tuple(int(c) for c in os.environ.get("CHI", "12430"))
D_ORDER = tuple(int(c) for c in os.environ.get("DORD", "01234"))
REREP = int(os.environ.get("REREP", "3"))  # lanes lose one valid copy per round (rho), theta words are re-replicated every round


class Emit:
    def __init__(self):
        self.code = bytearray()
        self.stack = []  # bottom .. top, labels
        self.max_depth = 0

    def _op(self, b):
        self.code.append(b)

    # code labels: PUSH2 placeholders patched once every label is placed
    labels = {}
    fixups = []

    def label(self, name):
        self.labels[name] = len(self.code)
        self._op(0x5B)

    def push_label(self, name):
        self._op(0x61)
        self.fixups.append((len(self.code), name))
        self.code += b"\0\0"
        self.stack.append("#")

    def patch(self):
        for pos, name in self.fixups:
            off = self.labels[name]
            assert self.code[off] == 0x5B
            self.code[pos] = off >> 8
            self.code[pos + 1] = off & 0xFF

    def jump(self, name):
        self.push_label(name)
        self._op(0x56)
        self.stack.pop()

    def jumpi(self, name):
        """consumes the condition on top"""
        self.push_label(name)
        self._op(0x57)
        self.stack.pop()
        self.stack.pop()

    def call_body(self, ret):
        self.push_label(ret)
        self.jump("BODY")
        self.stack.pop()  # the body consumes the return address when it jumps back
        self.label(ret)

    def grev(self):
        """top := its bytes reversed within each 64-bit group"""
        for mask, s in ((0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00, 8), (0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000, 16), (0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000, 32)):
            w = self.stack[-1]
            self.dup(w)
            self.push(mask)
            self.binop(0x16, "a")
            self.dup("a")
            self.push(s)
            self.binop(0x1C, "hi")
            self.swap_to_top(w)
            self.binop(0x18, "x")
            self.push(s)
            self.binop(0x1B, "lo")
            self.binop(0x17, w)

    def push(self, v):
        if v == 0:
            self._op(0x5F)
        else:
            n = (v.bit_length() + 7) // 8
            self._op(0x5F + n)
            self.code += v.to_bytes(n, "big")
        self.stack.append("#")

    def depth(self, label):
        for d in range(1, len(self.stack) + 1):
            if self.stack[-d] == label:
                return d
        raise KeyError(label)

    def dup(self, label):
        d = self.depth(label)
        assert d <= 16, f"dup depth {d} for {label}"
        self.max_depth = max(self.max_depth, d)
        self._op(0x7F + d)
        self.stack.append(label)

    def swap_to_top(self, label):
        d = self.depth(label)
        if d == 1:
            return
        assert d <= 17, f"swap depth {d} for {label}"
        self.max_depth = max(self.max_depth, d)
        self._op(0x8F + (d - 1))
        self.stack[-1], self.stack[-d] = self.stack[-d], self.stack[-1]

    def pop(self):
        self._op(0x50)
        self.stack.pop()

    def binop(self, b, label):
        self._op(b)
        self.stack.pop()
        self.stack.pop()
        self.stack.append(label)

    def unop(self, b, label):
        self._op(b)
        self.stack.pop()
        self.stack.append(label)

    def mload(self, addr, label):
        self.push(addr)
        self.unop(0x51, label)

    def mstore(self, addr):
        """stores the top of the stack"""
        self.push(addr)
        self._op(0x52)
        self.stack.pop()
        self.stack.pop()

    def rot(self, r, label):
        """top := rotl_r(top), all four copies valid in, all four valid out"""
        if r == 0:
            self.stack[-1] = label
            return
        src = self.stack[-1]
        self.dup(src)
        self.push(r)
        self.binop(0x1B, "L")  # shl(r, x)
        self.swap_to_top(src)
        self.push(64 - r)
        self.binop(0x1C, "R")  # shr(64 - r, x)
        self.binop(0x17, label)

    def rot4(self, r, label):
        """top := rotl_r(top) in copies 0..2 (copy 3 zero): shr(64, shl(r, x))"""
        if r == 0:
            self.stack[-1] = label
            return
        self.push(r)
        self.binop(0x1B, "L")
        self.push(64)
        self.binop(0x1C, label)

    def rerep(self):
        """top := its copy 0 replicated four times"""
        self.push(M64)
        self.binop(0x16, "m")
        self.push(REP4)
        self.binop(0x02, "rep")


def lane(buf, x, y):
    return buf + 32 * (x + 5 * y)


def keccak_round(e, rnd, src, dst, rerep_now):
    # theta 1: column parities C[x] on the stack
    for x in range(5):
        e.mload(lane(src, x, 0), f"c{x}")
        for y in range(1, 5):
            e.mload(lane(src, x, y), "a")
            e.binop(0x18, f"c{x}")
    # theta 2: D[x] = C[x-1] ^ rotl1(C[x+1]); each C is used twice, a last use is
    # consumed in place when it sits where the operation takes it
    cuses = {f"c{k}": 2 for k in range(5)}

    def cfetch(lbl, at):
        cuses[lbl] -= 1
        if cuses[lbl] == 0 and e.depth(lbl) == at:
            return
        e.dup(lbl)

    for x in D_ORDER:
        cfetch(f"c{(x + 1) % 5}", 1)
        if RHO4:
            # shr(64, shl(1, C)) loses one copy; the theta word is re-replicated from
            # its copy 0 right after, so it never carries garbage into the lanes
            e.rot4(1, "r")
        else:
            e.rot(1, "r")
        cfetch(f"c{(x - 1) % 5}", 2)
        e.binop(0x18, f"d{x}")
        if RHO4:
            e.dup("K64")
            e.binop(0x16, "m")
            e.dup("KREP")
            e.binop(0x02, f"d{x}")
    # drop whatever C's were not consumed
    for k in range(5):
        if f"c{k}" in e.stack:
            e.swap_to_top(f"c{k}")
            e.pop()
    # rho, pi, chi, iota: output row y', lanes x' = 0..4 from A[x, y] with y = x', x = 3 (y' - 3 x') mod 5
    for yp in range(5):
        for xp in range(5):
            y = xp
            x = (3 * (yp - 3 * xp)) % 5
            e.mload(lane(src, x, y), "a")
            e.dup(f"d{x}")
            e.binop(0x18, "t")
            if RHO4:
                e.rot4(RHO[x][y], f"b{xp}")
            else:
                e.rot(RHO[x][y], f"b{xp}")
        # chi: out[x'] = b[x'] ^ (~b[x'+1] & b[x'+2]). Each b is used three times;
        # a last use is consumed in place when the operand sits where the operation
        # takes it (on top for NOT, right below the top for AND / XOR), else dup'd.
        uses = {f"b{k}": 3 for k in range(5)}

        def fetch(lbl, at):
            uses[lbl] -= 1
            if uses[lbl] == 0 and e.depth(lbl) == at:
                return
            e.dup(lbl)

        for xp in CHI_ORDER:
            first, do_not, opb = CHI_PLAN[xp + 5 * yp]
            b1, b2 = f"b{(xp + 1) % 5}", f"b{(xp + 2) % 5}"
            fetch(b1 if first == "b1" else b2, 1)
            if do_not:
                e.unop(0x19, "n")
            fetch(b2 if first == "b1" else b1, 2)
            e.binop(opb, "n")
            fetch(f"b{xp}", 2)
            e.binop(0x18, "o")
            if xp == 0 and yp == 0:
                e.push(RC[rnd] * REP4)
                e.binop(0x18, "o")
            if rerep_now:
                e.dup("K64")
                e.binop(0x16, "m")
                e.dup("KREP")
                e.binop(0x02, "rep")
            e.mstore(lane(dst, xp, yp))
        # whatever b's were not consumed are popped
        while e.stack and e.stack[-1].startswith("b"):
            e.pop()
        assert all(v == 0 for v in uses.values())
    for x in range(5):
        e.pop()
    assert e.stack == (["ret", "K64", "KREP"] if RHO4 else ["ret"]), e.stack


SCR = 0x9C0  # 136-byte block scratch (5 words)
OUT = 0xAC0  # squeeze output (5 words)


def emit_body(e):
    """the 24 rounds on the (complemented) state at S0; return address on the stack"""
    e.label("BODY")
    e.stack.append("ret")
    if RHO4:
        e.push(M64)
        e.stack[-1] = "K64"
        e.push(REP4)
        e.stack[-1] = "KREP"
    for rnd in range(24):
        src, dst = (S0, S1) if rnd % 2 == 0 else (S1, S0)
        rerep_now = RHO4 and (rnd % REREP == REREP - 1 or rnd == 23)
        keccak_round(e, rnd, src, dst, rerep_now)
    if RHO4:
        e.pop()
        e.pop()
    assert e.stack == ["ret"], e.stack
    e._op(0x56)
    e.stack.pop()


def complement(e, lanes=LC_LANES):
    for i in lanes:
        e.mload(S0 + 32 * i, "v")
        e.unop(0x19, "v")
        e.mstore(S0 + 32 * i)


def absorb_block(e):
    """XOR the 136 bytes at SCR (little-endian lanes) into the replicated state"""
    for k in range(5):
        e.mload(SCR + 32 * k, "w")
        e.grev()
        for m in range(4 if k < 4 else 1):
            j = 4 * k + m
            e.dup("w")
            if m < 3:
                e.push(192 - 64 * m)
                e.binop(0x1C, "l")
            e.push(M64)
            e.binop(0x16, "l")
            e.push(REP4)
            e.binop(0x02, "l")
            e.mload(S0 + 32 * j, "s")
            e.binop(0x18, "s")
            e.mstore(S0 + 32 * j)
        e.pop()


def build():
    e = Emit()
    e.labels, e.fixups = {}, []
    # dispatch: 801 -> resident permutation (25 replicated lanes + one ignored
    # byte, so that no 32-byte-aligned message length collides), 800 -> clean
    # permutation, else SHAKE256 of the calldata
    e._op(0x36); e.stack.append("n")
    e.push(801); e.binop(0x14, "c"); e.jumpi("RES")
    e._op(0x36); e.stack.append("n")
    e.push(800); e.binop(0x14, "c"); e.jumpi("CLEAN")
    # ---- SHAKE256(calldata), first 136 bytes of output ----------------------
    # state = zero, pattern lanes complemented (all ones)
    for i in LC_LANES:
        e.push(0); e.unop(0x19, "v"); e.mstore(S0 + 32 * i)
    e.push(0); e.stack[-1] = "off"
    e._op(0x36); e.stack.append("rem")
    e.label("LOOP")
    e.dup("rem"); e.push(136); e.binop(0x11, "c")  # 136 > rem
    e.jumpi("LAST")
    e.push(136); e.dup("off"); e.push(SCR); e._op(0x37); e.stack.pop(); e.stack.pop(); e.stack.pop()
    absorb_block(e)
    e.call_body("R1")
    # off += 136 ; rem -= 136
    e.swap_to_top("off"); e.push(136); e.binop(0x01, "off"); e.swap_to_top("rem")
    e.push(136); e.swap_to_top("rem"); e.binop(0x03, "rem")
    e.jump("LOOP")
    e.label("LAST")
    # last block: rem bytes (zero-padded by CALLDATACOPY), 0x1f at rem, 0x80 on byte 135
    e.push(136); e.dup("off"); e.push(SCR); e._op(0x37); e.stack.pop(); e.stack.pop(); e.stack.pop()
    e.push(0x1F); e.dup("rem"); e.push(SCR); e.binop(0x01, "p"); e._op(0x53); e.stack.pop(); e.stack.pop()
    e.mload(SCR + 104, "t"); e.push(0x80); e.binop(0x17, "t"); e.mstore(SCR + 104)
    e.pop(); e.pop()
    absorb_block(e)
    e.call_body("R2")
    complement(e, [i for i in LC_LANES if i < 17])
    # squeeze: lanes 4k..4k+3 into output word k, bytes reversed within each lane
    for k in range(5):
        for m in range(4 if k < 4 else 1):
            e.mload(S0 + 32 * (4 * k + m), "l")
            e.push(M64); e.binop(0x16, "l")
            if m < 3:
                e.push(192 - 64 * m); e.binop(0x1B, "l")
            if m > 0:
                e.binop(0x17, "l")
        e.grev()
        e.mstore(OUT + 32 * k)
    e.push(136); e.push(OUT); e._op(0xF3); e.stack.clear()
    # ---- clean permutation ----------------------------------------------------
    e.label("CLEAN")
    e.push(800); e.push(0); e.push(S0); e._op(0x37); e.stack.pop(); e.stack.pop(); e.stack.pop()
    e.push(REP4); e.stack[-1] = "K"
    for k in range(25):
        e.mload(S0 + 32 * k, "v"); e.dup("K"); e.binop(0x02, "v"); e.mstore(S0 + 32 * k)
    e.pop()
    complement(e)
    e.call_body("R3")
    complement(e)
    e.push(M64); e.stack[-1] = "K"
    for k in range(25):
        e.mload(S0 + 32 * k, "v"); e.dup("K"); e.binop(0x16, "v"); e.mstore(S0 + 32 * k)
    e.pop()
    e.push(800); e.push(S0); e._op(0xF3); e.stack.clear()
    # ---- resident permutation -------------------------------------------------
    e.label("RES")
    e.push(800); e.push(0); e.push(S0); e._op(0x37); e.stack.pop(); e.stack.pop(); e.stack.pop()
    complement(e)
    e.call_body("R4")
    complement(e)
    e.push(800); e.push(S0); e._op(0xF3); e.stack.clear()
    # ---- the permutation body -------------------------------------------------
    emit_body(e)
    e.patch()
    return bytes(e.code), e.max_depth


if __name__ == "__main__":
    code, md = build()
    sys.stderr.write(f"{len(code)} bytes, max stack depth used {md}, NOTs per round {CHI_NOTS}\n")
    sys.stdout.write(code.hex())
