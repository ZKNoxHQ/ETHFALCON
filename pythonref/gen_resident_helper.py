#!/usr/bin/env python3
# gen_resident_helper.py -- wraps the unchanged straight-line Keccak-f[1600]
# body of the Fireblocks helper (test/f1600_170.hex, MIT, evm-ml-dsa-verifier
# @ cca262b) with two calldata interfaces:
#
#   800 bytes  25 clean uint64 lanes in, 25 clean lanes out (as the original)
#   832 bytes  one ignored prefix word, then 25 REPLICATED lanes (each 64-bit
#              lane copied four times in its word) in; 25 replicated lanes out
#
# The body works on replicated words: the original replicates on entry
# (multiply by 0x0001000100010001) and masks on exit, at every call. A caller
# that keeps the replicated form between permutations (ZKNOX_falcon_core8.sol)
# skips both. Any other calldata length reverts.
#
#   python3 pythonref/gen_resident_helper.py > test/f1600_resident.hex
#
# Layout of the original helper (checked here): dispatch on CALLDATASIZE, a
# SHAKE256 sponge path, and at 0x4f2a the 800-byte path that replicates the
# lanes into memory 0x320..0x620 and jumps to the body at 0x5a9, which is
# straight-line (scratch at 0x20..0x300, state at 0x320..0x620, no calldata
# or code-address use) and returns with `PUSH2 0x3f JUMP` to the loop head.
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
orig = bytes.fromhex(open(os.path.join(HERE, "..", "test", "f1600_170.hex")).read().strip().replace("0x", ""))
assert len(orig) == 21622, "unexpected helper"

BODY_START = 0x5A9  # JUMPDEST
BODY_END = 0x4F29  # the JUMP back to the sponge loop head
assert orig[BODY_START] == 0x5B and orig[BODY_END] == 0x56
assert orig[BODY_END - 3 : BODY_END] == bytes([0x61, 0x00, 0x3F]), "body tail is not PUSH2 0x3f"
body = orig[BODY_START + 1 : BODY_END - 3]
# straight-line: no jumps, no calldata access, no code addresses inside
i = 0
while i < len(body):
    op = body[i]
    assert op not in (0x56, 0x57, 0x5B, 0x35, 0x36, 0x37, 0x39, 0xF3, 0xFD, 0x00), f"control op {op:#x} at {i}"
    i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)

REP4 = bytes.fromhex("1000000000000000100000000000000010000000000000001".rjust(50, "0"))  # 25 bytes
STATE = [0x320 + 32 * k for k in range(25)]


def push2(v):
    return bytes([0x61, v >> 8, v & 0xFF])


def assemble(off_clean, off_resident, off_body, off_exit):
    """returns the code and the actual label offsets (the sizes do not depend on the
    offsets: every code address is a PUSH2)"""
    out = bytearray()
    labels = {}
    # dispatch
    out += bytes([0x36]) + push2(0x340) + bytes([0x14]) + push2(off_resident) + bytes([0x57])
    out += bytes([0x36]) + push2(0x320) + bytes([0x14]) + push2(off_clean) + bytes([0x57])
    out += bytes([0x5F, 0x5F, 0xFD])
    # clean path: state from calldata[0..800), replicated; mode word at 0x640 = 1 (mask on exit);
    # the body uses 0x00 and 0x20..0x300 as scratch, 0x320..0x620 as the state
    labels["clean"] = len(out)
    out += bytes([0x5B]) + push2(0x320) + bytes([0x5F]) + push2(0x320) + bytes([0x37])
    out += bytes([0x78]) + REP4
    for a in STATE:
        out += push2(a) + bytes([0x51, 0x81, 0x02]) + push2(a) + bytes([0x52])
    out += bytes([0x50, 0x60, 0x01]) + push2(0x640) + bytes([0x52])
    out += push2(off_body) + bytes([0x56])
    # resident path: state from calldata[32..832), already replicated; mode stays 0
    labels["resident"] = len(out)
    out += bytes([0x5B]) + push2(0x320) + bytes([0x60, 0x20]) + push2(0x320) + bytes([0x37])
    # body
    labels["body"] = len(out)
    out += bytes([0x5B]) + body
    # exit: mask iff mode
    out += push2(0x640) + bytes([0x51, 0x15]) + push2(off_exit) + bytes([0x57])
    out += bytes([0x67]) + bytes.fromhex("ffffffffffffffff")
    for a in STATE:
        out += push2(a) + bytes([0x51, 0x81, 0x16]) + push2(a) + bytes([0x52])
    out += bytes([0x50])
    labels["exit"] = len(out)
    out += bytes([0x5B]) + push2(0x320) + push2(0x320) + bytes([0xF3])
    return bytes(out), labels


_, lab = assemble(0, 0, 0, 0)
code, lab2 = assemble(lab["clean"], lab["resident"], lab["body"], lab["exit"])
assert lab == lab2
for k, v in lab.items():
    assert code[v] == 0x5B, k
sys.stdout.write(code.hex())
