#!/usr/bin/env python3
import sys
from collections import defaultdict
from pwnlib.util.misc import read
from pwnlib.util.lists import group
from pwnlib.util.packing import u32

def sx(bits, width):
    return bits - (1 << width) if bits & (1 << (width - 1)) else bits

fields_decoders = {
    "op": lambda a, w: (w >> 26) & 0x3f,
    "rs": lambda a, w: (w >> 21) & 0x1f,
    "rd": lambda a, w: (w >> 16) & 0x1f,
    "rt": lambda a, w: (w >> 11) & 0x1f,
    "shamt": lambda a, w: (w >> 11) & 0x1f,
    "imm16": lambda a, w: w & 0xffff,
    "simm16": lambda a, w: sx(w & 0xffff, 16),
    "imm11": lambda a, w: w & 0x7ff,
    "simm11": lambda a, w: sx(w & 0x7ff, 11),
    "stoff16": lambda a, w: sx((((w >> 16) & 0x1f) << 11) | (w & 0x7ff), 16),
    "subop": lambda a, w: w & 0x7ff,
    "jmpop": lambda a, w: (w >> 24) & 0x3,
    "jmpoff": lambda a, w: a + (sx(w & 0xffffff, 24) << 2),
    "branchoff": lambda a, w: a + (sx(w & 0xffff, 16) << 2),
}

table = lambda table, field, default: lambda fs: table.get(fs[field], default)(fs)
opcodes = table(
    table = {
        0x00: lambda fs: "add r{rd}, r{rs}, {simm16}".format(**fs),
        0x05: lambda fs: "cmp r{rd}, r{rs}, {imm16:#06x}".format(**fs),
        0x06: lambda fs: "set0 r{rd}, r{rs}, {imm16:#06x}".format(**fs),
        0x07: lambda fs: "set1 r{rd}, r{rs}, {imm16:#06x}".format(**fs),
        0x08: lambda fs: "set2 r{rd}, r{rs}, {imm16:#06x}".format(**fs),
        0x09: lambda fs: "set3 r{rd}, r{rs}, {imm16:#06x}".format(**fs),
        0x19: lambda fs: "ld.d r{rd}, r{rs}, {imm11:#05x}".format(**fs),
        0x1b: lambda fs: "st.d r{rt}, r{rs}, {stoff16:#06x}".format(**fs),
        0x1c: lambda fs: "st.d! r{rt}, r{rs}, {stoff16:#06x}".format(**fs),
        0x1e: lambda fs: "st.q r{rt}, r{rs}, {stoff16:#06x}".format(**fs),
        0x25: table(
            table = {
                0x00: lambda fs: "call {jmpoff:#010x}".format(**fs),
            },
            field = "jmpop",
            default = lambda fs: "jump.{jmpop} {jmpoff:#010x}".format(**fs),
        ),
        0x29: lambda fs: "b.{rs}.{rd} {branchoff:#010x}".format(**fs),
        0x3f: table(
            table = {
                0x000: lambda fs: "add r{rd}, r{rs}, r{rt}".format(**fs),
                0x008: lambda fs: "or r{rd}, r{rs}, r{rt}".format(**fs),
                0x00a: lambda fs: "and r{rd}, r{rs}, r{rt}".format(**fs),
                0x00e: lambda fs: "xor r{rd}, r{rs}, r{rt}".format(**fs),
                0x081: lambda fs: "shr r{rd}, r{rs}, {shamt}".format(**fs),
                0x083: lambda fs: "shl r{rd}, r{rs}, {shamt}".format(**fs),
                0x219: lambda fs: "ld.d r{rd}, r{rs}, r{rt}".format(**fs),
            },
            field = "subop",
            default = lambda fs: "alu.{subop:03x} r{rs}, r{rd}, r{rt}".format(**fs)
        ),
    },
    field = "op",
    default = lambda fs: "unk.{op:02x} r{rs}, r{rd}, r{rt}, {imm16:#06x}".format(**fs)
)
    
for i, word in enumerate(map(lambda d: u32(d, endian="big"), group(4, read(sys.argv[1])))):
    address = i * 4
    fields = {op: f(address, word) for op, f in fields_decoders.items()}
    inst = opcodes(fields)
    print(f"{address:08x}:\t{word:08x}\t{inst}")
