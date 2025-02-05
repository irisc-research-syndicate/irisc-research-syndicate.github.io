#!/usr/bin/env python3
import sys
from collections import defaultdict
from pwnlib.util.misc import read
from pwnlib.util.lists import group
from pwnlib.util.packing import u32

fields_decoders = {
    "op": lambda w: (w >> 26) & 0x3f,
    "rs": lambda w: (w >> 21) & 0x1f,
    "rd": lambda w: (w >> 16) & 0x1f,
    "rt": lambda w: (w >> 11) & 0x1f,
    "imm16": lambda w: w & 0xffff,
    "imm11": lambda w: w & 0x7ff,
}

opcodes = defaultdict(lambda: lambda fs: "unk.{op:02x} r{rs}, r{rd}, r{rt}, {imm16:#06x}".format(**fs))
opcodes[0x1b] = lambda fs: "st.d r{rt}, r{rs}, {imm11:#05x}".format(**fs)
opcodes[0x19] = lambda fs: "ld.d r{rd}, r{rs}, {imm11:#05x}".format(**fs)
    
for i, word in enumerate(map(lambda d: u32(d, endian="big"), group(4, read(sys.argv[1])))):
    address = i * 4
    fields = {op: f(word) for op, f in fields_decoders.items()}
    inst = opcodes[fields["op"]](fields)
    print(f"{address:08x}:\t{word:08x}\t{inst}")

