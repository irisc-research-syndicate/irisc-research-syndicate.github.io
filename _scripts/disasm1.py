#!/usr/bin/env python3
import sys
from pwnlib.util.misc import read
from pwnlib.util.lists import group
from pwnlib.util.packing import u32

for i, word in enumerate(map(lambda d: u32(d, endian="big"), group(4, read(sys.argv[1])))):
    address = i * 4
    op = (word >> 26) & 0x3f
    rs = (word >> 21) & 0x1f
    rd = (word >> 16) & 0x1f
    rt = (word >> 11) & 0x1f
    imm11 = word & 0x7ff
    imm16 = word & 0xffff
    print(f"{address:08x}:\t{word:08x}\top{op:02x} r{rs}, r{rd}, r{rt}, {imm16:#06x}")

