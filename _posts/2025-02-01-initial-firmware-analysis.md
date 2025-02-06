---
title: ConnectX-5 Firmware tooling and initial analysis
author: Jonas Rudloff
layout: post
---

NVIDIA/Mellanox has made a series of smart network interface cards(SmartNICs/NICs) called ConnectX primarily for server and datacenter uses. In this series of articles we will take a look at its firmware.

The ConnectX family of devices also seem to form a basis for the BlueField family of NICs(basically a ConnectX + user controllable embedded ARM system running Linux) as well as some of their switch technology.

The features set of these NICs are quite complex and includes at least the following:

- SR-IOV: Making a single physical NIC pretend to be multiple PCIe device enabling it to accelerate network access from virtual machines. This technology bypasses the hosts network stack entirely by making it a matter of PCIe pass-through of the virtual hardware to a VM. [1, 2]

- Many off loading capabilities: the NICs can manipulate headers and checksums in packets on the fly, this for instance enables vlan isolation of different virtual functions. [1, 2]

- Newer generations of ConnectX cards have encryption capabilities such as IPSEC or TLS acceleration.[2] (As an example, Netflix uses this to deliver TLS encrypted video at speeds of 400GB/s on single server[3])

- Infiniband: A Remote memory access technology which enables tightly coupled parallel applications to run on multiple machines simultaneously with low overhead.[1, 2]

- Signed firmware updates using RSA public key crypto

Attacking NICs is also a very interesting target as we have direct access NICs from the network and well as NICs having access to PCIe and therefor has DMA access to the host machines memory. There is nothing to do about this fact, it is what NIC are made for: shuffling packets between the network and the host machine.

For this article we will analyse the firmware named:

`fw-ConnectX5-rel-16_35_4030-MCX566M-GDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin`

Firmware tooling
================
NVIDIA publishes open-source drivers[4] and tooling[5] of interacting with these SmartNICs.

The drivers are pretty high quality with a lot of the NICs features documented and some very useful debug and tracing capabilities.

`mstflint`
==========
`mstflint` is the firmware management tool, this is the their own description from their documentation:
```
flint is a FW (firmware) burning and flash memory operations tool for Mellanox Infiniband HCAs, Ethernet NIC cards, and switch devices.
```

A few really interesting commands are:
```
burn|b [-ir]        : Burn flash. Use "-ir burn" flag to perform image reactivation prior burning.
query|q [full]      : Query misc. flash/firmware characteristics, use "full" to get more information.
verify|v [showitoc] : Verify entire flash, use "showitoc" to see ITOC headers in FS3/FS4 image only.
ri   <out-file>     : Read the fw image on the flash.
```
In particular the `verify [showitoc]` command looks very interesting as it seems to be able to parse the firmware images and dump sections of it. Lets try it!

```
$ mstflint -i fw.bin v
FS4 failsafe image
     /0x00000018-0x0000001f (0x000008)/ (HW_POINTERS) - OK
... snip: more HW_POINTERs ...
     /0x00000090-0x00000097 (0x000008)/ (HW_POINTERS) - OK
     /0x00000500-0x0000053f (0x000040)/ (TOOLS_AREA) - OK
     /0x00001000-0x00003a8b (0x002a8c)/ (BOOT2) - OK
     /0x00005000-0x0000501f (0x000020)/ (ITOC_HEADER) - OK
     /0x00007000-0x0001c613 (0x015614)/ (IRON_PREP_CODE) - OK
     /0x0001c614-0x0001c713 (0x000100)/ (RESET_INFO) - OK
     /0x0001c748-0x003edce7 (0x3d15a0)/ (MAIN_CODE) - OK
     /0x003edce8-0x004019b7 (0x013cd0)/ (PCIE_LINK_CODE) - OK
     /0x004019b8-0x00402547 (0x000b90)/ (POST_IRON_BOOT_CODE) - OK
     /0x00402548-0x00430687 (0x02e140)/ (PCI_CODE) - OK
     /0x00430688-0x00432327 (0x001ca0)/ (UPGRADE_CODE) - OK
     /0x00432328-0x0043bc47 (0x009920)/ (PHY_UC_CODE) - OK
     /0x0043bc48-0x0043dac7 (0x001e80)/ (PCIE_PHY_UC_CODE) - OK
... snip: sections we don't care about ...
-I- FW image verification succeeded. Image is bootable.
```

These section of the firmware we can extract with either `dd` or byte slicing in python. We decided to have a look at `IRON_PREP_CODE` first,
```
$ dd if=fw.bin of=IRON_PREP_CODE bs=1 iseek=$((0x7000)) count=$((0x015614))
87572+0 records in
87572+0 records out
87572 bytes (88 kB, 86 KiB) copied, 0.0831351 s, 1.1 MB/s
```

We can get then take a look at the contents:
```
$ phd -c 0x100 IRON_PREP_CODE 
00000000  48 03 00 bc  6c 20 18 06  70 3f 0f e2  6c 20 98 1e  │H···│l ··│p?··│l ··│
00000010  6c 20 a0 1a  6c 20 a8 16  6c 20 b0 12  6c 20 b8 0e  │l ··│l ··│l ··│l ··│
00000020  fd 57 50 08  fd 36 48 08  fd 15 40 08  fc f4 38 08  │·WP·│·6H·│··@·│··8·│
00000030  fc d3 30 08  00 06 00 01  14 a7 00 01  a0 01 00 05  │··0·│····│····│····│
00000040  4a 06 00 02  14 c7 00 00  a0 00 00 12  fc c6 20 0a  │J···│····│····│·· ·│
00000050  4a 04 00 03  14 c6 00 00  a0 00 00 0e  2c 86 00 ff  │J···│····│····│,···│
00000060  fc a5 30 05  a0 02 00 0b  fc 84 80 83  14 85 00 00  │··0·│····│····│····│
00000070  a0 00 00 02  94 00 3e 72  fe 64 98 08  fe 85 a0 08  │····│··>r│·d··│····│
00000080  fe a6 a8 08  fe c7 b0 08  fe e8 b8 08  94 00 00 b8  │····│····│····│····│
00000090  64 37 00 0e  64 36 00 12  64 35 00 16  64 34 00 1a  │d7··│d6··│d5··│d4··│
000000a0  64 33 00 1e  00 21 00 20  64 23 00 06  fd 00 18 25  │d3··│·!· │d#··│···%│
000000b0  48 03 00 bc  6c 20 18 06  70 3f 0f f2  6c 20 b0 0e  │H···│l ··│p?··│l ··│
000000c0  6c 20 b8 0a  fc f7 38 08  fc d6 30 08  00 06 00 01  │l ··│··8·│··0·│····│
000000d0  14 a7 00 01  a0 01 00 05  4a 06 00 02  14 c7 00 00  │····│····│J···│····│
000000e0  a0 00 00 0f  fc c6 20 0a  4a 04 00 03  14 c6 00 00  │····│·· ·│J···│····│
000000f0  a0 00 00 0b  2c 86 00 ff  fc a5 30 05  a0 02 00 08  │····│,···│··0·│····│
00000100
```

Initial observations:
- `00000000 - 00000020`: of the first 32 bytes of the firmware each the byte sequence `6c 20` repeats and always at aligned offsets.
- `000000b0` the first 4 bytes `48 03 00 bc` is present again followed by a similar pattern of `6c 20`.
- `00000090 - 000000b0`: there is a pattern of `64 3x 00 yy` where the `yy` matches with the first sequence of `6c 20 zz yy` at the beginning.
- seems to be big endian as the `yy` bytes seem to be counting/offsetting something.

As someone with experience of reverse engineering these patterns looks quite familiar, they look like function prologue and epilogue, which in pseudo assembly look like:

```
... unknown instruction ...
store ra, [sp + offset] 
... unknown instruction, maybe changing sp ...
store rb, [sp + offset - 0]
store rc, [sp + offset - 4]
store rd, [sp + offset - 8]
store re, [sp + offset - 12]
store rf, [sp + offset - 16]
store rg, [sp + offset - 20]

... function body, which we can't comprehend yet... 

load rg, [sp + offset - 20]
load rf, [sp + offset - 16]
load re, [sp + offset - 12]
load rd, [sp + offset - 8]
load rc, [sp + offset - 4]
load rb, [sp + offset - 0]
... unknown instruction, maybe restoring sp ...
load ra, [sp + offset]
return / indirect jump to return address
```

Guessing an instruction set
===========================
According to some documentation, error messages in the kernel driver, and the source code for the user space tooling, these NICs contains a(or multiple) embedded processors called with an architecture called iRISC. There is no description of the architecture anywhere on the internet, however we can make some educated guesses on how they work based on prior work.

The MIPS instruction set has roughly the following format:
```
| 6bit opcode | 5bit reg | 5bit reg | 5bit | 11bit immidiate |
| 6bit opcode | 5bit reg | 5bit reg |    16bit immidiate     |
```

Assuming that the iRISC as a similar layout, we can make a very primitive disassembler:
```python
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

```

This assembler gives us the following output:

```
00000000:       480300bc        op12 r0, r3, r0, 0x00bc
00000004:       6c201806        op1b r1, r0, r3, 0x1806
00000008:       703f0fe2        op1c r1, r31, r1, 0x0fe2
0000000c:       6c20981e        op1b r1, r0, r19, 0x981e
00000010:       6c20a01a        op1b r1, r0, r20, 0xa01a
00000014:       6c20a816        op1b r1, r0, r21, 0xa816
00000018:       6c20b012        op1b r1, r0, r22, 0xb012
0000001c:       6c20b80e        op1b r1, r0, r23, 0xb80e
... snip: function body ...
00000090:       6437000e        op19 r1, r23, r0, 0x000e
00000094:       64360012        op19 r1, r22, r0, 0x0012
00000098:       64350016        op19 r1, r21, r0, 0x0016
0000009c:       6434001a        op19 r1, r20, r0, 0x001a
000000a0:       6433001e        op19 r1, r19, r0, 0x001e
000000a4:       00210020        op00 r1, r1, r0, 0x0020
000000a8:       64230006        op19 r1, r3, r0, 0x0006
000000ac:       fd001825        op3f r8, r0, r3, 0x1825

000000b0:       480300bc        op12 r0, r3, r0, 0x00bc
000000b4:       6c201806        op1b r1, r0, r3, 0x1806
000000b8:       703f0ff2        op1c r1, r31, r1, 0x0ff2
000000bc:       6c20b00e        op1b r1, r0, r22, 0xb00e
000000c0:       6c20b80a        op1b r1, r0, r23, 0xb80a
... snip: its goes on and on ...
```

This output almost confirms our suspicion of these the byte sequences we discussed before is really are function prologues and epilogues. We are now able to conclude the following:

- `opcode=0x1b`: is a store instruction doing roughly the following semantics: `mem[rs + imm11] = rt`
- `opcode=0x19`: is a load instruction doing roughly the following semantics: `rd = mem[rs + imm1]`
- `r1` is the stack pointer
- `r19` - `r20` are callee saved registers.
- something weird is going on in the lower 2 bit of both stores and loads(unaligned? why?)
- `opcode=0x3f` using some constants that we do not know what does, is a return instruction.
- `r3` seems to be written to in the first instruction, saved to the stack in the second instruction, then loaded from the stack(at `0x000000a8`) and then used in the return instruction(at `0x000000ac`). This might indicate that the return address is not stored in a general purpose register but likely somewhere else(`0x00bc`?), and that the return instruction is some kind of indirect jump to `r3`.

Armed with all these assumptions, can now refine out assembler a bit more, and make it a bit more table driven:
```python
#!/usr/bin/env python3
import sys
from collections import defaultdict
from pwnlib.util.misc import read
from pwnlib.util.lists import group
from pwnlib.util.packing import u32

field_decoders = {
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
    fields = {op: f(word) for op, f in field_decoders.items()}
    inst = opcodes[fields["op"]](fields)
    print(f"{address:08x}:\t{word:08x}\t{inst}")
```

Now we have the following:

```
00000000:       480300bc        unk.12 r0, r3, r0, 0x00bc
00000004:       6c201806        st.d r3, r1, 0x006
00000008:       703f0fe2        unk.1c r1, r31, r1, 0x0fe2
0000000c:       6c20981e        st.d r19, r1, 0x01e
00000010:       6c20a01a        st.d r20, r1, 0x01a
00000014:       6c20a816        st.d r21, r1, 0x016
00000018:       6c20b012        st.d r22, r1, 0x012
0000001c:       6c20b80e        st.d r23, r1, 0x00e
... snip: lot of unknown opcodes ...
00000090:       6437000e        ld.d r23, r1, 0x00e
00000094:       64360012        ld.d r22, r1, 0x012
00000098:       64350016        ld.d r21, r1, 0x016
0000009c:       6434001a        ld.d r20, r1, 0x01a
000000a0:       6433001e        ld.d r19, r1, 0x01e
000000a4:       00210020        unk.00 r1, r1, r0, 0x0020
000000a8:       64230006        ld.d r3, r1, 0x006
000000ac:       fd001825        unk.3f r8, r0, r3, 0x1825

000000b0:       480300bc        unk.12 r0, r3, r0, 0x00bc
000000b4:       6c201806        st.d r3, r1, 0x006
000000b8:       703f0ff2        unk.1c r1, r31, r1, 0x0ff2
000000bc:       6c20b00e        st.d r22, r1, 0x00e
000000c0:       6c20b80a        st.d r23, r1, 0x00a
...
```

Now we make make a few more guesses:

- `opcode=0x00`: most likely a addition instruction, `rd = rs + imm16`
- `opcode=0x1c`: is some kind of store + addition, because `0xfe2 ~= -0x20`, but the low 2bits are being weird.

In addition store operations have their offset split into multiple bit sections:

```
| 6bit opcode | 5bit rs | 5bit hi-offset | 5bit rt | 11bit lo-offset |
```

These assumptions yields the following disassembly:

```
00000000:       480300bc        unk.12 r0, r3, r0, 0x00bc
00000004:       6c201806        st.d r3, r1, 0x0006
00000008:       703f0fe2        st.d! r1, r1, 0xffe2
0000000c:       6c20981e        st.d r19, r1, 0x001e
00000010:       6c20a01a        st.d r20, r1, 0x001a
00000014:       6c20a816        st.d r21, r1, 0x0016
00000018:       6c20b012        st.d r22, r1, 0x0012
0000001c:       6c20b80e        st.d r23, r1, 0x000e
00000020:       fd575008        unk.3f r10, r23, r10, 0x5008
00000024:       fd364808        unk.3f r9, r22, r9, 0x4808
00000028:       fd154008        unk.3f r8, r21, r8, 0x4008
0000002c:       fcf43808        unk.3f r7, r20, r7, 0x3808
00000030:       fcd33008        unk.3f r6, r19, r6, 0x3008
00000034:       00060001        add r6, r0, 1
00000038:       14a70001        unk.05 r5, r7, r0, 0x0001
0000003c:       a0010005        unk.28 r0, r1, r0, 0x0005
00000040:       4a060002        unk.12 r16, r6, r0, 0x0002
00000044:       14c70000        unk.05 r6, r7, r0, 0x0000
00000048:       a0000012        unk.28 r0, r0, r0, 0x0012
0000004c:       fcc6200a        unk.3f r6, r6, r4, 0x200a
00000050:       4a040003        unk.12 r16, r4, r0, 0x0003
00000054:       14c60000        unk.05 r6, r6, r0, 0x0000
00000058:       a000000e        unk.28 r0, r0, r0, 0x000e
0000005c:       2c8600ff        unk.0b r4, r6, r0, 0x00ff
00000060:       fca53005        unk.3f r5, r5, r6, 0x3005
00000064:       a002000b        unk.28 r0, r2, r0, 0x000b
00000068:       fc848083        unk.3f r4, r4, r16, 0x8083
0000006c:       14850000        unk.05 r4, r5, r0, 0x0000
00000070:       a0000002        unk.28 r0, r0, r0, 0x0002
00000074:       94003e72        unk.25 r0, r0, r7, 0x3e72
00000078:       fe649808        unk.3f r19, r4, r19, 0x9808
0000007c:       fe85a008        unk.3f r20, r5, r20, 0xa008
00000080:       fea6a808        unk.3f r21, r6, r21, 0xa808
00000084:       fec7b008        unk.3f r22, r7, r22, 0xb008
00000088:       fee8b808        unk.3f r23, r8, r23, 0xb808
0000008c:       940000b8        unk.25 r0, r0, r0, 0x00b8
00000090:       6437000e        ld.d r23, r1, 0x00e
00000094:       64360012        ld.d r22, r1, 0x012
00000098:       64350016        ld.d r21, r1, 0x016
0000009c:       6434001a        ld.d r20, r1, 0x01a
000000a0:       6433001e        ld.d r19, r1, 0x01e
000000a4:       00210020        add r1, r1, 32
000000a8:       64230006        ld.d r3, r1, 0x006
000000ac:       fd001825        unk.3f r8, r0, r3, 0x1825
000000b0:       480300bc        unk.12 r0, r3, r0, 0x00bc
000000b4:       6c201806        st.d r3, r1, 0x0006
000000b8:       703f0ff2        st.d! r1, r1, 0xfff2
000000bc:       6c20b00e        st.d r22, r1, 0x000e
000000c0:       6c20b80a        st.d r23, r1, 0x000a
```

Conclusion:
===========

The firmware for ConnectX-5 is a viable target for reverse engineering but there is a lot of work to be done.

So far we have learned the following about the iRISC instructions set:

- Big Endian
- Similar instruction layout to the MISP architecture: 6 bits opcode, 5 bits per register.
- load and store instruction does not have same encoding of the offset.
- load and store instruction have something weird going on in the low bits of the offset. All load and store instruction so far has been off-by-2 to 4-byte alignment
- `r1` is the stack pointer
- `r19` - `r20` are callee saved registers.
- `opcode = 0x00`: Add immediate instruction, `add rd, rs, imm16`.
- `opcode = 0x19`: Load instruction.
- `opcode = 0x1b`: Store instruction.
- `opcode = 0x1c`: Store instruction, but adds offset to base address register.
- `opcode = 0x3f`: Used for return, and other things.

References:
===========
[1] https://network.nvidia.com/files/doc-2020/pb-connectx-5-en-card.pdf

[2] https://www.nvidia.com/content/dam/en-zz/Solutions/networking/infiniband-adapters/infiniband-connectx7-data-sheet.pdf

[3] https://people.freebsd.org/~gallatin/talks/euro2021.pdf

[4] https://github.com/torvalds/linux/tree/master/drivers/net/ethernet/mellanox/mlx5/core

[5] https://github.com/Mellanox/mstflint
