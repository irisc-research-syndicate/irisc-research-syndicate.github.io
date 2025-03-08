---
title: Patching the firmware
author: Jonas Rudloff
layout: post
---

In this article we will explore the posibility to patch the firmware of a ConnectX-5 to gain code execution on the NICs iRISC processor. We will discuss many of the problems we had doing this, as well as review tooling and linux Driver code related to interacting with the NICs.


In the privious articles we have [started with almost nothing]({% post_url 2025-02-06-initial-firmware-analysis %}) found a [SHA256 implementation in the firmware]({% post_url 2025-02-10-finding-sha256 %}) used that to gain more knowledge about the iRISC ISA, and finally we made a [basic Ghidra processor module]({% post_url 2025-02-14-writing-a-ghidra-processor-module %}). We can highly reccomend that you, the reader, review our privious work before continuing reading this article.


Hardware overview
=================
TODO

Hardware setup and availability
-------------------------------
We have the following hardware setup for testing firmware:
- Intel NUC with Thunderbolt/USB4
- [Thunderbolt EGPU Dock: TH3P4G3]([https://egpu.io/exp-gdc-th3p4g2-thunderbolt-gpu-dock-review/)
- ATX Power supply for the dock.
- [Mellanox ConnectX-5](https://www.ebay.com/sch/i.html?_nkw=mellanox+connectx-5+100Gb)

This setup allows us to power cycle the NICs without rebooting our lab machine.


Firmware security and recovery mode
===================================
TODO


Firmware reverse engineering
============================

Firmware Layout, ITOC, and CRC
------------------------------
So an ConnectX-5 firmware contains a section called 'ITOC' which likely means 'Image Table Of Content'. This section contains entries describing the layout of the firmware and information about other sections of the firmware:
`
If we have a look a the [ITOC layout](https://github.com/Mellanox/mstflint/blob/42be686187316e9d809c8c81eca546fab6ee1746/tools_layouts/image_info_layouts.h#L285) we have the following:
```c
/*---------------- DWORD[1] (Offset 0x4) ----------------*/
/* Description - if partition type is code or ini then the load address is in here */
/* 0x4.0 - 0x4.29 */
u_int32_t param0;
// ... snip ...
/* Description - When this bit is set, Data within the section is protected by per-line crc. See
/* yu.flash.replacement.crc_en */
/* 0x4.30 - 0x4.30 */
u_int8_t cache_line_crc;
// ... snip ...
/*---------------- DWORD[6] (Offset 0x18) ----------------*/
/* Description -  */
/* 0x18.0 - 0x18.15 */
u_int16_t section_crc;
// ... snip ...
/*---------------- DWORD[7] (Offset 0x1c) ----------------*/
/* Description -  */
/* 0x1c.0 - 0x1c.15 */
u_int16_t itoc_entry_crc;
```
So we have the following:
- `param0`: We know the load address of sections that contains code.
- `cache_line_crc`: Some sections have embedded CRC checksums embedded in them, most likely at cache-line sized intervals.
- `section_crc` and `itoc_entry_crc`: we have a CRC checksum of all of a sections data, as well as a checksum of each ITOC entry. 

Before we can begin reverse engineer the firmware code we need to strip it of the cache-line CRC checksums, and when patching the firmware we need to recalculate those checksums.

We can get an understanding of how the cache-line CRC work from the following [code](https://github.com/Mellanox/mstflint/blob/42be686187316e9d809c8c81eca546fab6ee1746/mlxfwops/lib/fs4_ops.cpp#L511), this indicates that a cache-line is 68 bytes, and contains 4 bytes of CRC checksum at the end of each cache-line. However this function is never used in the `mstflint` code.

Fortunaltely the mstflint codebase has multiple [diffrent implementations](https://github.com/Mellanox/mstflint/blob/1c487746dc9cb36a8da560ee1ec63e082d01d83a/mft_utils/crc16.cpp#L34) of [crc](https://github.com/Mellanox/mstflint/blob/master/mft_utils/calc_hw_crc.c#L56), we will not go into much more detail about the checksums of the firmware as we have made a [tool](https://github.com/irisc-research-syndicate/mlx5fw/tree/master) for modifying sections of the firmware while taking care of all the checksums.

Using that tool we begin look at the firmware:
```
$ mlx5fw fw.bin show-sections
 0 0x00007000/0x00015614 0x00710000 0x007161d8: false false IRON_PREP_CODE
 1 0x0001c614/0x00000100 0x00000000 0x00000000: false false RESET_INFO
 2 0x0001c748/0x003d15a0 0x00800000 0x0081d58c: false true MAIN_CODE
 3 0x003edce8/0x00013cd0 0x00780000 0x00792e90: false false PCIE_LINK_CODE
 4 0x004019b8/0x00000b90 0x00740000 0x007402c0: false false POST_IRON_BOOT_CODE
 5 0x00402548/0x0002e140 0x01000000 0x01000004: false false PCI_CODE
 6 0x00430688/0x00001ca0 0x0106ac00 0x0106ac50: false false UPGRADE_CODE
 7 0x00432328/0x00009920 0x00000000 0x00000000: false false PHY_UC_CODE
 8 0x0043bc48/0x00001e80 0x00000000 0x00000000: false false PCIE_PHY_UC_CODE
 9 0x0043dac8/0x00000400 0x00000000 0x00000000: false false IMAGE_INFO
10 0x0043dec8/0x00000b00 0x00000000 0x00000000: false false FW_MAIN_CFG
11 0x0043e9c8/0x000004c0 0x00000000 0x00000000: false false FW_BOOT_CFG
12 0x0043ee88/0x00000980 0x00000000 0x00000000: false false HW_MAIN_CFG
13 0x0043f808/0x00000140 0x00000000 0x00000000: false false HW_BOOT_CFG
14 0x0043f948/0x00002c80 0x00000000 0x00000000: false false PHY_UC_CONSTS
15 0x004425c8/0x00000140 0x00000000 0x00000000: false false IMAGE_SIGNATURE_256
16 0x00442708/0x00000900 0x00000000 0x00000000: false false PUBLIC_KEYS_2048
17 0x00443008/0x00000090 0x00000000 0x00000000: false false FORBIDDEN_VERSIONS
18 0x00443098/0x00000240 0x00000000 0x00000000: false false IMAGE_SIGNATURE_512
19 0x004432d8/0x00001100 0x00000000 0x00000000: false false PUBLIC_KEYS_4096
20 0x004443d8/0x000b9c28 0x00000000 0x00000000: false false ROM_CODE
21 0x004fe000/0x00000be0 0x00000000 0x00000000: false false DBG_FW_INI
22 0x004febe0/0x00000008 0x00000000 0x00000000: false false DBG_FW_PARAMS
23 0x004febe8/0x00008d30 0x00000000 0x00000000: false false CRDUMP_MASK_DATA
24 0x00507918/0x00050000 0x00000000 0x00000000: false false PROGRAMMABLE_HW_FW
```
From this we can see that we have a cache-line crc protected `MAIN_CODE` section, which has a load address of `0x00800000` and a entrypoint at `0x0081d58c`.

Firmware strings
----------------
Next we will have a look at that strings of the `MAIN_CODE` section to get an idea about possible patch options as well as the general:

With a little bit of hopeful grepping, we are able to find something that was refereing to `cmdif_driver`:
```
cmdif_driver: 0) start:        dbase_entry_ix=0x%.8x, dbase_entry=0x%.8x, toc.hca_state = 0x%x
cmdif_driver: 1) read command, [uid,gvmi]= (0x%.8x), opcode=(0x%.4x), opcode_mod=(0x%x), input_ix=(0x%x), ctx->missions=0x%.8x
cmdif_driver: 2) get_op_prop opcode=(0x%.4x) op_prop.cmd_missions = %.8x
cmdif_driver: 3) allocate_pages_req: %d / %d, ctx.allocated_pages=0x%.8x
cmdif_driver: 4) exit_exe_cmd ctx.done_missions=0x%x, op_prop.missions=0x%x, output_ix=(0x%x), syndrom=0x%.8x
cmdif_driver: 5) ctx.missions = 0x%x, more_missions=0x%x, hdr->input_inline.ix=%.8x
cmdif_driver: 6) wr cmd to mem  dbase_entry_ix=0x%.8x dbase_entry=0x%.8x toc.hca_state = 0x%x
cmdif_driver: final_state dbase_entry_ix=0x%.8x dbase_entry=0x%.8x, cmd_ret=%d
cmdif_driver: 7) done           dbase_entry_ix=0x%.8x, cmd_ret = 0x%x
cmdif_driver: 8) CMD_DB_EVENT_NEEDED: sw_eqn 0x%.8x, [is_ecmd,gvmi]=0x%.8x
```

From the [Linux kernel driver](https://github.com/torvalds/linux/blob/87a132e73910e8689902aed7f2fc229d6908383b/include/linux/mlx5/mlx5_ifc.h#L119) we also know that these NICs accepts all sorts of commands, in particular we have a `NOP` command and multiple different `QUERY_*` command, we can find string for the query commands:
```
$ strings 00800000_MAIN_CODE  | grep -i query_
...
query_l2_table_entry: DONE. gvmi=0x%x, table_index=0x%x, mac=0x%.4x%.8x, vlan_valid=0x%x, vlan=0x%x
PRM_QUERY_MKEY
query_rqt: DONE. gvmi=0x%x, rqt_num=0x%x, rqt_actual_size=0x%x
query_freelist_is_someone_busy_no_prefix gvmi=%.4x type=%d first_idx=0x%llx log2_cyclewrap: %d
query_flow_table_entry: table_type=0x%x, table_id=0x%x, group_id=0x%x, flow_index=0x%x
QUERY_FG
query_diagnostic_counters: gvmi=0x%.4x
query_flow_table: DONE. gvmi=0x%x, table_id=0x%x, table_type=0x%x
check_query_cre_cmd, cre_type 0x%x can't use this function
query_esw_functions: gvmi=0x%x, ext_host_pf_gvmi=0x%x, ext_host_pf_disabled=%d
query_esw_vport_context: DONE. gvmi=0x%x, vport_idx=0x%x
query_num_regular_pages: default_value: (%d), free_count: (%d)
query_match_definer_object Done: gvmi=0x%x, res_num=0x%x, format_id=0x%x
```
Looking at all these string they all seem be C format strings(note all the `%`), this means that something might try to format them somewhere. Additionally it means that there is tracing functionallity inside the firmware. That is a great advantage for reverse engineering the firmware.


Firmware tracing
----------------
- decompilation of traceing functions
- cmdif
TODO

Command interface
-----------------
TODO
- docs pdf ConnectX-4

Linux kernel `debugfs` interface
--------------------------------
Next we are gonna deal with the question: How do we send command to the NIC?

Lucklily The linux kernel driver implementes a [command interface](https://github.com/torvalds/linux/blob/87a132e73910e8689902aed7f2fc229d6908383b/drivers/net/ethernet/mellanox/mlx5/core/cmd.c#L1587) for the NICs via files in `debugfs`, the protocol for interacting with the NIC is the following:
- Write the command input to `in`.
- Write the expected total output size to `out_len`.
- Write `go` to `run`
- Read `status` and `out` to get the command output.

TODO


Patching the firmware
==================
TODO

Patching the `NOP` command 
--------------------------
TODO

Pathcing the `QUERY_WHATEVER` command
-------------------------------------
TODO

Conclusion
==========
We have successfully managed to patch the firmware and gain code execution on the NICs.

We, The iRISC research syndicate, hope to inspiere and encourage future work either into the iRISC ISA or into similar work on different hardware from other vendors. We sincerly hope that readers of this series of articles have found our methods interesting and we hope to have instilled a felling of "I could probably have done this".

Stay tuned for our next blog post about either the making of a userspace driver for ConnectX-5 or fuzzing of the iRISC ISA using our code execution primitive.