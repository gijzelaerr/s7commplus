# -*- coding: utf-8 -*-
"""Golden TIA Portal frames, captured 2026-09-15 against PLCSIM S7-1500 FW 2.9.

These are verbatim TIA -> PLC (peer0) and PLC -> TIA (peer1) bytes from an
independent MITM session between TIA Portal and the PLC (TLS terminated by a
pinned proxy, TOFU certificate trust), shared upstream in PR #45. They are
not captured or verified by this project; treat field interpretations built
on top of them (see the inline comments) as reported, not confirmed, unless
a test in ``tests/test_golden_tia_captures.py`` pins the claim against this
codebase's own parsers.

This file is data only. Nothing here is collected by pytest (no test_
prefix). Import it when you want to unit test a parser against frames that
TIA Portal really sent.

Frame layout recap:

    72 vv LL LL | opcode | res u16 | func u16 | res u16 | seq u16 |
    session u32 | transport flags 1B | body...

    72 vv LL LL  0x72 protocol id, vv protocol version, LL body length
    opcode       0x31 request, 0x32 response, 0x33 notification
    0x72 0xFE    SystemEvent control frame family (no opcode byte)
"""

# -- EXPLORE -----------------------------------------------------------------
#
# Three TIA explores, three different shapes. Body order:
#   id u32 | req VLQ | childs u8 | flag u8 | parents u8 | filter count VLQ |
#   address count VLQ | [address ids VLQ] | kq VLQ | fill 5B
# The flag byte sits between ChildsRecursive and Parents. TIA sends 1 on the
# device tree explore and 0 on the event tree and pair explores.

# Device tree explore, id 0x22 (34). childs=1, flag=1, parents=0, no
# attributes, kq VLQ 04 (running read counter).
explore_device_tree_req = (
    b"\x72\x02\x00\x1e\x31\x00\x00\x04\xbb\x00\x00\x00\x09\x70\x00\x10\x3d\x34"
    b"\x00\x00\x00\x22\x00\x01\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00"
)

# ASRoot / PLCProgram event tree explore, id 3, 58 attributes.
# childs=1, flag=0, parents=1. Body head:
#   id u32 00 00 00 03 | req VLQ 00 | childs 01 | flag 00 | parents 01 |
#   filter count 00 | address count VLQ 3a (58)
# then 58 VLQ attribute ids (each 2 bytes here), the TIA online info set:
#   93 61 93 60 93 6f 93 15 93 13 be 09 bf 03 81 69 93 59 93 2f 93 5b 93 5c
#   be 7d 93 5f 93 7b 93 77 9c 16 bd 19 bc 35 94 27 94 40 94 42 8f 67 97 35
#   90 2a 90 0a 90 27 90 15 8f 6a 90 24 90 0d 8f 7d 90 10 90 3a 90 3d 90 32
#   90 1a 90 37 90 07 90 20 c0 39 a1 2f 9c 33 93 1b 93 64 bb 25 bc 37 be 08
#   bb 62 bf 62 bb 61 a4 3e a4 06 a3 50 a4 1e bb 22 a4 21 a3 62
# then kq VLQ 21 (33) and the 5 byte fill.
# Note 81 69 = VLQ 233 = ObjectVariableTypeName, so ids are VLQ, not u16.
explore_asroot_req = (
    b"\x72\x02\x00\x92\x31\x00\x00\x04\xbb\x00\x00\x00\x28\x70\x00\x10\x3d\x34"
    b"\x00\x00\x00\x03\x00\x01\x00\x01\x00\x3a"
    b"\x93\x61\x93\x60\x93\x6f\x93\x15\x93\x13\xbe\x09\xbf\x03\x81\x69\x93\x59"
    b"\x93\x2f\x93\x5b\x93\x5c\xbe\x7d\x93\x5f\x93\x7b\x93\x77\x9c\x16\xbd\x19"
    b"\xbc\x35\x94\x27\x94\x40\x94\x42\x8f\x67\x97\x35\x90\x2a\x90\x0a\x90\x27"
    b"\x90\x15\x8f\x6a\x90\x24\x90\x0d\x8f\x7d\x90\x10\x90\x3a\x90\x3d\x90\x32"
    b"\x90\x1a\x90\x37\x90\x07\x90\x20\xc0\x39\xa1\x2f\x9c\x33\x93\x1b\x93\x64"
    b"\xbb\x25\xbc\x37\xbe\x08\xbb\x62\xbf\x62\xbb\x61\xa4\x3e\xa4\x06\xa3\x50"
    b"\xa4\x1e\xbb\x22\xa4\x21\xa3\x62"
    b"\x21\x00\x00\x00\x00\x00"
)

# Pair explore, id 0x8A11FFFF, zero attributes.
# childs=1, flag=0, parents=1. Body:
#   id u32 | req VLQ 00 | childs 01 | flag 00 | parents 01 |
#   filter count 00 | address count 00 | kq VLQ 22 (34) | fill
explore_pair_req = (
    b"\x72\x02\x00\x1e\x31\x00\x00\x04\xbb\x00\x00\x00\x29\x70\x00\x10\x3d\x34"
    b"\x8a\x11\xff\xff\x00\x01\x00\x01\x00\x00\x22\x00\x00\x00\x00\x00"
)

# -- NOTIFICATIONS -----------------------------------------------------------
#
# Two content bearing event notifications. Header after the subscription id:
# 04 00 00 00 00 00, then 00, seq VLQ, 00, an 8 byte block, then records
# starting with the 0x92 element id. Decoded and pinned by
# tests/test_golden_tia_captures.py via parse_subscription_notification.
#
# notification_cpu_state: rid 0x7000103f, seq VLQ 02. Records reference the
# CPU state attributes 9c 70/71/72/74 (VLQ 3760..3764) with USInt values.
# Values seen: 03 while RUN was active in this window.
notification_cpu_state = (
    b"\x72\x02\x00\x3b\x33\x70\x00\x10\x3f\x04\x00\x00\x00\x00\x00\x00\x02\x00"
    b"\x06\x5b\x8b\xa1\x99\x31\xa9\x02\x92\x00\x00\x00\x01\x00\x17\x00\x00\x0e"
    b"\x79\x9c\x74\x00\x08\x03\x9c\x70\x00\x08\x01\x9c\x71\x00\x08\x02\x9c\x72"
    b"\x00\x08\x00\x00\x00\x00\x00\x00\x00"
)

# notification_sub_events: rid 0x70001040, seq VLQ 84 13 (531). One record per
# registered diagnostic event object, 0x92 + id u32 + PValue each.
notification_sub_events = (
    b"\x72\x02\x00\xb7\x33\x70\x00\x10\x40\x04\x00\x00\x00\x00\x00\x00\x84\x13"
    b"\x00\x06\x5b\x8b\xbd\xd2\xa0\xce\x02\x92\x00\x00\x00\x0d\x00\x04\x00\x92"
    b"\x00\x00\x00\x0e\x00\x04\x00\x92\x00\x00\x00\x0f\x00\x08\x04\x92\x00\x00"
    b"\x00\x02\x00\x17\x00\x00\x0e\x79\x9c\x74\x00\x08\x03\x9c\x70\x00\x08\x01"
    b"\x9c\x71\x00\x08\x02\x9c\x72\x00\x08\x00\x00\x92\x00\x00\x00\x03\x00\x04"
    b"\xa2\xc0\x80\x00\x92\x00\x00\x00\x04\x00\x04\x00\x92\x00\x00\x00\x05\x00"
    b"\x05\x00\x92\x00\x00\x00\x06\x00\x05\x00\x92\x00\x00\x00\x07\x00\x04\xab"
    b"\xe5\x20\x92\x00\x00\x00\x08\x00\x04\x00\x92\x00\x00\x00\x09\x00\x04\x84"
    b"\xc0\x80\x00\x92\x00\x00\x00\x0a\x00\x04\x9e\x80\x80\x00\x92\x00\x00\x00"
    b"\x0b\x00\x04\x00\x92\x00\x00\x00\x0c\x00\x04\x00\x92\x00\x00\x00\x10\x00"
    b"\x08\x02\x00\x00\x00\x00\x00"
)

# -- SUBSCRIPTION CREATE (two counters) ---------------------------------------
#
# TIA diagnostic subscription create (function 0x04CA). Two distinct qualifier
# counters: the VLQ after the 00 04 00 00 00 00 marker is the create's WRITE
# slot (0x12 = 18 here), the VLQ inside the a1 7f ff c0 prefix is the client
# subscription counter (0x56), mirrored in the object name
# Subscription_2147467350 = Subscription_(0x7FFFC000 + 0x56).
sub_create_req = (
    b"\x72\x02\x00\x98\x31\x00\x00\x04\xca\x00\x00\x00\x8f\x70\x00\x10\x3d\x34"
    b"\x70\x00\x10\x3e\x00\x04\x00\x00\x00\x00\x00\x12\xa1\x7f\xff\xc0\x56\x87"
    b"\x69\x00\x00\xa3\x81\x69\x00\x15\x17\x53\x75\x62\x73\x63\x72\x69\x70\x74"
    b"\x69\x6f\x6e\x5f\x32\x31\x34\x37\x34\x36\x37\x33\x35\x30\xa3\x88\x3a\x00"
    b"\x02\x03\xa3\x87\x6a\x00\x03\x00\x00\xa3\x87\x6b\x00\x09\x00\xa3\x88\x10"
    b"\x00\x02\x01\xa3\x88\x11\x00\x01\x01\xa3\x88\x18\x20\x04\x03\x88\x80\x84"
    b"\x80\x00\x00\x00\xa3\x88\x19\x00\x04\x87\x04\xa3\x88\x1b\x00\x02\x00\xa3"
    b"\x88\x1c\x00\x02\x00\xa3\x88\x1d\x00\x07\xff\xff\xa3\x88\x1e\x00\x03\xff"
    b"\xff\xa3\x88\x1f\x00\x02\x00\xa2\x00\x00\x00\x00"
)

# -- SYMBOLIC WRITE ON THE WATCH TABLE SESSION --------------------------------
#
# TIA SetVarSubStreamed (function 0x057C) writing the string 'test'. TIA runs
# this on a third short lived connection, never on the subscription session.
# Body: object rid u32 00 00 00 c9, then 20 04 (UDInt scalar header) 01 83 1f
# (access data), the object qualifier block with the running write counter as
# KeyQualifier, and the WString value 74 65 73 74.
symbolic_write_req = (
    b"\x72\x02\x00\x3d\x31\x00\x00\x05\x7c\x00\x00\x00\x07\x70\x00\x10\x42\x34"
    b"\x00\x00\x00\xc9\x20\x04\x01\x83\x1f\x00\x00\x04\xe8\x89\x69\x00\x12\x00"
    b"\x00\x00\x00\x89\x6a\x00\x13\x00\x89\x6b\x00\x04\x00\x00\x00\x01\x00\x14"
    b"\x00\x04\x74\x65\x73\x74\x06\x00\x00\x00\x00"
)

# Its response. retval VLQ 00, then 0x0d (not 00 — the byte after ReturnValue
# is not constant across function codes), then the 4 byte fill.
symbolic_write_resp = b"\x72\x02\x00\x10\x32\x00\x00\x05\x7c\x00\x00\x00\x07\x34\x00\x0d\x00\x00\x00\x00"

# -- FIRMWARE COMPONENT TABLE POLL --------------------------------------------
#
# GVS response (function 0x0586) for the component table page 1. retval VLQ
# 00, then 00, then the body. The 64 byte fixed width record carries the
# firmware string S29.80.05 and the component name s7pcpu.
#
# This is a short excerpt, not the full frame: the header's own body length
# (0xd1 = 979 bytes) exceeds what is captured below.
component_table_resp = (
    b"\x72\x02\x03\xd3\x32\x00\x00\x05\x86\x00\x00\x00\xd1\x34\x00\x00\x00\x14"
    b"\x00\x9f\x7e\x0a\x02\x00\x00\x00\x01\x53\x32\x39\x2e\x38\x30\x2e\x30\x35"
)
