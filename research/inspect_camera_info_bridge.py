"""Cross-architecture CameraInfo RTTI, constructor and reader evidence.

Offline bytes only; no device access or firmware execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from scan_direct_calls import branch_target
from emulate_cp_receiver import EXPECTED_SHA256 as CP_SHA, LOAD as CP_BASE

ROOT = Path(__file__).parent / 'a7c2-2.01'
AV_BASE = 0xffffffc001000000
AV_SHA = '90343f5f2edc0393ad8809d907cfe648dfd3a82ce0ef39cf06167929d8955096'


def rtti(data, base, vtable_offset, width):
    fmt = '<I' if width == 4 else '<Q'
    def read(address):
        offset = address-base
        assert 0 <= offset <= len(data)-width
        return struct.unpack_from(fmt, data, offset)[0]
    table = base+vtable_offset
    assert read(table) == 0  # offset-to-top for this primary table
    typeinfo = read(table+width)
    name = read(typeinfo+width)
    start = name-base
    assert 0 <= start < len(data)
    end = data.index(0, start)
    return dict(vtable=hex(table), typeinfo=hex(typeinfo), name_va=hex(name),
                encoded_name=data[start:end].decode('ascii'))


def region(data, base, start, end, thumb=False):
    decoder = Cs(CS_ARCH_ARM if thumb else CS_ARCH_ARM64,
                 CS_MODE_THUMB if thumb else CS_MODE_ARM)
    instructions = list(decoder.disasm(data[start:end], base+start))
    assert sum(i.size for i in instructions) == end-start
    return dict(file_offset=hex(start), end_offset_exclusive=hex(end),
                va=hex(base+start), bytes=data[start:end].hex(),
                assembly=[dict(offset=hex(i.address-base), mnemonic=i.mnemonic, operands=i.op_str)
                          for i in instructions])


def inspect():
    cp = (ROOT / 'cp-selected/files/cpapp-b.bin').read_bytes()
    av = (ROOT / 'system-selected/files/av-cam.bin').read_bytes()
    assert hashlib.sha256(cp).hexdigest() == CP_SHA
    assert hashlib.sha256(av).hexdigest() == AV_SHA
    cp_type = rtti(cp, CP_BASE, 0xd15d28-CP_BASE, 4)
    av_type = rtti(av, AV_BASE, 0x33a560, 8)
    assert cp_type['encoded_name'] == av_type['encoded_name'] == '32C_DataflowInfra_Entry_CameraInfo'
    cp_ctor = region(cp, CP_BASE, 0x6888e6-CP_BASE, 0x688928-CP_BASE, True)
    av_ctor = region(av, AV_BASE, 0x8d830, 0x8d880)
    # Pin exact constructor instructions supporting ID and payload size.
    cp_ops = {(i['mnemonic'], i['operands']) for i in cp_ctor['assembly']}
    av_ops = {(i['mnemonic'], i['operands']) for i in av_ctor['assembly']}
    assert ('movs', 'r1, #5') in cp_ops and ('mov.w', 'r6, #0x3a8') in cp_ops
    assert ('mov', 'w8, #5') in av_ops and ('mov', 'w21, #0x3a8') in av_ops
    targets = {target: [] for target in (0x8d830, 0x8d8c8, 0x8d928, 0x94314, 0xa437c)}
    for offset in range(0, len(av)-3, 4):
        decoded = branch_target(struct.unpack_from('<I', av, offset)[0], offset)
        if decoded and decoded[1] in targets:
            targets[decoded[1]].append(dict(offset=hex(offset), kind=decoded[0]))
    ranges = {
        'camera_info_ctor': (0x8d830, 0x8d880),
        'camera_info_full_payload_getter': (0x8d8c8, 0x8d8dc),
        'camera_info_tail_getter': (0x8d928, 0x8d93c),
        'entry_parser': (0x933c8, 0x93438),
        'camera_info_parser_wrapper': (0x94314, 0x94318),
        'camera_info_reader': (0xa437c, 0xa43f0),
        'consumer_slice': (0x147934, 0x147988),
        'consumer_conversion': (0x1483b0, 0x148404),
    }
    strings = {}
    for offset in (0x41699e, 0x416bc4, 0x42b145, 0x42b590):
        strings[hex(offset)] = av[offset:av.index(0, offset)].decode('ascii')
    return dict(cp=dict(sha256=CP_SHA, base=hex(CP_BASE), rtti=cp_type, constructor=cp_ctor),
                av_cam=dict(sha256=AV_SHA, base=hex(AV_BASE), rtti=av_type,
                            regions={name: region(av, AV_BASE, *bounds) for name, bounds in ranges.items()},
                            candidate_direct_callers={hex(k): v for k, v in targets.items()}, strings=strings),
                reviewed_match=dict(class_name='C_DataflowInfra_Entry_CameraInfo', entry_id=5, payload_size=936),
                limitation='Matching representation and parser/copy path only. Raw scan may include data. AV base is an offline layout supported by RTTI/ADRP consistency, not proof of runtime mapping. Does not establish transport, image processing, JPEG effects or deployment capability.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    evidence = inspect()
    with args.output.open('x') as output:
        json.dump(evidence, output, indent=2)
    print('Verified matching CameraInfo RTTI, entry ID 5 and 936-byte payload; saved', args.output)
