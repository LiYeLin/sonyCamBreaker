"""Resolve MLUT resource lists using complete original functions and update-image tables."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, LOAD, EXPECTED_SHA256

OUT = 0x10010000
RETURN = 0x10020000


def run_matrix():
    data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(LOAD, (len(data)+0xfff) & ~0xfff)
    uc.mem_write(LOAD, data)
    uc.mem_map(0x10000000, 0x21000)
    def call(address, *args):
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM_REG_SP, 0x10008000)
        uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        uc.emu_start(address | 1, RETURN, count=10000)
        return uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_R0)
    rows = []
    for stream in range(1, 11):
        first = struct.unpack_from('<I', data, 0xce8230-LOAD+(stream-1)*4)[0]
        last = struct.unpack_from('<I', data, 0xce8260-LOAD+(stream-1)*4)[0]
        expected = []
        tables = []
        for component in range(first, last+1):
            pc, component_table = call(0x46f6e0, component)
            assert pc == RETURN
            tables.append(hex(component_table))
            record = component_table + 0x10*0x6c
            if data[record-LOAD] == 1:
                expected.append(struct.unpack_from('<I', data, record-LOAD+4)[0])
        row = dict(stream_id=stream, component_tables=tables, component_range=[first, last], resources=expected)
        # Empty lists enter diagnostic handling; do not claim its execution or emulate its OS.
        if expected:
            assert len(expected) <= 4
            uc.mem_write(OUT, struct.pack('<4I', *([0xfe]*4)))
            pc, status = call(0xb0a332, stream, 0x10, OUT)
            assert pc == RETURN and status == 1
            output = list(struct.unpack('<4I', uc.mem_read(OUT, 16)))
            assert output == expected + [0xfe]*(4-len(expected))
            row['original_lookup_executed'] = True
        else:
            row['original_lookup_executed'] = False
        rows.append(row)
    names = {}
    for i in range(72):
        resource, pointer = struct.unpack_from('<II', data, 0xe79c90-LOAD+i*8)
        if resource in (23, 30, 37, 44):
            names[str(resource)] = data[pointer-LOAD:].split(b'\0', 1)[0].decode('ascii')
    return dict(binary_sha256=EXPECTED_SHA256, resource_category=16, rows=rows, resource_names=names,
                executed_nonempty_lookups=sum(r['original_lookup_executed'] for r in rows),
                limitation='Complete original selector and nonempty lookup execution using initial update-image table bytes. Empty results evaluated statically, diagnostics not run. Stream IDs are not named shooting modes. Runtime table mutation, capture scheduling, OS and JPEG pixel processing unverified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
    for row in report['rows']:
        print(row['stream_id'], row['component_range'], row['resources'], row['original_lookup_executed'])
    print(report['resource_names'])
