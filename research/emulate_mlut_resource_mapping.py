"""Original resource matching and mask-to-IP slices; no OS lock emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, LOAD, EXPECTED_SHA256

POOL = 0x1a7e578
OUT = 0x10010000
RETURN = 0x10020000
SENTINEL = 0xfeedbeef
EXPECTED = {1: 0, 2: 1, 4: 2, 8: 3, 15: 4, 3: 5, 12: 6}


class ResourceMapping:
    def __init__(self):
        data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
        assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for page in (0x54d000, 0xbb4000, 0xe9d000):
            self.uc.mem_map(page, 0x1000)
            self.uc.mem_write(page, data[page-LOAD:page-LOAD+0x1000])
        self.uc.mem_map(0x1a7e000, 0x1000)
        self.uc.mem_map(0x10000000, 0x21000)

    def run(self, kind, pool, acquire=0x123):
        uc = self.uc
        assert len(pool) == 4
        uc.mem_write(POOL, b''.join(struct.pack('<II', *entry) for entry in pool))
        uc.mem_write(OUT, struct.pack('<I', SENTINEL))
        uc.reg_write(UC_ARM_REG_R6, kind)
        uc.reg_write(UC_ARM_REG_R5, acquire)
        uc.reg_write(UC_ARM_REG_R8, OUT)
        uc.reg_write(UC_ARM_REG_SP, 0x10008000)
        uc.emu_start(0x54d7c7, 0x54d862, count=1000)
        assert uc.reg_read(UC_ARM_REG_PC) == 0x54d862
        mask = uc.reg_read(UC_ARM_REG_R4)
        expected_mask = sum(1 << i for i, (owner, tag) in enumerate(pool)
                            if kind in (0, 1) and owner == acquire and tag == kind+1)
        assert mask == expected_mask
        # Resume after the OS unlock/error handling; that part is deliberately untested.
        uc.emu_start(0x54d891, 0x54d8d0, count=100)
        assert uc.reg_read(UC_ARM_REG_PC) == 0x54d8d0
        status = uc.reg_read(UC_ARM_REG_R0)
        output = struct.unpack('<I', uc.mem_read(OUT, 4))[0]
        assert status == (0 if mask in EXPECTED else 5)
        assert output == EXPECTED.get(mask, SENTINEL)
        if status == 0:
            uc.reg_write(UC_ARM_REG_R0, output)
            uc.reg_write(UC_ARM_REG_R1, OUT+4)
            uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
            uc.emu_start(0xbb42db, RETURN, count=100)
            assert uc.reg_read(UC_ARM_REG_PC) == RETURN
            assert uc.reg_read(UC_ARM_REG_R0) == 1
            assert struct.unpack('<I', uc.mem_read(OUT+4, 4))[0] == output
        return dict(kind=kind, acquire=acquire, pool=pool, matching_mask=mask,
                    status=status, ip=output if status == 0 else None,
                    output_untouched=status != 0)


def run_matrix():
    emulator = ResourceMapping()
    cases = []
    for kind in (0, 1):
        for mask in range(16):
            pool = [(0x123 if mask & (1 << i) else 0x456, kind+1) for i in range(4)]
            cases.append(emulator.run(kind, pool))
    cases.append(emulator.run(0, [(0x123, 2)]*4))
    cases.append(emulator.run(1, [(0x123, 1)]*4))
    cases.append(emulator.run(2, [(0x123, 3)]*4))
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                limitation='Synthetic acquire ownership table; original matching/mapping slices and lookup function. OS lock/unlock and allocation are not executed. Does not identify physical engines, capture modes, actual allocation or JPEG paths.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    print('PASS', report['passed_cases'], 'resource mapping cases; no OS/device execution')
