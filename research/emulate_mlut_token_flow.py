"""Original dispatcher token storage and submit argument slices; not full capture execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, LOAD, EXPECTED_SHA256

STACK = 0x10008000
OBJECT = 0x10010000
LIST = 0x10014000
STATE = 0x1a539a8
TOKEN = 0x80041235
SUBMITS = ((0x4c2ea2, 0x4c2eae), (0xb2b4c8, 0xb2b4d4),
           (0xb2b58a, 0xb2b596), (0xb2ba02, 0xb2ba0e))


def run_matrix():
    data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
    cases = [i for i in range(72) if 0x4bad12 + 2*struct.unpack_from('<H', data, 0x4bad12-LOAD+i*2)[0] == 0x4baeba]
    assert cases == [23, 30, 37, 44]
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for page in (0x4bb000, 0x4c2000, 0xb2b000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, data[page-LOAD:page-LOAD+0x1000])
    uc.mem_map(0x10000000, 0x20000)
    uc.mem_map(0x1a53000, 0x2000)
    results = []
    for resource in cases:
        uc.mem_write(LIST, struct.pack('<4I', resource, 0xfe, 0xfe, 0xfe))
        uc.mem_write(LIST+0x20, struct.pack('<I', 0x123))
        uc.mem_write(STACK+0xa0, struct.pack('<3I', 0, 4, TOKEN))
        for reg, value in ((UC_ARM_REG_SP, STACK), (UC_ARM_REG_R10, LIST), (UC_ARM_REG_R9, LIST+0x20)):
            uc.reg_write(reg, value)
        uc.emu_start(0x4bb051, 0x4bb092, count=100)
        assert uc.reg_read(UC_ARM_REG_PC) == 0x4bb092
        record = STATE + resource*0x40
        assert struct.unpack('<I', uc.mem_read(record+0xc, 4))[0] == TOKEN
        # Explicitly restore the selected record/output pointer from the reviewed
        # intervening bookkeeping. No claim that this slice executes those branches.
        uc.reg_write(UC_ARM_REG_LR, record)
        uc.reg_write(UC_ARM_REG_R8, OBJECT+0x13b4)
        uc.emu_start(0x4bb223, 0x4bb230, count=100)
        assert uc.reg_read(UC_ARM_REG_PC) == 0x4bb230
        assert struct.unpack('<I', uc.mem_read(OBJECT+0x13b4, 4))[0] == TOKEN
        for entry, stop in SUBMITS:
            uc.reg_write(UC_ARM_REG_R4, OBJECT)
            uc.emu_start(entry | 1, stop, count=100)
            assert uc.reg_read(UC_ARM_REG_PC) == stop
            assert uc.reg_read(UC_ARM_REG_R0) == TOKEN
            assert uc.reg_read(UC_ARM_REG_R1) == OBJECT+0x13b8
            results.append(dict(resource_case=resource, submit_call=hex(stop), token=hex(TOKEN), parameter_offset='0x13b8'))
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(results), cases=results,
                limitation='Synthetic successful-acquire token and object. Original storage, copy-out and submit-argument slices; registers restored across omitted bookkeeping. No allocation call, full path reachability, MLUT submission, OS, hardware or JPEG execution.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
    print('PASS', report['passed_cases'], 'token storage/argument cases')
