"""Original configuration-bank selection and stream-field copy, with synthetic state."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, LOAD, EXPECTED_SHA256

CONTEXT = 0x173efe8
CONFIG = 0x10010000
FLAGS = 0x10018000
OBJECT = 0x10020000


def run_matrix():
    data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for page in (0x4be000, 0xb2d000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, data[page-LOAD:page-LOAD+0x1000])
    uc.mem_map(0x173e000, 0x2000)
    uc.mem_map(0x1a53000, 0x1000)
    uc.mem_map(0x10000000, 0x30000)
    def write32(address, value):
        uc.mem_write(address, struct.pack('<I', value))
    write32(CONTEXT+0xc, CONFIG)
    write32(CONTEXT+0x2c, FLAGS)
    payloads = {0x20: (101, 1, 103, 104), 0x630: (201, 8, 203, 204)}
    for bank, words in payloads.items():
        uc.mem_write(CONFIG+bank+0x74, struct.pack('<4I', *words))
    cases = []
    for state in range(4):
        for flag in range(4):
            for global_bit in (0, 1):
                write32(CONFIG+0x698, state)
                uc.mem_write(FLAGS+1, bytes([flag]))
                uc.mem_write(0x1a533ba, bytes([global_bit << 1]))
                uc.reg_write(UC_ARM_REG_R0, OBJECT)
                uc.reg_write(UC_ARM_REG_SP, 0x10008000)
                uc.emu_start(0x4be1a5, 0x4be1fa, count=1000)
                assert uc.reg_read(UC_ARM_REG_PC) == 0x4be1fa
                bank = uc.reg_read(UC_ARM_REG_R8)-CONFIG
                fallback = state == 0 or (state == 1 and (flag | 1) == 3) or (state == 2 and flag == 3) or global_bit
                assert bank == (0x630 if fallback else 0x20)
                # Skip unrelated initializer work; retain the selected r8 and original fp.
                uc.emu_start(0x4be57b, 0x4be58e, count=100)
                assert uc.reg_read(UC_ARM_REG_PC) == 0x4be58e
                words = struct.unpack('<4I', uc.mem_read(OBJECT+0x14fc, 16))
                assert words == payloads[bank]
                cases.append(dict(state=state, flag=flag, global_bit=global_bit,
                                  selected_bank=hex(bank), copied_stream_id=words[1]))
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                limitation='Synthetic context, flags and bank contents. Original selection including context getter, then manually resume at original 16-byte copy. Remaining initializer skipped. Does not name bank/mode semantics or establish real stream values, resource allocation or JPEG processing.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
    print('PASS', report['passed_cases'], 'bank selection/copy cases')
