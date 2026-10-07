"""Execute original CP allocation slices, then verify ownership resolution offline."""
import argparse
import json
from pathlib import Path
import struct

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_PC
from emulate_mlut_resource_mapping import ResourceMapping, POOL, OUT, SENTINEL
from emulate_cp_receiver import EXPECTED_SHA256

SLOTS = ((0,), (1,), (2,), (3,), (0, 1, 2, 3), (0, 1), (2, 3))


def run_matrix():
    emulator = ResourceMapping()
    uc = emulator.uc
    cases = []
    for kind in (0, 1):
        for index, slots in enumerate(SLOTS):
            for flag in (0, 1):
                before = [(0x1200 + i, 0) for i in range(4)]
                uc.mem_write(POOL, b''.join(struct.pack('<II', *item) for item in before))
                uc.mem_write(OUT, struct.pack('<I', SENTINEL))
                for register, value in ((UC_ARM_REG_R0, kind), (UC_ARM_REG_R1, OUT),
                                        (UC_ARM_REG_R2, index), (UC_ARM_REG_R3, flag),
                                        (UC_ARM_REG_SP, 0x10008000)):
                    uc.reg_write(register, value)
                # Run the actual prologue/type selection, stopping before the OS lock.
                uc.emu_start(0x54d2d5, 0x54d300, count=100)
                assert uc.reg_read(UC_ARM_REG_PC) == 0x54d300
                # Assume the lock succeeded; do not emulate or stub the OS calls.
                uc.emu_start(0x54d32f, 0x54d3b4, count=100)
                assert uc.reg_read(UC_ARM_REG_PC) == 0x54d3b4
                token = struct.unpack('<I', uc.mem_read(OUT, 4))[0]
                expected = ((before[slots[0]][0] + 1) & 0xffff) | (index << 16)
                if flag == 0:
                    expected |= 0x80000000
                assert token == expected
                after = [struct.unpack('<II', uc.mem_read(POOL+i*8, 8)) for i in range(4)]
                assert after == [(token, kind+1) if i in slots else before[i] for i in range(4)]
                resolved = emulator.run(kind, after, acquire=token)
                assert resolved['ip'] == index
                cases.append(dict(kind=kind, resource_index=index, flag=flag,
                                  token=hex(token), written_slots=slots,
                                  resolved_ip=resolved['ip']))
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                limitation='Original prologue and allocation body with synthetic free slots; manually skip OS locking and stop before unlock. Then execute the separately tested resolver slices. No complete allocation API, contention, resource availability, physical engine or photo/JPEG validation.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
    print('PASS', report['passed_cases'], 'allocation/resolution cases; no OS/device execution')
