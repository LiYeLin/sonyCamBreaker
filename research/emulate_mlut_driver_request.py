"""Original MLUT length checks and request construction; stop BEFORE queue entry."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, LOAD, EXPECTED_SHA256

RETURN = 0x10020000
QUEUE = 0xb83282
SPEC = {'l3d': (0xb799de, 48000, 12000, 1), 'reg': (0xb79ab4, 124, 31, 3)}


class DriverRequest:
    def __init__(self):
        data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
        assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for page in (0xb79000, 0xb7a000, 0xb82000, 0xb83000, 0x535000, 0x61e000):
            self.uc.mem_map(page, 0x1000)
            self.uc.mem_write(page, data[page-LOAD:page-LOAD+0x1000])
        self.uc.mem_map(0x1139000, 0x1000)
        self.uc.mem_map(0x10000000, 0x21000)

    def run(self, kind, ip, size):
        entry, required_size, words, command = SPEC[kind]
        uc = self.uc
        uc.mem_write(0x10000000, bytes(0x21000))
        # Original getter returns 1: skip logging, not input validation.
        uc.mem_write(0x1139fb8, struct.pack('<I', 1))
        uc.mem_write(0x10010000, struct.pack('<II', 0x10018000, size))
        uc.reg_write(UC_ARM_REG_R0, ip)
        uc.reg_write(UC_ARM_REG_R1, 0x10010000)
        uc.reg_write(UC_ARM_REG_R2, 0)
        uc.reg_write(UC_ARM_REG_SP, 0x10008000)
        uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        valid = ip <= 6 and size == required_size
        stop = QUEUE if valid else RETURN
        uc.emu_start(entry | 1, stop, count=2000)
        assert uc.reg_read(UC_ARM_REG_PC) == stop
        result = dict(kind=kind, ip=ip, size=size, reached_queue_boundary=valid,
                      queue_executed=False, stop_pc=hex(stop))
        if valid:
            request = list(struct.unpack('<14I', uc.mem_read(uc.reg_read(UC_ARM_REG_R0), 56)))
            assert request == [command, 0, ip, 0, 0x02ae085a, 0x10018000, words] + [0]*7
            result['request_words'] = request
            # Separate experiment: manually deliver saved request to original dispatcher.
            # This does not emulate or prove OS queue delivery.
            uc.mem_write(0x10012000, struct.pack('<14I', *request))
            uc.reg_write(UC_ARM_REG_R0, 0x10012000)
            uc.reg_write(UC_ARM_REG_SP, 0x10008000)
            uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
            target = 0xb82d7c if kind == 'l3d' else 0xb82e00
            uc.emu_start(0x53533d, target, count=200)
            assert uc.reg_read(UC_ARM_REG_PC) == target
            assert uc.reg_read(UC_ARM_REG_R0) == 0x10012000
            result['manual_dispatch_target'] = hex(target)
            result['handler_executed'] = False
        else:
            code = uc.reg_read(UC_ARM_REG_R0)
            assert code == 0xfffffff3
            result['return_signed'] = code - (1 << 32)
        return result


def run_matrix():
    emulator = DriverRequest()
    cases = []
    for kind, (_, required, _, _) in SPEC.items():
        for ip in (*range(8), 0xffffffff):
            for size in (0, 1, required-1, required, required+1):
                cases.append(emulator.run(kind, ip, size))
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                limitation='Original functions including memset/getter; synthetic buffer and logging state. Stops before queue routine, then manually invokes dispatcher and stops before handler. No OS queue delivery, LUT content read, DMA, register programming, CUBE conversion or JPEG proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    print('PASS', report['passed_cases'], 'original driver validation/request cases; no queue execution')
