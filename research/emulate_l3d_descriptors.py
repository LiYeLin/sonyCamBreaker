"""Execute original L3D descriptor builder, not the transfer engine or MMIO."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, LOAD, EXPECTED_SHA256

RETURN = 0x10020000
SUMMARY = 0x10010000
DESCRIPTORS = 0x262d0f0


class DescriptorBuilder:
    def __init__(self):
        self.data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
        assert hashlib.sha256(self.data).hexdigest() == EXPECTED_SHA256
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for page in (0xb83000, 0xb77000, 0xb78000, 0xe95000):
            self.uc.mem_map(page, 0x1000)
            self.uc.mem_write(page, self.data[page-LOAD:page-LOAD+0x1000])
        self.uc.mem_map(0x262d000, 0x3000)
        self.uc.mem_map(0x10000000, 0x21000)

    def run(self, ip, source=0x20000000):
        assert 0 <= ip <= 6
        uc = self.uc
        uc.mem_write(0x262d000, bytes(0x3000))
        uc.reg_write(UC_ARM_REG_R0, ip)
        uc.reg_write(UC_ARM_REG_R1, source)
        uc.reg_write(UC_ARM_REG_R2, 12000)
        uc.reg_write(UC_ARM_REG_R3, SUMMARY)
        uc.reg_write(UC_ARM_REG_SP, 0x10008000)
        uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        uc.emu_start(0xb8336d, RETURN, count=3000)
        assert uc.reg_read(UC_ARM_REG_PC) == RETURN
        summary = struct.unpack('<III', uc.mem_read(SUMMARY, 12))
        assert summary == (ip, 48, DESCRIPTORS)
        uc.reg_write(UC_ARM_REG_R0, ip)
        uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        uc.emu_start(0xb77ff9, RETURN, count=30)
        assert uc.reg_read(UC_ARM_REG_PC) == RETURN
        target_base = uc.reg_read(UC_ARM_REG_R0)
        assert target_base == 0xf4009000 + (ip << 20)
        records = []
        for i in range(24):
            pointer = struct.unpack_from('<I', self.data, 0xe953fc-LOAD+4*i)[0]
            control = struct.unpack('<III', uc.mem_read(DESCRIPTORS+0x118*i, 12))
            chunk = struct.unpack('<III', uc.mem_read(DESCRIPTORS+0x118*i+0x8c, 12))
            assert control == (pointer, 0x408, 1)
            assert chunk == (source+2000*i, 0x3000, 500)
            assert uc.mem_read(DESCRIPTORS+0x118*i+0xc, 1)[0] == 0
            assert uc.mem_read(DESCRIPTORS+0x118*i+0x98, 1)[0] == 0
            records.append(dict(control_source=hex(pointer), control_target_offset=hex(control[1]),
                                data_source=hex(chunk[0]), data_target_offset=hex(chunk[1]), words=chunk[2]))
            # Static file inspection, not an emulated read of runtime control RAM.
            records[-1]['control_value_from_file'] = (
                struct.unpack_from('<I', self.data, pointer-LOAD)[0]
                if LOAD <= pointer <= LOAD+len(self.data)-4 else None)
        # Source LUT and target register windows are intentionally UNMAPPED in this emulator.
        return dict(ip=ip, source=hex(source), descriptor_count=48, chunks=24,
                    bytes_per_chunk=2000, total_bytes=48000,
                    target_base_from_helper=hex(target_base), records=records,
                    lut_read=False, transfer_executed=False)


def run_matrix():
    emulator = DescriptorBuilder()
    cases = [emulator.run(ip, source) for ip in range(7) for source in (0x20000000, 0x21001000)]
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                limitation='Original descriptor construction and base arithmetic only. LUT source and target MMIO remain unmapped; runtime control words are not dereferenced. File-backed control values inspected separately; first control pointer is outside file. No address translation, cache maintenance, DMA, interrupts, SRAM contents, path semantics or JPEG validated.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    print('PASS', report['passed_cases'], 'descriptor cases; LUT/MMIO memory never mapped')
