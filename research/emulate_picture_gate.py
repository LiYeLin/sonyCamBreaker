"""Execute isolated original AArch64 helper in Unicorn; no camera/OS/ISP emulation.

Only the reviewed helper and its read-only jump table are mapped. Unexpected
external calls fail instead of being silently stubbed. Never modifies firmware.
"""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

EXPECTED_SHA256 = '2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b'
ENTRY, END = 0x352C5DC, 0x352C790
STACK, OUTPUT, RETURN = 0x10000000, 0x10010000, 0x10020000


class PictureGate:
    def __init__(self, binary):
        data = Path(binary).read_bytes()
        if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
            raise ValueError('This experiment is pinned to the reviewed A7C II 2.01 appFw.so')
        elf = ELFFile(io.BytesIO(data))
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        # Map only pages needed by this leaf helper and its small switch table.
        for page in (0x352C000, 0x4C7D000):
            self.uc.mem_map(page, 0x1000)
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] <= page < segment['p_vaddr'] + segment['p_filesz']:
                    off = page - segment['p_vaddr'] + segment['p_offset']
                    self.uc.mem_write(page, data[off:off+0x1000])
                    break
            else:
                raise ValueError('Required code/data page missing')
        self.uc.mem_map(STACK, 0x10000)
        self.uc.mem_map(OUTPUT, 0x1000)
        self.uc.mem_map(RETURN, 0x1000)

    def run(self, lut=3, exists=1, log=0, signal=0, gamut=0, pp=12, mode=0, cinema=1, look=0):
        args = (lut, exists, log, signal, gamut, pp, mode, cinema)
        self.uc.mem_write(OUTPUT, b'\xa5' * 32)
        self.uc.mem_write(STACK, bytes(0x10000))
        sp = STACK+0x8000
        for i in range(29):
            self.uc.reg_write(UC_ARM64_REG_X0+i, 0)
        for i, value in enumerate(args):
            self.uc.reg_write(UC_ARM64_REG_X0+i, value)
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X30, RETURN)
        self.uc.mem_write(sp, struct.pack('<QQ', look, OUTPUT))
        self.uc.emu_start(ENTRY, RETURN, count=1000)
        if self.uc.reg_read(UC_ARM64_REG_PC) != RETURN:
            raise RuntimeError('Helper did not return within instruction budget')
        result = bytes(self.uc.mem_read(OUTPUT, 32))
        assert result[:8] == b'\xa5'*8 and result[13:] == b'\xa5'*19
        return list(result[8:13])


def run_matrix(binary):
    emulator = PictureGate(binary)
    rows = []
    for mode in (0, 1):
        for pp in (0, 1, 11, 12, 13, 15):
            for lut in (0, 1, 2, 3, 18):
                values = emulator.run(mode=mode, pp=pp, lut=lut)
                if mode == 0 or pp < 12:
                    assert values[:2] == [11, 3]
                else:
                    assert values[:2] == [{0: 9, 1: 7, 2: 8}.get(lut, 10), 0]
                rows.append(dict(mode=mode, pp=pp, lut=lut, bytes_8_to_12=values))
    for log in (1, 2, 3):
        for mode in (0, 1):
            result = emulator.run(log=log, mode=mode)
            assert result[:2] == ([11, 3] if mode == 0 else [10, 2 if log == 1 else 1])
            rows.append(dict(mode=mode, log=log, bytes_8_to_12=result))
    for exists in (0, 1):
        result = emulator.run(mode=1, exists=exists)
        assert result[:2] == [10 if exists else 0, 0]
        rows.append(dict(mode=1, exists=exists, bytes_8_to_12=result))
    return dict(binary_sha256=EXPECTED_SHA256, entry=hex(ENTRY),
                limitation='Original helper only. No sensor, ISP, transport, or JPEG output tested.',
                passed_cases=len(rows), cases=rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix(args.binary)
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    print('PASS', report['passed_cases'], 'isolated helper cases; not camera tests')
