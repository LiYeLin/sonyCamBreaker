"""Execute original CP receiver and MLUT builder up to its diagnostic tail.

Synthetic RAM context, no OS/ISP emulation, no patches, no replaced callees.
The descriptor at state+0x68 is NOT assumed to be the actual LUT sample data.
"""
import argparse
import hashlib
from itertools import product
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from emulate_cp_receiver import BASE, EXPECTED_SHA256, LOAD

STATE = 0x165a720
CONTEXT = 0x173efe8
OUTPUT = 0x10010000
MESSAGE = 0x10014000
AUX = 0x10018000
RETURN = 0x10020000
STOP = 0xb2c568  # All investigated builder writes are complete; before diagnostic tail.
FLAGS = [0, 1, 0, 1]


class Pipeline:
    def __init__(self):
        self.data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
        assert hashlib.sha256(self.data).hexdigest() == EXPECTED_SHA256
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for page in (0x8db000, 0x4e8000, 0xb31000, 0xb2c000, 0xb2d000, 0x61e000):
            self.uc.mem_map(page, 0x1000)
            self.uc.mem_write(page, self.data[page-LOAD:page-LOAD+0x1000])
        for page, size in ((0x165a000, 0x2000), (0x173e000, 0x2000),
                           (0x1a53000, 0x1000), (0x10000000, 0x21000)):
            self.uc.mem_map(page, size)

    def word(self, address, value):
        self.uc.mem_write(address, struct.pack('<I', value))

    def read_word(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def run(self, base_look=10, shooting_mode=0, color_gamut=1, input_gamut=0,
            target_display=0, descriptor_word=1, state_word_7c=0):
        uc = self.uc
        for address, size in ((0x165a000, 0x2000), (0x173e000, 0x2000),
                              (0x1a53000, 0x1000), (0x10000000, 0x21000)):
            uc.mem_write(address, bytes(size))
        self.word(CONTEXT, STATE)
        self.word(CONTEXT+0x30, AUX)
        self.word(CONTEXT+0x10, AUX+0x1000)
        # Deliberately identifiable, synthetic 96-byte descriptor.
        uc.mem_write(STATE+0x68, bytes(range(0x60)))
        self.word(STATE+0x78, descriptor_word)
        self.word(STATE+0x7c, state_word_7c)
        self.word(STATE+0xb04, color_gamut)  # Receiver preserves this for mode 3.
        for index, value in enumerate(FLAGS):
            uc.mem_write(OUTPUT+0x1c4+0x70*index, bytes([value]))
        payload = [base_look, shooting_mode, input_gamut, color_gamut, target_display]
        uc.mem_write(MESSAGE, bytes(8) + bytes(payload))
        uc.reg_write(UC_ARM_REG_R0, MESSAGE)
        uc.reg_write(UC_ARM_REG_SP, 0x10008000)
        uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        uc.emu_start(0x8db56f, RETURN, count=1000)
        assert uc.reg_read(UC_ARM_REG_PC) == RETURN
        assert uc.reg_read(UC_ARM_REG_R0) == 1
        uc.reg_write(UC_ARM_REG_R0, OUTPUT)
        uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        uc.emu_start(0xb2c407, STOP, count=5000)
        assert uc.reg_read(UC_ARM_REG_PC) == STOP
        effective = self.read_word(OUTPUT+0x13c0)
        mlut = self.read_word(OUTPUT+0x13b8)
        flags = [uc.mem_read(OUTPUT+0x1c4+0x70*i, 1)[0] for i in range(4)]
        expected_effective = 11 if shooting_mode == 3 else (0 if base_look == 10 and descriptor_word == 0 else base_look)
        assert effective == expected_effective
        assert self.read_word(OUTPUT+0x13bc) == shooting_mode
        assert mlut == expected_look(expected_effective, shooting_mode, color_gamut, input_gamut, target_display, state_word_7c)
        expected_flags = [0]*4 if mlut == 0 else ([1]*4 if shooting_mode == 0 and effective in (0, 10) else FLAGS)
        assert flags == expected_flags
        descriptor = bytes(uc.mem_read(OUTPUT+0x13d0, 0x60))
        expected_descriptor = bytes(uc.mem_read(STATE+0x68, 0x60)) if effective == 10 else bytes(0x60)
        assert descriptor == expected_descriptor
        return dict(input=dict(base_look=base_look, shooting_mode=shooting_mode, color_gamut=color_gamut,
                               input_gamut=input_gamut, target_display=target_display,
                               descriptor_word_0x10=descriptor_word, state_word_0x7c=state_word_7c),
                    effective_base_look=effective, mlut_id=mlut, path_flags=flags,
                    descriptor_copied=effective == 10, stop_pc=hex(STOP))


def expected_look(base, mode, color, input_gamut, target, extra):
    """Independent transcription of reviewed switch for valid inputs, debug override off."""
    if base in (1, 2, 3, 4, 5, 6, 11):
        return 0
    if base == 0:
        return 0x12 if mode in (1, 2) and color == 0 else 1
    if base in (7, 8, 9):
        return {7: (0x19, 7), 8: (0x13, 2), 9: (0x12, 1)}[base][color == 1]
    assert base == 10
    if mode in (1, 2):
        return (4 if extra else 0xd) if color == 1 else (0x18 if extra else 0x1b)
    if input_gamut == 1:
        return (5 if extra else 0xe) if target else (6 if extra else 0xf)
    return (8 if extra else 10) if target else (9 if extra else 11)


def run_matrix():
    emulator = Pipeline()
    cases = [emulator.run(*values) for values in product((0, 7, 8, 9, 10, 11), range(4),
                                                       range(2), range(2), range(2), range(2), range(2))]
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases),
                executed='Original receiver, builder, context getter, normalization, MLUT selection, flag setter and ARM memcpy',
                limitation='Synthetic context and descriptors; stop before diagnostic tail. No substituted callees, actual LUT sample loading, OS transport, ISP or JPEG.',
                cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = run_matrix()
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    print('PASS', report['passed_cases'], 'original-code receiver-to-builder cases')
