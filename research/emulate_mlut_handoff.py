"""Observe original CP code at a lower MLUT call boundary, without executing it."""
import argparse
import json
from pathlib import Path
import struct

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from emulate_cp_pipeline import Pipeline, OUTPUT, RETURN
from emulate_cp_receiver import EXPECTED_SHA256, LOAD


def run_handoff(mode=0, reg_size=0):
    pipeline = Pipeline()
    previous = pipeline.run(shooting_mode=mode, descriptor_word=1, state_word_7c=reg_size)
    uc = pipeline.uc
    # Extra RAM needed by the original submit/cache functions.
    for page in (0x1a6a000, 0x1b1e000):
        uc.mem_map(page, 0x1000)
    uc.mem_map(0x54e000, 0x1000)
    uc.mem_write(0x54e000, pipeline.data[0x54e000-LOAD:0x54f000-LOAD])
    pipeline.word(0x1a6aefc, 1)  # Synthetic prerequisite; not a proven real-camera state.
    uc.reg_write(UC_ARM_REG_R0, 0x123)
    uc.reg_write(UC_ARM_REG_R1, OUTPUT+0x13b8)
    uc.reg_write(UC_ARM_REG_SP, 0x10008000)
    uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
    stop = RETURN if previous['mlut_id'] == 0 else (0x54e398 if reg_size else 0x54e15c)
    uc.emu_start(0x4e876d, stop, count=2000)
    assert uc.reg_read(UC_ARM_REG_PC) == stop
    result = dict(input=dict(cp_mode=mode, reg_size=reg_size, cache_state=1),
                  previous=previous, stop_pc=hex(stop), lower_function_executed=False)
    if stop == RETURN:
        assert pipeline.read_word(0x1a6aefc) == 1
        assert uc.mem_read(0x1b1e235, 1)[0] == 0
        result['handoff'] = None
        return result
    desc = uc.reg_read(UC_ARM_REG_R0)
    l3d = bytes(uc.mem_read(desc, 12))
    original = bytes(uc.mem_read(OUTPUT+0x13d0, 24))
    assert l3d == original[:8] + original[16:20]
    if reg_size:
        reg = bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R1), 12))
        assert reg == original[8:16] + original[20:24]
        look = uc.reg_read(UC_ARM_REG_R2)
        callback = uc.reg_read(UC_ARM_REG_R3)
        acquire_ptr = pipeline.read_word(uc.reg_read(UC_ARM_REG_SP))
    else:
        reg = None
        look = uc.reg_read(UC_ARM_REG_R1)
        callback = uc.reg_read(UC_ARM_REG_R2)
        acquire_ptr = uc.reg_read(UC_ARM_REG_R3)
    assert look == previous['mlut_id']
    assert callback == 0x4e89f1
    assert pipeline.read_word(acquire_ptr) == 0x123
    assert pipeline.read_word(0x1a6aefc) == 2
    assert uc.mem_read(0x1b1e235, 1)[0] == 1
    assert pipeline.read_word(0x1a6af00) == look
    def describe(blob):
        if blob is None:
            return None
        address, size = struct.unpack('<QI', blob)
        return dict(address=hex(address), size=size)
    result['handoff'] = dict(l3d=describe(l3d), reg=describe(reg), mlut_id=look,
                             callback=hex(callback), acquire_id=0x123,
                             cache_state=2, busy_byte=1)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    cases = [run_handoff(0, 0), run_handoff(0, 1), run_handoff(3, 1)]
    with args.output.open('x') as output:
        json.dump(dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                       limitation='Synthetic cache readiness, addresses and sizes. Stops before lower function executes; no LUT upload, completion callback, ISP or JPEG validated.'), output, indent=2)
    print('PASS', len(cases), 'original-code handoff cases; lower functions not executed')
