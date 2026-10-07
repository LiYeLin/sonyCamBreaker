"""Original instruction slices: per-path flags, shared config copy, branch gate.

Explicit synthetic entry registers; NOT whole-function or hardware execution.
"""
import argparse
import itertools
import json
from pathlib import Path
from unicorn.arm_const import *
from emulate_cp_pipeline import Pipeline, OUTPUT, AUX
from emulate_cp_receiver import EXPECTED_SHA256, LOAD

STACK = 0x10004000
MAP = 0x10019000
GLOBAL = 0x173f1e8


def run_routing(flags, mapping):
    assert len(mapping) == 4 and all(index in range(4) for index in mapping)
    assert len(flags) == 4 and all(value in (0, 1) for value in flags)
    pipeline = Pipeline()
    builder = pipeline.run()
    uc = pipeline.uc
    for page in (0x4d2000, 0x13e000, 0x4e0000):
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, pipeline.data[page-LOAD:page-LOAD+0x1000])
    for i, value in enumerate(flags):
        uc.mem_write(OUTPUT+0x1c4+0x70*i, bytes([value]))
    for i, value in enumerate(mapping):
        pipeline.word(MAP+4*i, value)
    uc.reg_write(UC_ARM_REG_SP, STACK)
    uc.reg_write(UC_ARM_REG_R8, OUTPUT)
    uc.reg_write(UC_ARM_REG_R9, MAP)
    uc.reg_write(UC_ARM_REG_R10, STACK+0x30)
    uc.reg_write(UC_ARM_REG_R12, STACK+0x110)
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.emu_start(0x4d281f, 0x4d289e, count=1000)
    assert uc.reg_read(UC_ARM_REG_PC) == 0x4d289e
    expected = bytes(flags[index] for index in mapping)
    assert bytes(uc.mem_read(STACK+0xf8, 4)) == expected
    assert pipeline.read_word(STACK+0xfc) == builder['mlut_id']
    assert pipeline.read_word(STACK+0x104) == builder['effective_base_look']
    # Original tail slice copies 100 bytes into the shared MLUT configuration.
    uc.emu_start(0x13e605, 0x13e616, count=1000)
    assert uc.reg_read(UC_ARM_REG_PC) == 0x13e616
    assert bytes(uc.mem_read(GLOBAL, 100)) == bytes(uc.mem_read(STACK+0xf8, 100))
    decisions = []
    for index, value in enumerate(expected):
        pipeline.word(STACK+0xb4, index)
        stop = 0x4e0ae4 if value else 0x4e0df0
        uc.emu_start(0x4e0ad3, stop, count=20)
        assert uc.reg_read(UC_ARM_REG_PC) == stop
        decisions.append(dict(path_index=index, enter_mlut_configuration=bool(value), stop_pc=hex(stop)))
    return dict(source_flags=flags, mapping=list(mapping), routed_flags=list(expected), decisions=decisions)


def run_matrix():
    cases = [run_routing(list(flags), mapping)
             for flags in itertools.product((0, 1), repeat=4)
             for mapping in itertools.permutations(range(4))]
    return dict(binary_sha256=EXPECTED_SHA256, passed_cases=len(cases), cases=cases,
                slices=[['0x4d281e', '0x4d289e'], ['0x13e604', '0x13e616'], ['0x4e0ad2', 'branch destination']],
                limitation='Synthetic register entry state, all permutations and Boolean flags. Does not validate actual routing table, whole-function reachability, path names, hardware or JPEG.')


def run_initial_mapping(shared):
    """Original initializer slice; caller's r8+0x1c meaning remains unknown."""
    pipeline = Pipeline()
    pipeline.run()
    uc = pipeline.uc
    uc.mem_map(0x4be000, 0x1000)
    uc.mem_write(0x4be000, pipeline.data[0x4be000-LOAD:0x4bf000-LOAD])
    pipeline.word(AUX+0x1c, int(shared))
    for i in range(4):
        pipeline.word(OUTPUT+0x1b0+0x70*i, 0)
        pipeline.word(OUTPUT+0x370+4*i, 0xdeadbeef)
    uc.reg_write(UC_ARM_REG_R8, AUX)
    uc.reg_write(UC_ARM_REG_R11, OUTPUT)
    uc.reg_write(UC_ARM_REG_SP, STACK)
    uc.emu_start(0x4be97f, 0x4be9c4, count=200)
    assert uc.reg_read(UC_ARM_REG_PC) == 0x4be9c4
    mapping = [pipeline.read_word(OUTPUT+0x370+4*i) for i in range(4)]
    counts = [pipeline.read_word(OUTPUT+0x1b0+0x70*i) for i in range(4)]
    assert mapping == ([0]*4 if shared else [0, 1, 2, 3])
    assert counts == ([4, 0, 0, 0] if shared else [1]*4)
    return dict(input_word=int(shared), mapping=mapping, counters=counts)


def run_initialized_matrix():
    initializers = [run_initial_mapping(value) for value in (False, True)]
    cases = [run_routing(list(flags), initial['mapping'])
             for initial in initializers for flags in itertools.product((0, 1), repeat=4)]
    return dict(binary_sha256=EXPECTED_SHA256, initializers=initializers,
                passed_routing_cases=len(cases), cases=cases,
                limitation='Original initialization slice + separately executed routing slices. Input field meaning, later table modifications, whole-function scheduling and JPEG remain unverified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--initialized-maps', action='store_true')
    args = parser.parse_args()
    report = run_initialized_matrix() if args.initialized_maps else run_matrix()
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    print('PASS', report.get('passed_cases', report.get('passed_routing_cases')), 'original-slice routing cases')
