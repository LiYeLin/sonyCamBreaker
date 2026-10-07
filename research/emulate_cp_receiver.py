"""Isolated Thumb receiver experiment; no OS transport or imaging hardware."""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

BASE = Path(__file__).parent / 'a7c2-2.01'
EXPECTED_SHA256 = 'f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428'
LOAD = 0x108000


def run_receiver(payload):
    data = (BASE / 'cp-selected/files/cpapp-b.bin').read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
    # Cross-component match: message id, Thumb handler pointer, diagnostic pointer.
    record = struct.unpack_from('<IIIII', data, 0x10fc450-LOAD)
    assert record == (0x4157, 0x8db56f, 0, 0, 0x366521)
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for page, size in ((0x8db000, 0x1000), (0x165a000, 0x2000), (0x1a53000, 0x1000),
                       (0x10000000, 0x10000), (0x10010000, 0x1000), (0x10020000, 0x1000)):
        uc.mem_map(page, size)
    uc.mem_write(0x8db000, data[0x8db000-LOAD:0x8dc000-LOAD])
    uc.mem_write(0x165b224, struct.pack('<I', 0x7e))  # Detect conditional preservation of color_gamut.
    uc.mem_write(0x10010000, bytes(8) + bytes(payload))
    uc.reg_write(UC_ARM_REG_R0, 0x10010000)
    uc.reg_write(UC_ARM_REG_SP, 0x10008000)
    uc.reg_write(UC_ARM_REG_LR, 0x10020001)
    uc.emu_start(0x8db56f, 0x10020000, count=1000)
    assert uc.reg_read(UC_ARM_REG_PC) == 0x10020000
    assert uc.reg_read(UC_ARM_REG_R0) == 1
    state = list(struct.unpack('<IIIII', uc.mem_read(0x165b218, 20)))
    assert state == [payload[0], payload[1], payload[2], 0x7e if payload[1] == 3 else payload[3], payload[4]]
    assert struct.unpack('<I', uc.mem_read(0x165ada4, 4))[0] == 1
    return dict(payload=payload, receiver_state=state, return_value=1)


if __name__ == '__main__':
    results = [run_receiver(payload) for payload in ([11, 3, 0, 1, 0], [10, 0, 0, 1, 0], [7, 2, 1, 0, 0])]
    with (BASE / 'cp-receiver-emulation.json').open('x') as output:
        json.dump(dict(binary_sha256=EXPECTED_SHA256, dispatch_record_va='0x10fc450',
                       message_id='0x4157', passed_cases=len(results), cases=results,
                       limitation='Simulated parameter storage only; no real messaging or JPEG capture.'), output, indent=2)
    print('PASS', len(results), 'CP receiver cases; dispatch table verified')
