"""Find candidate Thumb-2 BL/B.W references in a raw image, without mutation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


def branch_target(h1, h2, pc):
    if h1 & 0xf800 != 0xf000:
        return None
    kind = {0xd000: 'BL', 0x9000: 'B.W'}.get(h2 & 0xd000)
    if kind is None:
        return None
    s = h1 >> 10 & 1
    i1 = 1 ^ (h2 >> 13 & 1) ^ s
    i2 = 1 ^ (h2 >> 11 & 1) ^ s
    offset = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3ff) << 12) | ((h2 & 0x7ff) << 1)
    if s:
        offset -= 1 << 25
    return kind, (pc + 4 + offset) & 0xffffffff


def scan(data, base, targets):
    """Candidates only: instruction decoding does not prove code reachability."""
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    found = {target: dict(calls=[], pointers=[]) for target in targets}
    for offset in range(0, len(data)-3, 2):
        h1, h2 = struct.unpack_from('<HH', data, offset)
        result = branch_target(h1, h2, base + offset)
        if result is None or result[1] not in found:
            continue
        instruction = next(decoder.disasm(data[offset:offset+4], base+offset), None)
        if instruction is None or instruction.size != 4:
            continue
        if instruction.mnemonic not in ('bl', 'b.w') or instruction.operands[0].imm != result[1]:
            continue
        found[result[1]]['calls'].append(dict(va=hex(base+offset), kind=result[0], bytes=data[offset:offset+4].hex()))
    for offset in range(0, len(data)-3, 4):
        pointer = struct.unpack_from('<I', data, offset)[0]
        if pointer & 1 and pointer & ~1 in found:
            found[pointer & ~1]['pointers'].append(hex(base+offset))
    return {hex(target): evidence for target, evidence in found.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--base', type=lambda s: int(s, 0), default=0x108000)
    parser.add_argument('--target', type=lambda s: int(s, 0), action='append', required=True)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    report = dict(binary=str(args.binary), sha256=hashlib.sha256(data).hexdigest(),
                  load_base=hex(args.base),
                  limitation='Halfword-aligned Thumb decoding candidates; data and second-halfword false positives require caller review. No indirect calls or ARM-mode calls.',
                  targets=scan(data, args.base, args.target))
    with args.output.open('x') as output:
        json.dump(report, output, indent=2)
    for target, evidence in report['targets'].items():
        print(target, len(evidence['calls']), 'candidate calls,', len(evidence['pointers']), 'candidate pointers')
    print('Saved', args.output)


if __name__ == '__main__':
    main()
