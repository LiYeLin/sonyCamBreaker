"""Record direct B/BL references; indirect calls are explicitly not covered."""
import argparse
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile


def branch_target(word, pc):
    if word & 0x7C000000 != 0x14000000:
        return None
    immediate = word & 0x3FFFFFF
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return ('BL' if word & 0x80000000 else 'B'), pc + immediate * 4


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    functions = []
    for line in args.manifest.read_text().splitlines():
        if line.strip() and not line.startswith('#'):
            start, end, name = line.split()
            functions.append(dict(start=int(start, 16), end=int(end, 16), name=name, inbound=[], outbound=[]))
    elf = ELFFile(io.BytesIO(args.binary.read_bytes()))
    for section in elf.iter_sections():
        if not section['sh_flags'] & 4:
            continue
        code, va = section.data(), section['sh_addr']
        for i, (word,) in enumerate(struct.iter_unpack('<I', code[:len(code)//4*4])):
            pc = va+i*4
            decoded = branch_target(word, pc)
            if not decoded:
                continue
            kind, target = decoded
            for f in functions:
                if target == f['start']:
                    f['inbound'].append(dict(source=hex(pc), kind=kind))
                if f['start'] <= pc < f['end'] and not f['start'] <= target < f['end']:
                    f['outbound'].append(dict(source=hex(pc), target=hex(target), kind=kind))
    with args.output.open('x') as output:
        json.dump(functions, output, indent=2)
    for f in functions:
        print(f['name'], 'inbound', f['inbound'], 'outbound', len(f['outbound']))
