"""Find validated AArch64 ADRP/ADD string references in an offline ELF.

Does not execute target code. Addresses are ELF virtual addresses (before ASLR).
"""
import argparse
import hashlib
import io
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def adrp(word, pc):
    if word & 0x9F000000 != 0x90000000:
        return None
    immediate = ((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return word & 31, (pc & ~0xFFF) + (immediate << 12)


def add_immediate(word):
    if word & 0xFF800000 != 0x91000000:
        return None
    return word & 31, word >> 5 & 31, (word >> 10 & 0xFFF) << (12 if word & 0x400000 else 0)


def scan(binary, pattern):
    data = binary.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    if elf['e_machine'] != 'EM_AARCH64' or not elf.little_endian:
        raise ValueError('Expected little-endian AArch64 ELF')
    strings = {}
    for segment in elf.iter_segments():
        if segment['p_type'] != 'PT_LOAD':
            continue
        offset, size, va = (segment[k] for k in ['p_offset', 'p_filesz', 'p_vaddr'])
        for match in re.finditer(rb'[\x20-\x7e]{8,}', data[offset:offset+size]):
            if pattern.search(match.group()):
                address = va + match.start()
                strings[address] = dict(va=hex(address), file_offset=hex(offset+match.start()),
                                        text=match.group().decode('ascii'), xrefs=[], pointers=[])
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    pages = {address & ~0xFFF for address in strings}
    for section in elf.iter_sections():
        if not section['sh_flags'] & 4:
            continue
        code, start = section.data(), section['sh_addr']
        words = struct.unpack('<' + 'I' * (len(code)//4), code[:len(code)//4*4])
        for i, word in enumerate(words):
            decoded = adrp(word, start+i*4)
            if not decoded or decoded[1] not in pages:
                continue
            reg, page = decoded
            for j in range(i+1, min(i+13, len(words))):
                ins = next(decoder.disasm(code[j*4:j*4+4], start+j*4), None)
                if ins is None:
                    break
                added = add_immediate(words[j])
                if added and added[1] == reg and page+added[2] in strings:
                    strings[page+added[2]]['xrefs'].append(dict(
                        adrp=hex(start+i*4), add=hex(start+j*4), register='x'+str(added[0])))
                # No speculative propagation through calls, jumps, or register overwrites.
                if ins.mnemonic.startswith(('b', 'ret', 'cb', 'tb')):
                    break
                _, writes = ins.regs_access()
                if any(ins.reg_name(r) in ('x'+str(reg), 'w'+str(reg)) for r in writes):
                    break
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection) and section.is_RELA():
            for reloc in section.iter_relocations():
                if reloc['r_info_type'] == 1027 and reloc['r_addend'] in strings:
                    strings[reloc['r_addend']]['pointers'].append(hex(reloc['r_offset']))
    return dict(binary=str(binary), sha256=hashlib.sha256(data).hexdigest(),
                address_kind='ELF virtual address; no runtime load base',
                limitation='Bounded ADRP/ADD and RELATIVE relocation scan; absence is not proof of no references.',
                strings=list(strings.values()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--pattern', default=r'set_pplut_link|send_lut|set_base_picture_setting_i|get_select_lut_by_pp|convert_paint_struct_base_look_select')
    args = parser.parse_args()
    result = scan(args.binary, re.compile(args.pattern.encode()))
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
    for string in result['strings']:
        print(string['va'], string['text'][:110])
        print('  xrefs:', string['xrefs'], 'pointers:', string['pointers'][:8])
