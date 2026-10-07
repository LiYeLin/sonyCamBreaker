"""Recover named enum arrays using ELF RELATIVE relocations, not file offsets."""
import io
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

base = Path(__file__).parent / 'a7c2-2.01'
data = (base / 'selected/files/lib/appFw.so').read_bytes()
elf = ELFFile(io.BytesIO(data))
segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
relocs = {}
for section in elf.iter_sections():
    if isinstance(section, RelocationSection) and section.is_RELA():
        for entry in section.iter_relocations():
            if entry['r_info_type'] == 1027:
                relocs[entry['r_offset']] = entry['r_addend']

def read_string(va):
    for segment in segments:
        if segment['p_vaddr'] <= va < segment['p_vaddr'] + segment['p_filesz']:
            off = va - segment['p_vaddr'] + segment['p_offset']
            return data[off:off+512].split(b'\0')[0].decode('ascii', 'replace')
    return None

tables = []
for name, start, count in [('general_shooting_mode', 0x5808F50, 2),
                           ('setting_picture_profile', 0x5815BE8, 17),
                           ('setting_select_lut', 0x5828A78, 20)]:
    table = dict(name=name, table_va=hex(start),
                 note='Array positions support enum numbers; corroborate with code before interpreting a branch.',
                 entries=[], incoming_table_pointers=[])
    for i in range(count):
        pointer = start+i*8
        target = relocs.get(pointer)
        if target is None:
            raise ValueError('Expected string relocation missing')
        text = read_string(target)
        if not text.startswith('VAL_'+name+'_'):
            raise ValueError('Unexpected enum family: '+str(text))
        table['entries'].append(dict(index=i, pointer_va=hex(pointer), string_va=hex(target), name=text))
    table['incoming_table_pointers'] = [hex(p) for p, v in relocs.items() if v == start]
    tables.append(table)
with (base / 'enum-tables.json').open('x') as output:
    json.dump(tables, output, indent=2)
for table in tables:
    print(table['name'], table['table_va'], 'incoming', table['incoming_table_pointers'])
    for entry in table['entries']:
        print(entry['index'], entry['name'])
