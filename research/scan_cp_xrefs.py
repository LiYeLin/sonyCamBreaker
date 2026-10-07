"""Candidate ARM32 literal-pool references in cpapp-b.bin; offline only."""
import hashlib
import argparse
import json
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pattern', default=r'CheckSetParamBasePictureSetting|Set_Param_Base_Picture_Setting|GetVfxMlutLookname|SendVEF_PathSetLut|Base_Picture_Setting_')
parser.add_argument('--output', type=Path)
args = parser.parse_args()
base = Path(__file__).parent / 'a7c2-2.01'
binary = base / 'cp-selected/files/cpapp-b.bin'
data = binary.read_bytes()
load_base = 0x108000  # Entry stub's embedded self-address at file +0xc is 0x10800c.
assert struct.unpack_from('<I', data, 12)[0] == load_base + 12
targets = {}
for match in re.finditer(rb'[\x20-\x7e]{8,}', data):
    if re.search(args.pattern.encode(), match.group()):
        targets[load_base+match.start()] = dict(file_offset=hex(match.start()), va=hex(load_base+match.start()),
                                              text=match.group().decode(), literals=[], xrefs=[], mov_pairs=[], thumb_pairs=[])
literals = {}
words = struct.unpack('<'+'I'*(len(data)//4), data[:len(data)//4*4])
for i, value in enumerate(words):
    if value in targets:
        literals[i*4] = value
        targets[value]['literals'].append(hex(load_base+i*4))
for i, word in enumerate(words):
    # ARM LDR (immediate), PC-relative, pre-indexed, word access, no writeback.
    if word & 0x0F7F0000 != 0x051F0000:
        continue
    off = i*4+8 + (1 if word & 0x800000 else -1)*(word & 0xFFF)
    if off in literals:
        targets[literals[off]]['xrefs'].append(dict(va=hex(load_base+i*4), literal_va=hex(load_base+off)))
decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
decoder.detail = True
low_words = {address & 0xffff for address in targets}
for i, word in enumerate(words):
    if word & 0x0FF00000 != 0x03000000:
        continue
    low = (word & 0xfff) | ((word >> 16 & 0xf) << 12)
    if low not in low_words:
        continue
    register = word >> 12 & 0xf
    for j in range(i+1, min(i+13, len(words))):
        current = words[j]
        instruction = next(decoder.disasm(data[j*4:j*4+4], load_base+j*4), None)
        if instruction is None:
            break
        if current & 0x0FF00000 == 0x03400000 and current >> 12 & 0xf == register:
            high = (current & 0xfff) | ((current >> 16 & 0xf) << 12)
            address = high << 16 | low
            if address in targets and word >> 28 == current >> 28:
                targets[address]['mov_pairs'].append(dict(movw_va=hex(load_base+i*4), movt_va=hex(load_base+j*4)))
        if instruction.mnemonic.startswith(('b', 'pop')):
            break
        if any(instruction.reg_name(r) == 'r'+str(register) for r in instruction.regs_access()[1]):
            break
thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
thumb.detail = True
halves = struct.unpack('<'+'H'*(len(data)//2), data[:len(data)//2*2])
for i in range(len(halves)-1):
    h1, h2 = halves[i:i+2]
    if h1 & 0xFBF0 != 0xF240 or h2 & 0x8000:
        continue
    low = (h1 & 0xf) << 12 | (h1 >> 10 & 1) << 11 | (h2 >> 12 & 7) << 8 | (h2 & 0xff)
    if low not in low_words:
        continue
    register = h2 >> 8 & 0xf
    for ins in thumb.disasm(data[i*2+4:i*2+44], load_base+i*2+4):
        if ins.mnemonic == 'movt' and ins.op_str.startswith('r'+str(register)+','):
            high = ins.operands[1].imm
            address = high << 16 | low
            if address in targets:
                targets[address]['thumb_pairs'].append(dict(movw_va=hex(load_base+i*2), movt_va=hex(ins.address)))
        if ins.mnemonic.startswith(('b', 'pop')):
            break
        if any(ins.reg_name(r) == 'r'+str(register) for r in ins.regs_access()[1]):
            break
report = dict(binary=str(binary), sha256=hashlib.sha256(data).hexdigest(), load_base=hex(load_base),
              limitation='Linear ARM/Thumb MOVW-MOVT and ARM literal scan. Xrefs and load layout require validation; indirect references omitted.',
              strings=list(targets.values()))
with (args.output or base / 'cp-lut-xrefs-thumb.json').open('x') as output:
    json.dump(report, output, indent=2)
for item in targets.values():
    print(item['va'], item['text'], item['xrefs'], item['mov_pairs'], item['thumb_pairs'])
