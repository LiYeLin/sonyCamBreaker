"""Record offline string evidence, not function addresses or control-flow proof."""
import hashlib
import json
from pathlib import Path
import re

base = Path(__file__).parent / "a7c2-2.01"
binary = base / "selected/files/lib/appFw.so"
data = binary.read_bytes()
pattern = re.compile(rb"set_pplut_link|send_lut|set_base_picture_setting_i|/usr/data/lut|"
                     rb"get_select_lut_by_pp|convert_paint_struct_base_look_select")
matches = []
for match in re.finditer(rb"[\x20-\x7e]{8,}", data):
    if pattern.search(match.group()):
        matches.append({"file_offset": hex(match.start()),
                        "text": match.group().decode("ascii")})
report = {"binary": str(binary), "sha256": hashlib.sha256(data).hexdigest(),
          "note": "String file offsets only; not executable patch addresses.",
          "matches": matches}
(base / "lut-string-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
print("Recorded", len(matches), "candidate strings")
