"""Inventory an offline ext2 image, optionally copy named regular files only."""
import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys

parser = argparse.ArgumentParser()
parser.add_argument("image", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--copy", action="append", default=[])
parser.add_argument("--format", choices=["ext2", "fat"], default="ext2")
parser.add_argument("--quiet", action="store_true")
args = parser.parse_args()
sys.path.insert(0, str(Path(__file__).parent / "fwtool-cxd90057"))
from fwtool.archive.ext2 import readExt2
from fwtool.archive.fat import readFat

args.output.mkdir(parents=True, exist_ok=False)
inventory = []
with args.image.open("rb") as source:
    for member in (readExt2 if args.format == "ext2" else readFat)(source):
        entry = dict(path=member.path, size=member.size, mode=oct(member.mode))
        if stat.S_ISREG(member.mode):
            entry["header"] = member.contents.read(16).hex()
            if member.path in args.copy:
                relative = PurePosixPath(member.path.lstrip("/"))
                if ".." in relative.parts:
                    raise ValueError("Unsafe path")
                target = args.output / "files" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                member.contents.seek(0)
                with target.open("xb") as dest:
                    shutil.copyfileobj(member.contents, dest)
        inventory.append(entry)
(args.output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
print("Inventoried", len(inventory), "entries")
for entry in inventory:
    if not args.quiet and stat.S_ISREG(int(entry["mode"], 8)):
        print(entry["size"], entry["path"], entry.get("header", ""))
