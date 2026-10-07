"""Offline Sony DAT inspection; never connects to a camera or executes firmware."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument("input", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
sys.path.insert(0, str(Path(__file__).parent / "fwtool-cxd90057"))
from fwtool.sony import dat, fdat

args.output.mkdir(parents=True, exist_ok=False)
report = {"input": str(args.input), "size": args.input.stat().st_size}
with args.input.open("rb") as source:
    report["sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
    source.seek(0)
    container = dat.readDat(source)  # Includes DAT CRC validation.
    report["dat_crc_valid"] = True
    crypter, decrypted = fdat.decryptFdat(container.firmwareData)
    report["crypter"] = crypter
    print("DAT CRC valid; selected", crypter, flush=True)
    with (args.output / "firmware.fdat").open("wb") as target:
        shutil.copyfileobj(decrypted, target)
with (args.output / "firmware.fdat").open("rb") as source:
    contents = fdat.readFdat(source)  # Includes FDAT header CRC validation.
    report.update(model=hex(contents.model), region=contents.region,
                  version=contents.version, fdat_header_crc_valid=True)
    for name, data in [("firmware.tar", contents.firmware), ("updater.img", contents.fs)]:
        with (args.output / name).open("wb") as target:
            shutil.copyfileobj(data, target)
with tarfile.open(args.output / "firmware.tar", "r:*") as archive:
    report["members"] = [dict(name=m.name, size=m.size, type=m.type.decode("ascii", "replace"))
                         for m in archive.getmembers()]
(args.output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
