#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Add MindTheGapps to the Android system disk that Andarium carries.

Reads the staged `andarium-system` directory of an Andarium build, unpacks the
`product` and `system_ext` EROFS partitions of `guest/system.img` with their
owners, modes and SELinux labels, and copies the GApps files in the way the
MindTheGapps installer does: root:root, 0755 directories, 0644 files (0755 for
.sh), every file labelled system_file. It then repacks both partitions with the
image's compression (Zstandard level 15, 16 KiB physical clusters), reassembles
the disk with `ubd-disk.py assemble`, and writes the new disk, its partition
layout and the release manifest with the new sizes and digests.

Run as root: unpacking keeps owners and security.* extended attributes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

LABEL_XATTR = "security.selinux"
LABEL = b"u:object_r:system_file:s0"
PARTITIONS = ("product", "system_ext")
# What the MindTheGapps installer itself removes on a device without room.
SLIM = (
    "product/app/GoogleTTS",
    "product/app/SpeechServicesByGoogle",
    "product/app/talkback",
    "product/priv-app/GoogleRestore",
    "product/priv-app/Velvet",
    "product/priv-app/VelvetTitan",
    "product/priv-app/Wellbeing",
    "system_ext/priv-app/SetupWizard",
)
CHUNK = 1 << 24


class Failure(Exception):
    pass


def log(message: str = "") -> None:
    print(message, flush=True)


def run(command: list[str], *, capture: bool = False) -> str:
    log("+ " + " ".join(command))
    result = subprocess.run(
        command, check=False, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if result.returncode != 0:
        if capture and result.stdout:
            log(result.stdout[-6000:])
        raise Failure(f"{command[0]} exited with {result.returncode}")
    return result.stdout or ""


def help_text(tool: str) -> str:
    result = subprocess.run([tool, "--help"], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    return result.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_range(path: Path, start: int, length: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        handle.seek(start)
        remaining = length
        while remaining:
            chunk = handle.read(min(CHUNK, remaining))
            if not chunk:
                raise Failure(f"{path} ends before byte {start + length}")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def copy_range(source: Path, start: int, length: int, destination: Path) -> None:
    with source.open("rb") as src, destination.open("wb") as dst:
        src.seek(start)
        remaining = length
        while remaining:
            chunk = src.read(min(CHUNK, remaining))
            if not chunk:
                raise Failure(f"{source} ends before byte {start + length}")
            dst.write(chunk)
            remaining -= len(chunk)


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise Failure(f"{path} is not a JSON object")
    return document


def policy_images(policy: dict) -> dict[str, str]:
    system = policy["system_disk"]
    entries = list(system.get("boot_partitions", [])) + list(system.get("filesystem_partitions", []))
    return {entry["name"]: entry["image"] for entry in entries}


def label_census(root: Path) -> tuple[int, int, dict[bytes, int]]:
    total = labelled = 0
    labels: dict[bytes, int] = {}
    for entry in [root] + [Path(d) / n for d, ds, fs in os.walk(root) for n in ds + fs]:
        total += 1
        try:
            value = os.getxattr(entry, LABEL_XATTR, follow_symlinks=False)
        except OSError:
            continue
        labelled += 1
        labels[value] = labels.get(value, 0) + 1
    return total, labelled, labels


def show_census(name: str, root: Path) -> tuple[int, int]:
    total, labelled, labels = label_census(root)
    log(f"{name}: {labelled}/{total} entries carry {LABEL_XATTR}")
    for value, count in sorted(labels.items(), key=lambda item: -item[1])[:8]:
        log(f"    {count:6d}  {value!r}")
    return total, labelled


def excluded(relative: str, full: bool) -> str | None:
    if any("migrat" in part.lower() for part in relative.split("/")):
        return "Android Switch / cable migration"
    if not full:
        for prefix in SLIM:
            if relative == prefix or relative.startswith(prefix + "/"):
                return "slim"
    return None


def add_gapps(archive: Path, roots: dict[str, Path], label: bytes, full: bool) -> list[str]:
    added: list[str] = []
    overwritten: list[str] = []
    dropped: list[str] = []
    skipped: list[str] = []
    new_dirs: list[Path] = []
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if not any(info.filename.startswith("system/product/") for info in members):
            tops = sorted({info.filename.split("/", 1)[0] for info in members})
            raise Failure(f"no system/product/ in {archive.name}; top level: {tops}")
        if "build.prop" in bundle.namelist():
            log("GApps build.prop:\n" + bundle.read("build.prop").decode(errors="replace").strip())
        for info in members:
            name = info.filename
            if info.is_dir():
                continue
            if not name.startswith("system/"):
                if not name.startswith("META-INF/") and name != "build.prop":
                    skipped.append(name)
                continue
            relative = name[len("system/"):]
            partition, _, inner = relative.partition("/")
            if partition not in roots or not inner:
                skipped.append(name)
                continue
            reason = excluded(relative, full)
            if reason:
                dropped.append(f"{relative}  [{reason}]")
                continue
            inner_path = Path(inner)
            if inner_path.is_absolute() or ".." in inner_path.parts:
                raise Failure(f"unsafe path in the GApps archive: {name}")
            destination = roots[partition] / inner_path
            missing = []
            parent = destination.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            if not parent.is_dir() or parent.is_symlink():
                raise Failure(f"{parent} is not a directory in the image")
            for directory in reversed(missing):
                directory.mkdir()
                new_dirs.append(directory)
            if destination.is_symlink() or destination.exists():
                if destination.is_dir() and not destination.is_symlink():
                    raise Failure(f"{relative} is a directory in the image")
                overwritten.append(relative)
                destination.unlink()
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                os.symlink(bundle.read(info).decode(), destination)
            else:
                with bundle.open(info) as src, destination.open("wb") as dst:
                    shutil.copyfileobj(src, dst, CHUNK)
                os.chmod(destination, 0o755 if destination.suffix == ".sh" else 0o644)
            os.chown(destination, 0, 0, follow_symlinks=False)
            os.setxattr(destination, LABEL_XATTR, label, follow_symlinks=False)
            added.append(relative)
    for directory in new_dirs:
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o755)
        os.setxattr(directory, LABEL_XATTR, label, follow_symlinks=False)
    log(f"\nAdded {len(added)} GApps files, {len(new_dirs)} new directories:")
    for relative in added:
        path = roots[relative.split("/", 1)[0]] / relative.split("/", 1)[1]
        size = path.lstat().st_size
        log(f"    {size / 1048576:8.1f} MB  {relative}")
    log(f"Left out {len(dropped)}:")
    for item in dropped:
        log(f"    {item}")
    log(f"Not for product/system_ext, skipped {len(skipped)}: {skipped}")
    log(f"Replaced {len(overwritten)} existing files: {overwritten}")
    return added


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--system", type=Path, required=True,
                        help="staged andarium-system directory")
    parser.add_argument("--gapps", type=Path, required=True, help="MindTheGapps zip")
    parser.add_argument("--policy", type=Path, required=True, help="disk-policy.json")
    parser.add_argument("--disk-tool", type=Path, required=True, help="ubd-disk.py")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--full", action="store_true",
                        help="keep the apps the GApps installer drops on small devices")
    arguments = parser.parse_args()

    if os.geteuid() != 0:
        raise Failure("run as root: unpacking keeps owners and security labels")
    system_dir = arguments.system
    disk = system_dir / "guest/system.img"
    layout_path = system_dir / "guest/partition-layout.json"
    manifest_path = system_dir / "release-manifest.json"
    layout = read_json(layout_path)
    manifest = read_json(manifest_path)
    policy = read_json(arguments.policy)
    images = policy_images(policy)
    log(f"release {manifest.get('release_id')}  android {json.dumps(manifest.get('android'))[:300]}")

    fsck_help = help_text("fsck.erofs")
    mkfs_help = help_text("mkfs.erofs")
    log(subprocess.run(["mkfs.erofs", "-V"], text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, check=False).stdout.strip())
    if "xattrs" not in fsck_help or "--preserve" not in fsck_help:
        log(fsck_help)
        raise Failure("this fsck.erofs cannot extract owners and extended attributes")

    work = arguments.work
    if work.exists():
        shutil.rmtree(work)
    images_dir = work / "images"
    trees = work / "trees"
    fresh = work / "new"
    for directory in (images_dir, trees, fresh):
        directory.mkdir(parents=True)

    # 1. Cut every partition out of the disk and check it against the layout.
    partitions = layout["system_disk"]["partitions"]
    log(f"\nsystem disk: {disk.stat().st_size} bytes, {len(partitions)} partitions")
    for part in partitions:
        name = part["name"]
        if name not in images:
            raise Failure(f"partition {name} is not in the disk policy")
        length = part.get("image_bytes", part["size_bytes"])
        if sha256_range(disk, part["start_bytes"], part["size_bytes"]) != part["sha256"]:
            raise Failure(f"partition {name} does not match its layout digest")
        copy_range(disk, part["start_bytes"], length, images_dir / images[name])
        log(f"    {name:11s} {length:12d} bytes at {part['start_bytes']}")

    # 2. Unpack product and system_ext with owners, modes and labels.
    roots: dict[str, Path] = {}
    unlabelled: dict[str, int] = {}
    for name in PARTITIONS:
        image = images_dir / images[name]
        log("\n" + run(["dump.erofs", "-s", str(image)], capture=True)[:2500])
        root = trees / name
        run(["fsck.erofs", f"--extract={root}", "--xattrs", "--preserve", str(image)])
        total, labelled = show_census(name, root)
        if labelled < total * 0.98:
            raise Failure(f"unpacking {name} lost its SELinux labels")
        try:
            os.getxattr(root, LABEL_XATTR, follow_symlinks=False)
        except OSError:
            log(f"{name}: the root directory has no label; giving it system_file")
            os.setxattr(root, LABEL_XATTR, LABEL + b"\0", follow_symlinks=False)
            labelled += 1
        os.chown(root, 0, 0)
        os.chmod(root, 0o755)
        roots[name] = root
        unlabelled[name] = total - labelled

    sample = None
    for directory, _, files in os.walk(roots["product"]):
        for file in files:
            try:
                sample = os.getxattr(Path(directory) / file, LABEL_XATTR, follow_symlinks=False)
                break
            except OSError:
                continue
        if sample is not None:
            break
    if sample is None:
        raise Failure("no labelled file in product")
    label = LABEL + (b"\0" if sample.endswith(b"\0") else b"")
    log(f"\nlabel format of the image: {sample!r}; new files get {label!r}")

    # 3. Copy the GApps in.
    added = add_gapps(arguments.gapps, roots, label, arguments.full)
    if not any(path.startswith("product/") for path in added):
        raise Failure("no GApps files were added to product")
    for name, root in roots.items():
        total, labelled = show_census(name + " with GApps", root)
        if total - labelled > unlabelled[name]:
            raise Failure(f"{name} has new entries without a label")

    # 4. Repack both partitions as the image does.
    compressor = "-zzstd,level=15" if "level=" in mkfs_help else "-zzstd,15"
    for name in PARTITIONS:
        image = fresh / images[name]
        command = ["mkfs.erofs", compressor, "-C16384"]
        if "--workers" in mkfs_help:
            command.append(f"--workers={os.cpu_count() or 2}")
        run(command + [str(image), str(roots[name])])
        run(["fsck.erofs", str(image)])
        log(run(["dump.erofs", "-s", str(image)], capture=True)[:2500])
        old = (images_dir / images[name]).stat().st_size
        log(f"{name}: {old} -> {image.stat().st_size} bytes")
        shutil.move(image, images_dir / images[name])
        shutil.rmtree(roots[name])

    # 5. Reassemble the disk with the project's own tool.
    guest = arguments.output / "guest"
    if arguments.output.exists():
        shutil.rmtree(arguments.output)
    guest.mkdir(parents=True)
    run([sys.executable, "-I", str(arguments.disk_tool), "assemble", "--policy",
         str(arguments.policy), "--images-dir", str(images_dir), "--output-dir", str(guest)])
    new_layout = read_json(guest / "partition-layout.json")
    if new_layout.get("data_disk") != layout.get("data_disk"):
        log(json.dumps(layout.get("data_disk"), indent=2))
        log(json.dumps(new_layout.get("data_disk"), indent=2))
        raise Failure("the policy's data disk differs from the release's")
    old_ids = {(p["name"], p["type_guid"], p["unique_guid"]) for p in partitions}
    new_ids = {(p["name"], p["type_guid"], p["unique_guid"])
               for p in new_layout["system_disk"]["partitions"]}
    if old_ids != new_ids or layout["system_disk"].get("disk_guid") != new_layout["system_disk"].get("disk_guid"):
        raise Failure("the policy's partition identities differ from the release's")

    # 6. The manifest's inventory names the disk and the layout with their sizes.
    for entry in manifest.get("inventory", []):
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if path in ("guest/system.img", "guest/partition-layout.json"):
            produced = arguments.output / path
            entry["size"] = produced.stat().st_size
            if "sha256" in entry:
                entry["sha256"] = sha256_file(produced)
            log(f"manifest inventory {path}: {json.dumps(entry)}")
    (arguments.output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    log(f"\nold disk {disk.stat().st_size} bytes sha256 {layout['system_disk']['sha256']}")
    log(f"new disk {(guest / 'system.img').stat().st_size} bytes "
        f"sha256 {new_layout['system_disk']['sha256']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as error:
        print(f"add_gapps.py: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
