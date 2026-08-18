#!/usr/bin/env python3

from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUTPUT_ROOT = ROOT / "dev"
SOURCE_MANIFESTS = {
    "chromium": ROOT / "manifests" / "manifest.chromium.json",
    "firefox": ROOT / "manifests" / "manifest.firefox.json",
}
IGNORED_NAMES = {
    ".git",
    ".codegraph",
    "dev",
    "manifests",
    "__pycache__",
}


def copy_project(target_dir: Path) -> None:
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    for item in ROOT.iterdir():
        if item.name in IGNORED_NAMES:
            continue

        destination = target_dir / item.name
        if item.is_dir():
            shutil.copytree(item, destination, ignore=shutil.ignore_patterns(".DS_Store"))
        else:
            shutil.copy2(item, destination)


def build_variant(name: str, manifest_path: Path) -> None:
    target_dir = OUTPUT_ROOT / name
    copy_project(target_dir)
    shutil.copy2(manifest_path, target_dir / "manifest.json")


def main() -> None:
    OUTPUT_ROOT.mkdir(exist_ok=True)

    for variant_name, manifest_path in SOURCE_MANIFESTS.items():
        build_variant(variant_name, manifest_path)

    print(f"Built extension variants in: {OUTPUT_ROOT}")
    print("Chromium load path: dev/chromium")
    print("Firefox manifest path: dev/firefox/manifest.json")


if __name__ == "__main__":
    main()
