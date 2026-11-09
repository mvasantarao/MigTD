#!/usr/bin/env python3
"""Install the MigTD-owned v1 validation contract, not any build/source tree."""

import argparse
from pathlib import Path
import shutil

from validate_bundle import SCHEMA_NAME, schema_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    destination = args.destination
    sources = [Path(__file__).with_name(name) for name in (
        "validate_bundle.py", "image_content.py", "requirements.txt",
    )] + [schema_path()]
    names = {p.name for p in sources}
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            parser.error("destination is not a nonsymlink directory")
        existing = {p.name for p in destination.iterdir()}
        if not args.replace or not existing <= names:
            parser.error("destination exists; --replace permits only owned contract files")
    destination.mkdir(parents=True, exist_ok=True)
    for source in sources:
        target = destination / (SCHEMA_NAME if source == schema_path() else source.name)
        shutil.copyfile(source, target)
        target.chmod(0o644)
    print(f"Installed the v1 consumer contract: {destination}")


if __name__ == "__main__":
    main()
