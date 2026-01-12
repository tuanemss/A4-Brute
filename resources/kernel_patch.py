#!/usr/bin/env python3
import sys
import re
import pathlib

pattern = re.compile(r"B0F5FA6F00F0(92|A2|82)80")
replacement = "B0F5FA6F0C460C46"

def patch_file(input_path: pathlib.Path):
    with open(input_path, "rb") as f:
        data = f.read()

    hex_data = data.hex().upper()

    patched_hex, count = pattern.subn(replacement, hex_data)

    output_path = input_path.with_suffix(".patched")

    with open(output_path, "wb") as f:
        f.write(bytes.fromhex(patched_hex))

    print(f"Patched {input_path} -> {output_path} ({count} changes)")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patch.py *.raw")
        sys.exit(1)

    files = []
    for arg in sys.argv[1:]:
        files.extend(pathlib.Path().glob(arg))

    if not files:
        print("No matching files found!")
        sys.exit(1)

    for inp in files:
        patch_file(inp)

if __name__ == "__main__":
    main()
