#!/usr/bin/env python3
"""
Kernel AES patch for bruteforce tool
Patches IOAESAccelerator to enable keybag access
"""
import sys
import pathlib

def patch_kernel(input_path: pathlib.Path):
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    # Pattern: B0 F5 FA 6F 00 F0 [92|A2|82] 80
    pattern_prefix = bytes([0xB0, 0xF5, 0xFA, 0x6F, 0x00, 0xF0])
    valid_bytes = [0x92, 0xA2, 0x82]
    
    found = None
    for i in range(len(data) - 8):
        if data[i:i+6] == pattern_prefix:
            if data[i+6] in valid_bytes and data[i+7] == 0x80:
                found = i
                break
    
    if found is None:
        print(f"Target pattern not found for IOAESAccelerator patch.")
        return False
    
    print(f"Patching IOAESAccelerator at offset 0x{found:x}")
    
    # Patch bytes at offset+4 through offset+7 to: 0C 46 0C 46 ( NOP )
    data[found + 4] = 0x0C
    data[found + 5] = 0x46
    data[found + 6] = 0x0C
    data[found + 7] = 0x46
    
    output_path = input_path.with_suffix(".patched")
    with open(output_path, "wb") as f:
        f.write(data)
    
    print(f"Patched kernel saved to {output_path}")
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 kernel_patch.py <kernel.raw>")
        sys.exit(1)

    for arg in sys.argv[1:]:
        path = pathlib.Path(arg)
        if path.exists():
            if not patch_kernel(path):
                sys.exit(1)
        else:
            print(f"File not found: {arg}")
            sys.exit(1)

if __name__ == "__main__":
    main()
