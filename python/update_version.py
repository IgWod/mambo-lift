#!/bin/python3

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

import argparse
import struct
import sys

# Define the format string for Elf64_Sym
elf64_version_format = "H"
elf64_version_size = struct.calcsize(elf64_version_format)

def read_and_modify_elf64_version(filename, value):
    with open(filename, "rb") as f:
        data = f.read()

    modified_data = bytearray(data)

    for i in range(0, len(data), elf64_version_size):
        if i + elf64_version_size > len(data):
            break
        version = struct.unpack(elf64_version_format, data[i:i + elf64_version_size])
        version = list(version)
        
        if version[0] != 0 and version[0] != 1:
            version[0] = value
        
        packed_version = struct.pack(elf64_version_format, *version)
        
        modified_data[i:i + elf64_version_size] = packed_version

    with open(filename, "wb") as f:
        f.write(modified_data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        prog="update_version.py",
                        description="""
                        Update version elements in the raw binary file containing Elf64_Half. The input file is assumed
                        to be a binary file of .gnu.version of an ELF file using the objcopy utility. This file can be
                        later embeded into an ELF file .gnu.version section.
                        """,
                        epilog="Part of mambo-lift repository.")

    parser.add_argument("filename", help="Raw binary file to be processed.")
    parser.add_argument("value", help="Integer set to each version entry.")

    args = parser.parse_args()

    filename = args.filename
    value = int(args.value, 0)
    read_and_modify_elf64_version(filename, value)
