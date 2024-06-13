#!/bin/python3

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

import argparse
import struct
import sys

# Define the format string for Elf64_Sym
elf64_sym_format = "IBBHQQ"
elf64_sym_size = struct.calcsize(elf64_sym_format)

def read_and_modify_elf64_symbols(filename, add_offset):
    with open(filename, "rb") as f:
        data = f.read()

    modified_data = bytearray(data)

    for i in range(0, len(data), elf64_sym_size):
        if i + elf64_sym_size > len(data):
            break
        symbol = struct.unpack(elf64_sym_format, data[i:i + elf64_sym_size])
        symbol = list(symbol)
        
        if symbol[0] != 0:
            symbol[0] += add_offset
        
        packed_symbol = struct.pack(elf64_sym_format, *symbol)
        
        modified_data[i:i + elf64_sym_size] = packed_symbol

    with open(filename, "wb") as f:
        f.write(modified_data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        prog="update_syms.py",
                        description="""
                        Update index to the string table of symbols in the raw binary file containing Elf64_Sym structs.
                        The input file is assumed to be a binary file of .dynsym (or .symtab) of an ELF file using the
                        objcopy utility. This file can be later embeded into an ELF file .dynsym (or symtab) section.
                        """,
                        epilog="Part of mambo-lift repository.")

    parser.add_argument("filename", help="Raw binary file to be processed.")
    parser.add_argument("offset", help="Integer added to each string index.")

    args = parser.parse_args()

    filename = args.filename
    add_offset = int(args.offset, 0)
    read_and_modify_elf64_symbols(filename, add_offset)
