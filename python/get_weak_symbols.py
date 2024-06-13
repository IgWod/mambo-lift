#!/bin/python3

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

import argparse

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND

def get_weak_symbols(elf_file_path):
    with open(elf_file_path, "rb") as elf:
        elffile = ELFFile(elf)
        
        dynsym_section = elffile.get_section_by_name(".dynsym")

        for symbol in dynsym_section.iter_symbols():
            if symbol["st_info"]["bind"] == "STB_WEAK" and symbol["st_value"] != 0:
                print("PROVIDE (%s = 0x%lx);" % (symbol.name, symbol["st_value"]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        prog="get_weak_symbols.py",
                        description="""
                        Print all weak symbols from the .dynsym section of a binary in the linker script
                        format `PROVIDE (symbol = address);`. Only symbols with non-zero st_value are
                        printed.
                        """,
                        epilog="Part of mambo-lift repository.")

    parser.add_argument("filename", help="ELF file to be processed.")

    args = parser.parse_args()

    get_weak_symbols(args.filename)
