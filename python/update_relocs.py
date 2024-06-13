#!/bin/python3

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

import argparse
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

R_AARCH64_GLOB_DAT = 1025

def update_relocation_entries(filename, offset):
    with open(filename, "r+b") as fout:
        elf = ELFFile(fout)
        
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                entries = list(section.iter_relocations())
                
                for idx, rela in enumerate(entries):
                    # Only update relocations making use of symbols
                    if rela["r_info_type"] == R_AARCH64_GLOB_DAT:
                        new_r_sym = rela["r_info_sym"] + offset
                        new_r_info = (new_r_sym << 32) | (rela["r_info"] & 0xFFFFFFFF)
                        rela.entry["r_info"] = new_r_info
                        
                        entry_offset = section["sh_offset"] + (idx * section["sh_entsize"])
                        
                        fout.seek(entry_offset)
                        fout.write(section.structs.Elf_Rela.build(rela.entry))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        prog="update_relocs.py",
                        description="""
                        Update symbol indicies in global relocations by adding *offset* to the current symbol index.
                        Currently only R_AARCH64_GLOB_DATA are updated. Input has to be a valid ELF file containing
                        relocation sections (e.g., .rela.dyn).
                        """,
                        epilog="Part of mambo-lift repository.")

    parser.add_argument("filename", help="ELF file to be processed.")
    parser.add_argument("offset", help="Integer added to each symbol index.")

    args = parser.parse_args()

    filename = args.filename
    offset = int(args.offset)

    update_relocation_entries(filename, offset)

