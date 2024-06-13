#!/bin/python3

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.enums import ENUM_ST_INFO_TYPE

def _get_section(filename, section_name):
     with open(filename, "rb") as binary:
        elf = ELFFile(binary)

        section = elf.get_section_by_name(section_name)

        return (section["sh_addr"], section["sh_size"], section.data())
   

def get_text_section(filename):
    return _get_section(filename, ".text")

def get_plt_section(filename):
    return _get_section(filename, ".plt")

def get_init_array_section(filename):
    return _get_section(filename, ".init_array")

def get_symbol_info_by_addr(filename, addr):
    with open(filename, "rb") as binary:
        elf = ELFFile(binary)

        section = elf.get_section_by_name('.symtab')

        if not section:
            return ""

        if isinstance(section, SymbolTableSection):
            for s in section.iter_symbols():
                if ENUM_ST_INFO_TYPE[s.entry["st_info"]["type"]] == ENUM_ST_INFO_TYPE["STT_FUNC"] and s.entry["st_value"] == addr:
                    return (s.name)
        return ""

def get_plt_symbol_by_addr(filename, addr):
    with open(filename, "rb") as binary:
        elf = ELFFile(binary)

        dynsym = elf.get_section_by_name(".dynsym")
        rela_plt = elf.get_section_by_name(".rela.plt")
        plt = elf.get_section_by_name(".plt")

        if not dynsym or not rela_plt or not plt:
            return ""

        if addr < plt["sh_addr"] or addr >= (plt["sh_addr"] + plt["sh_size"]):
            return ""

        offset = int((addr - plt["sh_addr"] - 0x20) / 16)
        idx = rela_plt.get_relocation(offset)["r_info_sym"]

        return dynsym.get_symbol(idx).name.strip()

def get_symbols(filename):
    with open(filename, "rb") as binary:
        elf = ELFFile(binary)

        section = elf.get_section_by_name('.symtab')

        if not section:
            return []

        if isinstance(section, SymbolTableSection):
            symbols = []
            for s in section.iter_symbols():
                if ENUM_ST_INFO_TYPE[s.entry["st_info"]["type"]] == ENUM_ST_INFO_TYPE["STT_FUNC"]:
                    symbols.append((s.entry["st_value"], s.name))
            return symbols

        return []

def get_plt_symbols(filename):
    with open(filename, "rb") as binary:
        elf = ELFFile(binary)

        dynsym = elf.get_section_by_name(".dynsym")
        rela_plt = elf.get_section_by_name(".rela.plt")
        plt = elf.get_section_by_name(".plt")

        if not dynsym or not rela_plt or not plt:
            return []

        symbols = []
        for addr in range(plt["sh_addr"], plt["sh_addr"] + plt["sh_size"], 16):
            offset = int((addr - plt["sh_addr"] - 0x20) / 16)
            idx = rela_plt.get_relocation(offset)["r_info_sym"]
            symbol = dynsym.get_symbol(idx).name.strip()
            symbols.append((addr, symbol))

        return symbols 
