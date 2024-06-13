#!/bin/bash

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

TMP_DIR=/tmp/lifter

extract_section_update_syms() {
    objcopy -O binary --only-section=.${2} ${1} $TMP_DIR/${2} 2> /dev/null
    PYTHONPATH=python/pyelftools/ python3 $LIFT_ROOT/python/update_syms.py $TMP_DIR/${2} ${3}
    objcopy -I binary -O default --rename-section .data=_.${2} -S $TMP_DIR/${2} $TMP_DIR/${2}.o 2> /dev/null
}

extract_section_update_version() {
    objcopy -O binary --only-section=.${2} ${1} $TMP_DIR/${2} 2> /dev/null
    PYTHONPATH=python/pyelftools/ python3 $LIFT_ROOT/python/update_version.py $TMP_DIR/${2} ${3}
    objcopy -I binary -O default --rename-section .data=_.${2} -S $TMP_DIR/${2} $TMP_DIR/${2}.o 2> /dev/null
}

extract_section_rename() {
    objcopy -O binary --only-section=.${2} ${1} $TMP_DIR/${2} 2> /dev/null
    objcopy -I binary -O default --rename-section .data=${3} -S $TMP_DIR/${2} $TMP_DIR/${2}.o 2> /dev/null
}

extract_section() {
    extract_section_rename ${1} ${2} .${2}
}

generate_zero_section () {
    dd bs=${2} seek=1 of=$TMP_DIR/${1} count=0 2> /dev/null
    objcopy -I binary -O default --rename-section .data=.${1} -S $TMP_DIR/${1} $TMP_DIR/${1}.o 2> /dev/null
}
get_section_size() {
    size_hex=$(readelf -SW ${1} | grep "\.${2} " | head -n 1 | sed 's/\[ .*\]/\[\]/' | awk '{ print $6 }')
    echo $((16#${size_hex}))
}

get_section_addr() {
    echo "0x"$(readelf -SW ${1} | grep "\.${2} " | head -n 1 | sed 's/\[ .*\]/\[\]/' | awk '{ print $4 }')
}

get_num_symbols() {
    echo $(readelf -sW ${1} 2> /dev/null | fgrep ${2} | head -n 1 | awk '{print $5}')
}

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    --second-pass)
      SECOND_PASS=YES
      shift
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}"

if readelf -SW ${1} | grep .data.rel.ro > /dev/null; then
    REL_RO_EXISTS=1
else
    REL_RO_EXISTS=0
fi

# Extract sections as they are in the original binary
extract_section ${1} rodata
extract_section ${1} got
extract_section ${1} data
extract_section ${1} rela.dyn
extract_section ${1} init_array
extract_section ${1} fini_array
if [[ "$REL_RO_EXISTS" -eq 1 ]]; then
    extract_section ${1} data.rel.ro
fi

# Extract section with a placeholder section name. We use different section name to later enforce correct linking
# order. Any new symbol and string sections need to be linked to the end of the new section to avoid disrupting
# compiler generated symbols.
extract_section_rename ${1} dynsym _.dynsym
extract_section_rename ${1} dynstr _.dynstr
extract_section_rename ${1} gnu.version _.gnu.version

# TODO: .bss should be a NOBITS section to reduce ELF size, but having PROGBITS section filled with zeros is
# functionally equivalent.
generate_zero_section bss $(get_section_size ${1} bss)

# Before we can patch relocs and symbols we need to know how many new symbols are in the new binary. We first
# then create new binary without patched relocs/symbols and then extract the information we need from the new
# binary, patch relocs/symbols and compile the lifted code again this time with complete information.
if ! [ -z ${SECOND_PASS+x} ]; then
    old_num=$(get_num_symbols ${1} .dynsym)
    new_num=$(get_num_symbols ${2} .dynsym)
    num_diff=$((new_num-old_num))
    PYTHONPATH=$LIFT_ROOT/python/pyelftools/ python3 $LIFT_ROOT/python/update_relocs.py $TMP_DIR/rela.dyn.o $num_diff
    
    old_size=$(get_section_size ${1} dynstr)
    new_size=$(get_section_size ${2} dynstr)
    size_diff=$((new_size-old_size))
    extract_section_update_syms ${1} dynsym $size_diff

    # We clear versions by setting all symbols to 1 (*global*); same behaviour as clearing versions with patchelf.
    extract_section_update_version ${1} gnu.version 1
fi

if [[ "$REL_RO_EXISTS" -eq 1 ]]; then
    cat $LIFT_ROOT/link/custom.ld.part1 custom.ld.part2 $LIFT_ROOT/link/custom.ld.part3 $LIFT_ROOT/link/custom.ld.part4 $LIFT_ROOT/link/custom.ld.part5 > $TMP_DIR/custom.ld
else
    cat $LIFT_ROOT/link/custom.ld.part1 custom.ld.part2 $LIFT_ROOT/link/custom.ld.part3 $LIFT_ROOT/link/custom.ld.part5 > $TMP_DIR/custom.ld
fi

# Populate stubs for weak symbols
weak_symbols=$(PYTHONPATH=$LIFT_ROOT/python/pyelftools/ python3 $LIFT_ROOT/python/get_weak_symbols.py ${1})
sed -i "s|WEAK_SYMBOLS_STUBS|${weak_symbols}|g" $TMP_DIR/custom.ld

# Populate custom linker script with correct path
sed -i "s|TMP_DIR|${TMP_DIR}|g" $TMP_DIR/custom.ld

# Populate custom linker script with correct addresss
sed -i "s/OLD_RODATA_ADDR/$(get_section_addr ${1} rodata)/g" $TMP_DIR/custom.ld
sed -i "s/OLD_BSS_ADDR/$(get_section_addr ${1} bss)/g" $TMP_DIR/custom.ld
sed -i "s/OLD_GOT_ADDR/$(get_section_addr ${1} got)/g" $TMP_DIR/custom.ld
sed -i "s/OLD_DATA_ADDR/$(get_section_addr ${1} data)/g" $TMP_DIR/custom.ld
sed -i "s/OLD_RELA_DYN_ADDR/$(get_section_addr ${1} rela.dyn)/g" $TMP_DIR/custom.ld
sed -i "s/OLD_INIT_ADDR/$(get_section_addr ${1} init_array)/g" $TMP_DIR/custom.ld
sed -i "s/OLD_FINI_ADDR/$(get_section_addr ${1} fini_array)/g" $TMP_DIR/custom.ld
if [[ "$REL_RO_EXISTS" -eq 1 ]]; then
    sed -i "s/OLD_DATA_REL_RO_ADDR/$(get_section_addr ${1} data.rel.ro)/g" $TMP_DIR/custom.ld
fi
