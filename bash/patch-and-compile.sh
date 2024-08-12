#!/bin/bash

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

CC="${CC:=cc}"

TMP_DIR=/tmp/lifter

LDPATHS="-L${UNICORN_ROOT}/build"
LDFLAGS="-lstdc++ -lm -lz -lunishare -lm -lz -lpthread -ldl"
CFLAGS="-flax-vector-conversions -std=c99 -fno-strict-aliasing"
WFLAGS="-Wno-return-type -Wno-int-conversion -Wno-parentheses-equality -Wno-incompatible-function-pointer-types -Wno-typedef-redefinition"

mkdir -p $TMP_DIR

$LIFT_ROOT/bash/extract-sections.sh ${1}

${CC} -o "${1}"_lifted "${1}"_concat.c trampolines.s "${LIFT_ROOT}/runtime/helper.S" ${LDPATHS} ${LDFLAGS} ${CFLAGS} ${WFLAGS} -O3 -Wl,-T /tmp/lifter/custom.ld

$LIFT_ROOT/bash/extract-sections.sh ${1} "${1}"_lifted --second-pass

${CC} -o "${1}"_lifted "${1}"_concat.c trampolines.s "${LIFT_ROOT}/runtime/helper.S" ${LDPATHS} ${LDFLAGS} ${CFLAGS} ${WFLAGS} -O3 -Wl,-T /tmp/lifter/custom.ld

rm -r $TMP_DIR
