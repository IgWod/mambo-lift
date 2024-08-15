#!/bin/bash

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

POSITIONAL_ARGS=()

OPTS="-O3"

while [[ $# -gt 0 ]]; do
  case $1 in
    --size)
      OPTS="-Os"
      shift
      ;;
    --pac)
      OPTS="-O3 -march=armv8.3-a -mbranch-protection=standard"
      shift
      ;;
    --size-no-inline)
      OPTS="-Os -fno-inline"
      shift
      ;;
    --pac-no-ilnine)
      OPTS="-O3 -march=armv8.3-a -mbranch-protection=standard -fno-inline"
      shift
      ;;
    --no-inline)
      OPTS="-O3 -fno-inline"
      shift
      ;;
    --out)
      OUT=${2}
      shift 2
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

OUT="${OUT:=${1}_lifted}"

CC="${CC:=cc}"

TMP_DIR=/tmp/lifter

LDPATHS="-L${UNICORN_ROOT}/build"
LDFLAGS="-lstdc++ -lm -lz -lunishare -lm -lz -lpthread -ldl"
CFLAGS="-flax-vector-conversions -std=c99 -fno-strict-aliasing"
WFLAGS="-Wno-return-type -Wno-int-conversion -Wno-parentheses-equality -Wno-incompatible-function-pointer-types -Wno-typedef-redefinition"

mkdir -p $TMP_DIR

$LIFT_ROOT/bash/extract-sections.sh ${1}

${CC} -o ${OUT} "${1}"_concat.c trampolines.S "${LIFT_ROOT}/runtime/helper.S" ${LDPATHS} ${LDFLAGS} ${CFLAGS} ${WFLAGS} ${OPTS} -Wl,-T /tmp/lifter/custom.ld

$LIFT_ROOT/bash/extract-sections.sh ${1} "${1}"_lifted --second-pass

${CC} -o ${OUT} "${1}"_concat.c trampolines.S "${LIFT_ROOT}/runtime/helper.S" ${LDPATHS} ${LDFLAGS} ${CFLAGS} ${WFLAGS} ${OPTS} -Wl,-T /tmp/lifter/custom.ld

rm -r $TMP_DIR
