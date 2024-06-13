#!/bin/bash

# Copyright 2024 Igor Wodiany
# Licensed under the Apache License, Version 2.0 (the "License")

sed -i "s/native_call(close)/x0.s = close(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(malloc)/x0.s = (int64_t) malloc(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(puts)/x0.s = puts((const char*)x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fclose)/x0.s = fclose(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(putchar)/x0.s = putchar(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(strlen)/x0.s = strlen((const char*)x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(textdomain)/x0.s = textdomain(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(atexit)/x0.s = atexit(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(getpwuid)/x0.s = getpwuid(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(getenv)/x0.s = getenv(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(nl_langinfo)/x0.s = nl_langinfo(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fflush)/x0.s = fflush(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(isatty)/x0.s = isatty(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(tolower)/x0.s = tolower(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutexattr_destroy)/x0.s = pthread_mutexattr_destroy(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutexattr_init)/x0.s = pthread_mutexattr_init(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutex_destroy)/x0.s = pthread_mutex_destroy(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutex_lock)/x0.s = pthread_mutex_lock(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutex_unlock)/x0.s = pthread_mutex_unlock(x0.s); return (pair) {.a = x0, .b = x1}/" "${1}".c

sed -i "s/native_call(free)/free(x0.s)/" "${1}".c
sed -i "s/native_call(exit)/exit(x0.s)/" "${1}".c

sed -i "s/native_call(getuid)/x0.s = getuid(); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(getpid)/x0.s = getpid(); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(__errno_location)/x0.s = __errno_location(); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(__ctype_b_loc)/x0.s = __ctype_b_loc(); return (pair) {.a = x0, .b = x1}/" "${1}".c

sed -i "s/native_call(__strcpy_chk)/x0.s = __strcpy_chk(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fgets)/x0.s = fgets(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(memcpy)/x0.s = memcpy(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(read)/x0.s = read(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(memset)/x0.s = (int64_t) memset((void*)x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(strtol)/x0.s = strtol(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(memcmp)/x0.s = memcmp(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(memmove)/x0.s = memmove(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(strncmp)/x0.s = strncmp(x0.s, x1.s, x2.s); return (pair) {.a = x0, .b = x1}/" "${1}".c

sed -i "s/native_call(getopt_long)/x0.s = getopt_long(x0.s, x1.s, x2.s, x3.s, x4.s); return (pair) {.a = x0, .b = x1}/" "${1}".c

sed -i "s/native_call(open)/x0.s = open(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(open64)/x0.s = open(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(calloc)/x0.s = calloc(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fopen)/x0.s = fopen(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fopen64)/x0.s = fopen(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(realloc)/x0.s = realloc(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(setlocale)/x0.s = setlocale(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(bindtextdomain)/x0.s = bindtextdomain(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(strrchr)/x0.s = strrchr(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fputc)/x0.s = fputc(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(clock_gettime)/x0.s = clock_gettime(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(localtime_r)/x0.s = localtime_r(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(strcmp)/x0.s = strcmp(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(__overflow)/x0.s = __overflow(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(mallopt)/x0.s = mallopt(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(access)/x0.s = access(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(fputs)/x0.s = fputs(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(signal)/x0.s = signal(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutexattr_settype)/x0.s = pthread_mutexattr_settype(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(pthread_mutex_init)/x0.s = pthread_mutex_init(x0.s, x1.s); return (pair) {.a = x0, .b = x1}/" "${1}".c

sed -i "s/native_call(fwrite)/x0.s = fwrite(x0.s, x1.s, x2.s, x3.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(strftime)/x0.s = strftime(x0.s, x1.s, x2.s, x3.s); return (pair) {.a = x0, .b = x1}/" "${1}".c
sed -i "s/native_call(setvbuf)/x0.s = setvbuf(x0.s, x1.s, x2.s, x3.s); return (pair) {.a = x0, .b = x1}/" "${1}".c

sed -i "s/helper_mulsh_i64_aarch64/__mulh/" "${1}".c

sed -i "s/x0.s=x0 = setjmp(x0);/x0.s = setjmp(x0.s);/" "${1}".c
sed -i "s/x0 = longjmp(x0,x1);/longjmp(x0.s, x1.s);/" "${1}".c
sed -i "s/x0.s=x0 = pthread_create(x0,x1,\(.*\),x3);/x0.s = pthread_create(x0.s, x1.s, \1, x3.s);/" "${1}".c
sed -i "s/x0.s=x0 = GOMP_parallel(\(.*\),x1,x2,x3);/x0.s = GOMP_parallel(\1, x1.s, x2.s, x3.s);/" "${1}".c

sed -i "s/=x0 = mambo_lift_mrs_tpidr();/ = mambo_lift_mrs_tpidr();/" "${1}".c
sed -i "s/=x0 = mambo_lift_mrs_dczid();/ = mambo_lift_mrs_dczid();/" "${1}".c

sed -i "s/=x0 = mambo_lift_mrs_fpcr();/ = mambo_lift_mrs_fpcr();/" "${1}".c
sed -i "s/=x0 = mambo_lift_mrs_fpsr();/ = mambo_lift_mrs_fpsr();/" "${1}".c

sed -i "s/=x0 = syscall(x8,x0,x1,x2,x3,x4,x5);/ = syscall(x8.s,x0.s,x1.s,x2.s,x3.s,x4.s,x5.s);/" "${1}".c
sed -i "s/=x0 = mambo_lift_clz64(\(.*\));/ = mambo_lift_clz64(\1\.s);/" "${1}".c
sed -i "s/=x0 = mambo_lift_clz32(\(.*\));/ = mambo_lift_clz64(\1\.s);/" "${1}".c
sed -i "s/=x0 = mambo_lift_rbit(\(.*\));/ = mambo_lift_rbit(\1\.s);/" "${1}".c

sed -i "s/x0 = \(.*\)/ret = \1 x0 = ret.a; x1 = ret.b;/" "${1}".c

sed -i "s/native_call(\(.*\)/x0.s = native_call(x0.s, x1.s, x2.s, x3.s, x4.s, x5.s, x6.s, x7.s, sp.s, env.s, \1 return (pair) {.a = x0, .b = x1};/" "${1}".c

sed -i "s/ret = mambo_lift_dc_zva(\(.*\)); x0 = ret.a; x1 = ret.b;/mambo_lift_dc_zva(\1\.s);/" "${1}".c

sed -i "s/@@GLIBC_2_17_/_/" "${1}".c

# TODO: Should be fixed in the code.
sed -i "s/x31.s/sp.s/" "${1}".c
sed -i "s/__executable_start.s/\&__executable_start/" "${1}".c

cat "${LIFT_ROOT}/runtime/headers" \
    "${LIFT_ROOT}/runtime/helpers.h" \
    "${LIFT_ROOT}/runtime/cpp_symbols.h" \
    "${LIFT_ROOT}/runtime/asm.c" \
    "${1}".c > "${1}"_concat.c
