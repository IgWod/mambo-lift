CSOURCES+=ast/ast.c ast/ast_list.c ast/ast_utils.c ast/symbol_table.c ast/ast_optimizer.c
CSOURCES+=cfg/cfg.c cfg/cfg_preprocessor.c cfg/cfg_print.c cfg/cfg_utils.c
CSOURCES+=utils/hashmap_utils.c utils/print_utils.c
CSOURCES+=lift.c options.c
CSOURCES+=ast_to_code.c cfg_to_ast.c tcg_to_ast.c
CSOURCES+=hash_table.c

PYSOURCES=python/python.c
PYINCLUDE=$(shell pkg-config --cflags python3-embed)
PYLIBS=$(shell pkg-config --libs python3-embed)

CFLAGS+=-D_GNU_SOURCE -g -std=gnu99 -O2 -Wunused-variable

LDFLAGS+=-ldl

LIBS=-lelf -lz -L$(UNICORN_ROOT)/build -lunishare -lpthread -lm -lcapstone

INCLUDES=-I. -Iinclude/
INCLUDES+=-I$(UNICORN_ROOT)/include -I$(UNICORN_ROOT)/qemu/include -I$(UNICORN_ROOT)/qemu/target/arm -I$(UNICORN_ROOT)/build -I$(UNICORN_ROOT)/glib_compat -I$(UNICORN_ROOT)/build/aarch64-softmmu/ -I$(UNICORN_ROOT)/qemu/tcg/aarch64 -I$(UNICORN_ROOT)/qemu -DNEED_CPU_H

PIE += pie/pie-a64-field-decoder.o pie/pie-a64-encoder.o pie/pie-a64-decoder.o

.PHONY: clean cleanall

all:
	$(MAKE) -C pie/
	$(CC) $(CFLAGS) $(CSOURCES) $(LDFLAGS) $(INCLUDES) -o lifter $(PYSOURCES) $(PYINCLUDE) $(PIE) $(LIBS) $(PYLIBS)

clean:
	rm -f lifter

cleanall: clean
	$(MAKE) -C pie/ clean
