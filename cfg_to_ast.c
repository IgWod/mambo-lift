/*
  Copyright 2024 Igor Wodiany
  Copyright 2024 The Univesrity of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdio.h>

#include <capstone/capstone.h>

#include "tcg_to_ast.h"

#include "python/python.h"

#include "options.h"

#include "cfg_to_ast.h"

// #define SKIP_DEFAULT_JUMP ///< Do not generate default statements for unexplored branches

// TODO: Clean up
void** tcalls;
void** taddrs;

extern char* gcode;
/*
 * Replace '.' with '_' in the string.
 */
static char* sanitize_name(char* str) {
    int c = 0;
    while (str[c] != '\0') {
        if (str[c] == '.') {
            str[c] = '_';
        }
        c++;
    }

    return str;
}

static ast_function *build_or_return_function(void *addr, ast_translation_unit *translation_unit) {
    ast_function *function = NULL;
    int ret = mambo_ht_get_nolock(translation_unit->function_table, (uintptr_t) addr, (void *) (&function));

    // We do not have to build the function again if it already exists.
    if (!ret) {
        return function;
    }

    char *symbol = NULL;
    get_symbol_info_by_addr(translation_unit->binary, addr, &symbol);

    if (symbol != NULL) {
        sanitize_name(symbol);
    }

    if (addr == translation_unit->main_addr) {
        symbol = "main";
    } else if (symbol == NULL) {
        char *buf = malloc(1024);
        sprintf(buf, "func_%p", addr);
        symbol = buf;
    } else {
        char *buf = malloc(strlen(symbol) + 128);
        sprintf(buf, "%s_%p", symbol, addr);
        symbol = buf;
    }

    function = build_function(symbol);

    function->local_vars = (symbol_table *) malloc(sizeof(symbol_table));

    if(function->local_vars == NULL) {
        fprintf(stderr, "Lift: Cannot allocate symbol table for local vars!\n");
        exit(-1);
    }

    symbol_table_init(function->local_vars, 64);

    mambo_ht_add_nolock(translation_unit->function_table, (uintptr_t) addr, (uintptr_t) function);

    function->number_arguments = 11;
    for(int i = 0; i < 9; i++) {
        char buf[8];
        sprintf(buf, "x%d", i);
        function->arguments[i] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, buf));
    }

    function->arguments[9] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "sp"));
    function->arguments[10] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "env"));

#if MLDEBUG >= 2
    printf("build_or_return_function: created new function %s (starting addr %p)\n", symbol, addr);
#endif

    for(int i = 0; i < translation_unit->num_cb; i++) {
        if(translation_unit->callbacks[i] == (uintptr_t) addr) {
            function->is_callback = 1;
        }
    }

    return function;
}

mambo_ht_t* stack_vars = NULL;

static void build_basic_block(ast_stmt_list* list, cfg_node *node, mambo_ht_t *memory_profiles,
                              ast_function *function, ast_translation_unit *translation_unit) {
    void *current_addr = node->start_addr;
    void *end_addr = node->end_addr;

    ast_stmt *label_stmt = build_label_stmt(current_addr);

    if(is_stmt_list_empty(list)) {
        initialize_stmt_list(list, label_stmt);
    }

    // Block only consists of a branch.
    if (current_addr == end_addr) {
        if (node->type & CFG_RETURN) {
            ast_stmt *return_stmt = build_return_stmt(NULL);
            append_to_stmt_list(list, return_stmt);
        } else if(node->type & CFG_NATIVE_CALL) {
            return;
        }
    }

    uint64_t no_insn = ((uint64_t) end_addr - (uint64_t) current_addr + 4) / 4;

    // TODO: Verify it does not leak memory, but re-initializing temp lists.
    aarch64_generate_tcg_reinit();

    TCGContext *ctx = aarch64_generate_tcg_lift(&gcode[(uintptr_t)current_addr], no_insn);

#if MLDEBUG >= 10
    generate_tcg_print(ctx);
#endif

    translate_tcg_to_ast(ctx, list, function->local_vars, translation_unit->global_vars);

#if 0
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        exit(-1);
    }

    count = cs_disasm(handle, current_addr, (no_insn - 1) * 4, (uint64_t) current_addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("%s\t\t%s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }

    cs_close(&handle);
#endif

    if (node->type & CFG_RETURN) {
        ast_stmt *return_stmt = build_return_stmt(NULL);
        append_to_stmt_list(list, return_stmt);
    }
}

static int build_ast_dfs(ast_stmt_list *list, cfg_node *node, ast_translation_unit *translation_unit, ast_function *function) {
    if (node->visited) {
        initialize_stmt_list(list, NULL);
        return -1;
    }

    ast_stmt_list fret;
    initialize_stmt_list(&fret, NULL);

    node->visited = 1;

#if MLDEBUG >= 2
    printf("build_ast_dfs: build AST from node with address starting at %p (node %p, type %d)\n", node->start_addr, node, node->type);
#endif

    if ((node->type & CFG_FUNCTION_CALL && !(node->type & CFG_INDIRECT_BLOCK)) || node->type & CFG_SVC) {
        void *jump_addr = NULL;
        ast_stmt_list next_block;
        initialize_stmt_list(&next_block, NULL);

        // Function call and SVC always have only one outgoing edge
        cfg_edge *edge = node->edges;
        if (edge != NULL) {
            int ret = build_ast_dfs(&next_block, node->edges->node, translation_unit, function);

            // If we have not built the basic block, we do not need goto, as the next block will follow this one.
            // Otherwise, we need the jump as the next block was already placed somewhere else.
            if (ret) {
                jump_addr = edge->node->start_addr;
            }
        }


        if (node->type & CFG_FUNCTION_CALL) {
            ast_stmt *call_stmt;

            // TODO: Refactor
            if(node->calls->node->type == CFG_NATIVE_CALL && node->calls->node->native_function_name != NULL
               && (strcmp(node->calls->node->native_function_name, "_setjmp") == 0 || strcmp(node->calls->node->native_function_name, "longjmp") == 0
               || strcmp(node->calls->node->native_function_name, "__sigsetjmp") == 0 || strcmp(node->calls->node->native_function_name, "siglongjmp") == 0
                                                                                         || strcmp(node->calls->node->native_function_name, "__longjmp_chk") == 0)) {
                if(strcmp(node->calls->node->native_function_name, "_setjmp") == 0 || strcmp(node->calls->node->native_function_name, "__sigsetjmp") == 0) {
                    ast_function* jmp = build_function("setjmp");
                    jmp->arguments[0] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0"));
                    jmp->number_arguments = 1;
                    fret = node->stmts;
                    call_stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0")),
                                    AST_ASS_OP,
                                    build_call_expr(jmp)));
                } else if(strcmp(node->calls->node->native_function_name, "longjmp") == 0 || strcmp(node->calls->node->native_function_name, "siglongjmp") == 0
                    || strcmp(node->calls->node->native_function_name, "__longjmp_chk") == 0) {
                    ast_function* jmp = build_function("longjmp");
                    jmp->arguments[0] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0"));
                    jmp->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x1"));
                    jmp->number_arguments = 2;
                    fret = node->stmts;
                    call_stmt = build_expr_stmt(
                            build_call_expr(jmp)
                    );
                }
            } else {

                // TODO: Clean up
                if(node->calls->node->native_function_name != NULL && strcmp(node->calls->node->native_function_name, "pthread_create") == 0) {
                    ast_function* create = build_function("pthread_create");
                    create->arguments[0] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0"));
                    create->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x1"));
                    void* taddr = NULL;
                    for(int i = 0; i < 32; i++) {
                        if(tcalls[i] == node->end_addr) {
                            taddr = taddrs[i];
                            break;
                        }
                    }
                    ast_function *callee;
                    mambo_ht_get_nolock(translation_unit->function_table,
                                                  (uintptr_t) taddr, (void *) (&callee));
                    create->arguments[2] = build_string_expr(callee->name);
                    create->arguments[3] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x3"));
                    create->number_arguments = 4;
                    fret = node->stmts;
                    call_stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0")),
                                    AST_ASS_OP,
                                    build_call_expr(create)));
                } else if(node->calls->node->native_function_name != NULL && strcmp(node->calls->node->native_function_name, "GOMP_parallel") == 0) {
                    ast_function* create = build_function("GOMP_parallel");
                    void* taddr = NULL;
                    for(int i = 0; i < 32; i++) {
                        if(tcalls[i] == node->end_addr) {
                            taddr = taddrs[i];
                            break;
                        }
                    }
                    ast_function *callee;
                    mambo_ht_get_nolock(translation_unit->function_table,
                                        (uintptr_t) taddr, (void *) (&callee));
                    create->arguments[0] = build_string_expr(callee->name);
                    create->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x1"));
                    create->arguments[2] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x2"));
                    create->arguments[3] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x3"));
                    create->number_arguments = 4;
                    fret = node->stmts;
                    call_stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0")),
                                    AST_ASS_OP,
                                    build_call_expr(create)));
                } else {
                    ast_function *callee;
                    int ret = mambo_ht_get_nolock(translation_unit->function_table,
                                                  (uintptr_t) node->calls->node->start_addr, (void *) (&callee));

                    if (ret) {
                        fprintf(stderr, "MAMBO Lift: Could not retrieve function at %p!\n", node->calls->node->start_addr);
                        callee = build_function("assert");
                        callee->arguments[0] = build_int64_expr(0);
                        callee->number_arguments = 1;
                    }

                    /* If everything is as expected generate the function call. */
                    fret = node->stmts;

                    call_stmt = build_expr_stmt(
                            build_call_expr(callee)
                    );
                }
            }

            append_to_stmt_list(&fret, call_stmt);
        } else {
            // x0.s = syscall(x8.s, x0.s, x1.s, x2.s, x3.s, x4.s, x5.s);
            char *func_name = "syscall";

            ast_function *external_function = build_function(func_name);

            external_function->arguments[0] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x8"));
            external_function->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0"));
            external_function->arguments[2] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x1"));
            external_function->arguments[3] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x2"));
            external_function->arguments[4] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x3"));
            external_function->arguments[5] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x4"));
            external_function->arguments[6] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x5"));

            external_function->number_arguments = 7;

            ast_stmt *external_function_call = build_expr_stmt(
                    build_binary_expr(
                            build_var_expr(symbol_table_lookup(translation_unit->global_vars, "x0")),
                            AST_ASS_OP,
                            build_call_expr(external_function)
                    )
            );

            fret = node->stmts;
            append_to_stmt_list(&fret, external_function_call);
        }

        // It's either jump statement or next block (or neither), but never both
        if (jump_addr != NULL) {
            append_to_stmt_list(&fret, build_conditional_goto_stmt(NULL, jump_addr, NULL));
        }

        // We shouldn't add return on the terminator path
        if (edge == NULL) {
            append_to_stmt_list(&fret, build_return_stmt(NULL));

            if (strcmp(function->name, "main") == 0) {
                ast_decl *decl = (ast_decl *) symbol_table_lookup(translation_unit->global_vars, "x0");
                fret.tail->return_stmt.ret = build_var_expr(decl);
            }

        }

        if (!is_stmt_list_empty(&next_block)) {
            concatenate_stmt_lists(&fret, &next_block);
        }

        list->head = fret.head;
        list->tail = fret.tail;
    } else if (node->type & CFG_CONDITIONAL_BLOCK) {

        cfg_node *taken = NULL;
        cfg_node *skipped = NULL;

        void *taken_addr = NULL;
        void *skipped_addr = NULL;

        cfg_edge *edge = node->edges;

        if (edge == NULL) {
            ast_stmt *goto_stmt = build_conditional_goto_stmt(NULL, NULL, NULL);
            fret = node->stmts;
            append_to_stmt_list(&fret, goto_stmt);
            list->head = fret.head;
            list->tail = fret.tail;
            return 0;
        }

        if (edge->type == CFG_TAKEN_BRANCH) {
            taken = edge->node;
            taken_addr = edge->node->start_addr;
        } else {
            skipped = edge->node;
            skipped_addr = edge->node->start_addr;
        }

        if (edge->next != NULL) {
            skipped = edge->next->node;
            skipped_addr = edge->next->node->start_addr;
        }

        void *taken_goto = NULL;
#ifdef SKIP_DEFAULT_JUMP
        if (taken != NULL && (skipped != NULL || taken->visited)) {
#else
        if (taken != NULL) {
#endif
            taken_goto = taken_addr;
        }

        void *skipped_goto = NULL;
#ifdef SKIP_DEFAULT_JUMP
        if (skipped != NULL && (taken != NULL || skipped->visited)) {
#else
        if (skipped != NULL) {
#endif
            skipped_goto = skipped_addr;
        }

        fret = node->stmts;

        ast_expr *cond = build_var_expr(get_or_create_branch_cond(function->local_vars));

        if (!options.cmp_opts) {
            goto skip;
        }
// #if 0
        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
            exit(-1);
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        for(uint64_t i = (uint64_t) node->end_addr; i >= (uint64_t) node->start_addr; i -= 4) {
            insn = NULL;
            count = 0;
            count = cs_disasm(handle, (void*) i, 4, i, 0, &insn);

            if(count != 0) {
                cs_insn *in = &(insn[0]);
                cs_detail *detail = in->detail;
                if (insn[0].id == ARM64_INS_CMP || insn[0].id == ARM64_INS_CMN || insn[0].id == ARM64_INS_TST) {
                    bool neg = 0;
                    if(insn[0].id == ARM64_INS_CMN) {
                        neg = 1;
                    }
                    bool tst = 0;
                    if(insn[0].id == ARM64_INS_TST) {
                        tst = 1;
                    }
                    cs_arm64_op op1 = detail->arm64.operands[0];
                    cs_arm64_op op2 = detail->arm64.operands[1];
                    if(op2.ext != 0) {
                        break; // TODO: Add non implemented shifts
                    }
                    count = cs_disasm(handle, node->end_addr, 4, (uint64_t) node->end_addr, 0, &insn);
                    cs_insn *in = &(insn[0]);
                    cs_detail *detail = in->detail;
                    if (insn[0].id == ARM64_INS_B) {
                        if(detail->arm64.cc - 1 == AST_PL_OP || detail->arm64.cc - 1 == AST_MI_OP
                        || detail->arm64.cc - 1 == AST_VC_OP || detail->arm64.cc - 1 == AST_VS_OP
                        || detail->arm64.cc - 1 == AST_AL_OP || detail->arm64.cc - 1 == AST_ALT_OP) {
                            break;
                        }
                        char* str1 = strdup(cs_reg_name(handle, op1.reg));
                        bool cast1 = 0;
                        if(str1[0] == 'w') {
                            cast1 = 1;
                        }
                        str1[0] = 'x';
                        ast_expr* rhs = NULL;
                        if(op2.type == ARM64_OP_REG) {
                            char *str2 = strdup(cs_reg_name(handle, op2.reg));
                            bool cast2 = 0;
                            if(str2[0] == 'w') {
                                cast2 = 1;
                            }
                            str2[0] = 'x';
                            rhs = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "rhs"));
                            if(cast2) {
                                if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                                   || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                    rhs = build_cast_expr(rhs, AST_CAST_TO_UINT32);
                                } else {
                                    rhs = build_cast_expr(rhs, AST_CAST_TO_INT32);
                                }
                            } else {
                                if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                                   || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                    rhs = build_cast_expr(rhs, AST_CAST_TO_UINT64);
                                }
                            }
                            if(op2.shift.type == ARM64_SFT_LSL) {
                                rhs = build_binary_expr(rhs, AST_LSL_OP, build_int32_expr(op2.shift.value));
                            }
                            if(op2.shift.type == ARM64_SFT_ASR) {
                                rhs = build_binary_expr(rhs, AST_ASR_OP, build_int32_expr(op2.shift.value));
                            }
                            if(op2.shift.type == ARM64_SFT_LSR) {
                                rhs = build_binary_expr(rhs, AST_LSR_OP, build_int32_expr(op2.shift.value));
                            }
                            free(str2);
                        } else {
                            rhs = build_int64_expr(op2.imm);
                            if(op2.shift.type == ARM64_SFT_LSL) {
                                rhs = build_binary_expr(rhs, AST_LSL_OP, build_int32_expr(op2.shift.value));
                            }
                        }
                        ast_expr* lhs = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "lhs"));
                        if(cast1) {
                            if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                            || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                lhs = build_cast_expr(lhs, AST_CAST_TO_UINT32);
                            } else {
                                lhs = build_cast_expr(lhs, AST_CAST_TO_INT32);
                            }
                        } else {
                            if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                               || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                lhs = build_cast_expr(lhs, AST_CAST_TO_UINT64);
                            }
                        }
                        if(op2.type != ARM64_OP_REG && cast1) {
                            rhs = build_int32_expr(op2.imm);
                            if(op2.shift.type == ARM64_SFT_LSL) {
                                rhs = build_binary_expr(rhs, AST_LSL_OP, build_int32_expr(op2.shift.value));
                            }
                        }
                        if(neg) {
                            rhs = build_unary_expr(AST_SUB_OP, rhs);
                        }
                        if(tst) {
                            cond = build_binary_expr(
                                    build_binary_expr(
                                            lhs,
                                            AST_AND_OP,
                                            rhs
                                    ),
                                    detail->arm64.cc - 1,
                                    build_int64_expr(0)
                            );
                        } else {
                            cond = build_binary_expr(
                                    lhs,
                                    detail->arm64.cc - 1,
                                    rhs
                            );
                        }
                        free(str1);
                    }
                    break;
                } else if(insn[0].id == ARM64_INS_CBZ || insn[0].id == ARM64_INS_CBNZ) {
                    cs_arm64_op op1 = detail->arm64.operands[0];
                    char *str1 = strdup(cs_reg_name(handle, op1.reg));
                    bool cast1 = 0;
                    if(str1[0] == 'w') {
                        cast1 = 1;
                    }
                    str1[0] = 'x';
                    if(strcmp(str1, "x30") == 0) {
                        str1 = "lr";
                    }
                    ast_expr* lhs = build_var_expr(symbol_table_lookup(translation_unit->global_vars, str1));
                    if(cast1) {
                        lhs = build_cast_expr(lhs, AST_CAST_TO_INT32);
                    }
                    cond = build_binary_expr(
                            lhs,
                            (insn[0].id == ARM64_INS_CBZ) ? AST_EQ_OP : AST_NE_OP,
                            build_int64_expr(0)
                    );
                    if(strcmp(str1, "lr") != 0) {
                        free(str1);
                    }
                    break;
                } else if(insn[0].id == ARM64_INS_TBZ || insn[0].id == ARM64_INS_TBNZ) {
                    // Already fairly optimal
                    break;
                } else if((insn[0].id == ARM64_INS_ADD || insn[0].id == ARM64_INS_SUB || insn[0].id == ARM64_INS_AND) && detail->arm64.update_flags) {
                    bool neg = 0;
                    if(insn[0].id == ARM64_INS_ADD) {
                        neg = 1;
                    }
                    bool tst = 0;
                    if(insn[0].id == ARM64_INS_AND) {
                        tst = 1;
                    }
                    cs_arm64_op op1 = detail->arm64.operands[1];
                    cs_arm64_op op2 = detail->arm64.operands[2];
                    if(op2.ext != 0) {
                        break; // TODO: Add non implemented shifts
                    }
                    count = cs_disasm(handle, node->end_addr, 4, (uint64_t) node->end_addr, 0, &insn);
                    cs_insn *in = &(insn[0]);
                    cs_detail *detail = in->detail;
                    if (insn[0].id == ARM64_INS_B) {
                        if(detail->arm64.cc - 1 == AST_PL_OP || detail->arm64.cc - 1 == AST_MI_OP
                           || detail->arm64.cc - 1 == AST_VC_OP || detail->arm64.cc - 1 == AST_VS_OP
                           || detail->arm64.cc - 1 == AST_AL_OP || detail->arm64.cc - 1 == AST_ALT_OP) {
                            break;
                        }
                        if(neg && detail->arm64.cc - 1 == AST_CC_OP) {
                            break;
                        }
                        char* str1 = strdup(cs_reg_name(handle, op1.reg));
                        bool cast1 = 0;
                        if(str1[0] == 'w') {
                            cast1 = 1;
                        }
                        str1[0] = 'x';
                        ast_expr* rhs = NULL;
                        if(op2.type == ARM64_OP_REG) {
                            char *str2 = strdup(cs_reg_name(handle, op2.reg));
                            bool cast2 = 0;
                            if(str2[0] == 'w') {
                                cast2 = 1;
                            }
                            str2[0] = 'x';
                            rhs = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "rhs"));
                            if(op2.shift.type == ARM64_SFT_LSL) {
                                rhs = build_binary_expr(rhs, AST_LSL_OP, build_int32_expr(op2.shift.value));
                            }
                            if(op2.shift.type == ARM64_SFT_ASR) {
                                rhs = build_binary_expr(rhs, AST_ASR_OP, build_int32_expr(op2.shift.value));
                            }
                            if(cast2) {
                                if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                                   || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                    rhs = build_cast_expr(rhs, AST_CAST_TO_UINT32);
                                } else {
                                    rhs = build_cast_expr(rhs, AST_CAST_TO_INT32);
                                }
                            } else {
                                if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                                   || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                    rhs = build_cast_expr(rhs, AST_CAST_TO_UINT64);
                                }
                            }
                            free(str2);
                        } else {
                            rhs = build_int64_expr(op2.imm);
                        }
                        ast_expr* lhs = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "lhs"));
                        if(cast1) {
                            if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                               || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                lhs = build_cast_expr(lhs, AST_CAST_TO_UINT32);
                            } else {
                                lhs = build_cast_expr(lhs, AST_CAST_TO_INT32);
                            }
                        } else {
                            if(detail->arm64.cc - 1 == AST_LS_OP || detail->arm64.cc - 1 == AST_HI_OP
                               || detail->arm64.cc - 1 == AST_CS_OP || detail->arm64.cc - 1 == AST_CC_OP) {
                                lhs = build_cast_expr(lhs, AST_CAST_TO_UINT64);
                            }
                        }
                        if(neg) {
                            lhs = build_unary_expr(AST_SUB_OP, lhs);
                        }
                        if(tst) {
                            cond = build_binary_expr(
                                    build_binary_expr(
                                            lhs,
                                            AST_AND_OP,
                                            rhs
                                    ),
                                    detail->arm64.cc - 1,
                                    build_int64_expr(0)
                            );
                        } else {
                            cond = build_binary_expr(
                                    lhs,
                                    detail->arm64.cc - 1,
                                    rhs
                            );
                        }
                        free(str1);
                    }
                    break;
                } else if((insn[0].id == ARM64_INS_BIC) && detail->arm64.update_flags) {
                    break;
                } else if(insn[0].id == ARM64_INS_CCMP || insn[0].id == ARM64_INS_CCMN) {
                    break;
                } else if((insn[0].id == ARM64_INS_FCMP || insn[0].id == ARM64_INS_FCCMP)) {
                    break;
                }
            }

            cs_free(insn, count);
        }

        cs_close(&handle);
//#endif
skip:
        ;
        ast_stmt *goto_stmt = NULL;
        if (taken_goto != NULL && skipped_goto != NULL) {
            goto_stmt = build_conditional_goto_stmt(
                    cond,
                    taken_goto,
                    skipped_goto
            );
        } else if (skipped_goto == NULL && taken_goto != NULL) {
            goto_stmt = build_conditional_goto_stmt(
                    cond,
                    taken_goto,
                    NULL
            );
        } else if (skipped_goto != NULL && taken_goto == NULL) {
            cond = build_unary_expr(AST_LNG_OP, cond);
            goto_stmt = build_conditional_goto_stmt(
                    cond,
                    skipped_goto,
                    NULL
            );
        }

        if (goto_stmt != NULL) {
            append_to_stmt_list(&fret, goto_stmt);
        }

        ast_stmt_list skipped_next_stmt;
        initialize_stmt_list(&skipped_next_stmt, NULL);

        ast_stmt_list taken_next_stmt;
        initialize_stmt_list(&taken_next_stmt, NULL);

        if (skipped != NULL) {
            build_ast_dfs(&skipped_next_stmt, skipped, translation_unit, function);
        }

        if (taken != NULL) {
            build_ast_dfs(&taken_next_stmt, taken, translation_unit, function);
        }

        if (!is_stmt_list_empty(&skipped_next_stmt)) {
            concatenate_stmt_lists(&fret, &skipped_next_stmt);

            if (!is_stmt_list_empty(&taken_next_stmt)) {
                concatenate_stmt_lists(&fret, &taken_next_stmt);
            }
        } else {
            if (!is_stmt_list_empty(&taken_next_stmt)) {
                concatenate_stmt_lists(&fret, &taken_next_stmt);
            }
        }

        // TODO: Optimize jumps to empty basic blocks (basic blocks with the branch only).
        list->head = fret.head;
        list->tail = fret.tail;
    } else if (node->type == CFG_BASIC_BLOCK || node->type == CFG_RETURN) {
        ast_stmt_list post_current_block;
        initialize_stmt_list(&post_current_block, NULL);

        cfg_edge *edge = node->edges;

        if (node->type & CFG_RETURN) {
            edge = NULL;
        }

        if (edge != NULL) {
            ast_stmt_list next_block;
            build_ast_dfs(&next_block, node->edges->node, translation_unit, function);

            // If we have not built the basic block we do not need goto, as the next block will follow this one.
            // Otherwise, we need the jump as the next block was already placed somewhere else.
            if (is_stmt_list_empty(&next_block)) {
                ast_stmt *goto_stmt = build_conditional_goto_stmt(NULL, edge->node->start_addr, NULL);

                initialize_stmt_list(&post_current_block, goto_stmt);
            } else {
                post_current_block = next_block;
            }
        }

        fret = node->stmts;

        if (node->type & CFG_RETURN && strcmp(function->name, "main") == 0) {
            ast_decl *decl = (ast_decl *) symbol_table_lookup(translation_unit->global_vars, "x0");
            node->stmts.tail->return_stmt.ret = build_var_expr(decl);
        }

        if (!is_stmt_list_empty(&post_current_block)) {
            concatenate_stmt_lists(&fret, &post_current_block);
        }

        list->head = fret.head;
        list->tail = fret.tail;
    } else if (node->type & CFG_INDIRECT_BLOCK) {
        char buf[4];
        sprintf(buf, "x%d", node->branch_reg);
        ast_decl *decl = (ast_decl *) symbol_table_lookup(translation_unit->global_vars, buf);
        if (decl == NULL) {
            decl = build_var_decl(strdup(buf), AST_VAR_INT64);
            symbol_table_check_insert(translation_unit->global_vars, buf, (void *) decl);
            decl->var_decl.scope = AST_VAR_REG_GLOBAL;
        }

        ast_stmt *goto_stmt = build_indirect_goto_stmt(
                build_var_expr(
                        decl
                )
        );
        goto_stmt->indirect_goto_stmt.jumps = malloc(256 * sizeof(void*));

        fret = node->stmts;
        append_to_stmt_list(&fret, goto_stmt);

        if (node->type & CFG_FUNCTION_CALL) {
            // TODO: Refactor
            if(node->calls->node == NULL) {
                ast_function *callee;

                callee = build_function("assert");
                callee->arguments[0] = build_int64_expr(0);
                callee->number_arguments = 1;

                /* If everything is as expected generate the function call. */
                fret = node->stmts;

                ast_stmt* call_stmt = build_expr_stmt(
                        build_call_expr(callee)
                );

                append_to_stmt_list(&fret, call_stmt);

                list->head = fret.head;
                list->tail = fret.tail;

                return 0;
            } else if(node->calls->node->type == CFG_NATIVE_CALL && node->calls->node->native_function_name == NULL) {
                ast_function *external_function = build_function("native_call");
                external_function->arguments[0] = build_var_expr(decl);
                external_function->number_arguments = 1;
                goto_stmt->type = AST_EXPR_STMT;
                goto_stmt->expr_stmt = build_call_expr(external_function);
                if (node->edges != NULL) {
                    ast_stmt_list next_block;
                    build_ast_dfs(&next_block, node->edges->node, translation_unit, function);

                    // If we have not built the basic block we do not need goto, as the next block will follow this one.
                    // Otherwise, we need the jump as the next block was already placed somewhere else.
                    if (is_stmt_list_empty(&next_block)) {
                        ast_stmt *goto_stmt = build_conditional_goto_stmt(NULL, node->edges->node->start_addr, NULL);
                        append_to_stmt_list(&fret, goto_stmt);
                    } else {
                        concatenate_stmt_lists(&fret, &next_block);
                    }
                } else {
                    append_to_stmt_list(&fret, build_return_stmt(NULL));
                }

                list->head = fret.head;
                list->tail = fret.tail;

                return 0;
            } else {
                goto_stmt->indirect_goto_stmt.is_call = true;
                cfg_edge *edge = node->calls;
                while (edge != NULL && edge->node != NULL) {
                    goto_stmt->indirect_goto_stmt.jumps[goto_stmt->indirect_goto_stmt.number_jumps++] = edge->node->start_addr;

                    /*if (goto_stmt->indirect_goto_stmt.number_jumps >= MAX_INDIRECT_JUMPS) {
                        fprintf(stderr, "MAMBO Lift: Reached maximum number of jumps for indirect goto statement!\n");
                        exit(-1);
                    }*/
                    // TODO: Somehow track if allocation is full and increase the array.

                    edge = edge->next;
                }

                if (node->edges != NULL) {
                    ast_stmt_list next_block;
                    build_ast_dfs(&next_block, node->edges->node, translation_unit, function);

                    // If we have not built the basic block we do not need goto, as the next block will follow this one.
                    // Otherwise, we need the jump as the next block was already placed somewhere else.
                    if (is_stmt_list_empty(&next_block)) {
                        ast_stmt *goto_stmt = build_conditional_goto_stmt(NULL, node->edges->node->start_addr, NULL);
                        append_to_stmt_list(&fret, goto_stmt);
                    } else {
                        concatenate_stmt_lists(&fret, &next_block);
                    }
                } else {
                    append_to_stmt_list(&fret, build_return_stmt(NULL));
                }
            }
        } else {
            cfg_edge *edge = node->edges;
            while (edge != NULL && edge->node != NULL) {
                ast_stmt_list next_block;
                int ret = build_ast_dfs(&next_block, edge->node, translation_unit, function);

                if (!ret) {
                    concatenate_stmt_lists(&fret, &next_block);
                }

                goto_stmt->indirect_goto_stmt.jumps[goto_stmt->indirect_goto_stmt.number_jumps++] = edge->node->start_addr;

                /*if (goto_stmt->indirect_goto_stmt.number_jumps >= MAX_INDIRECT_JUMPS) {
                    fprintf(stderr, "MAMBO Lift: Reached maximum number of jumps for indirect goto statement!\n");
                    exit(-1);
                }*/
                // TODO: Somehow track if allocation is full and increase the array.


                edge = edge->next;
            }
        }

        for (int i = 0; i < goto_stmt->indirect_goto_stmt.number_jumps; i++) {
            char *object;
            int64_t base;
            // get_mapping(getpid(), (int64_t) goto_stmt->indirect_goto_stmt.jumps[0], &base, &object);

            char buf[64];
            sprintf(buf, "gv_%lx", base);

            ast_decl *decl = (ast_decl *) symbol_table_lookup(translation_unit->global_vars, buf);

            if (decl == NULL) {
                char *symbol = strdup(buf);

                decl = build_var_decl(symbol, AST_VAR_INT64);

                symbol_table_check_insert(translation_unit->global_vars, symbol, (void *) decl);

                decl->var_decl.scope = AST_VAR_MAP;
                decl->var_decl.object = object;
            }
        }

        list->head = fret.head;
        list->tail = fret.tail;
    } else if(node->type & CFG_NATIVE_CALL) {
        fret = node->stmts;

        ast_function *external_function = build_function("native_call");

        ast_stmt *external_function_call = NULL;

        if(strcmp(node->native_function_name, "__isoc99_sscanf") == 0) {
            external_function->arguments[0] = build_string_expr("sscanf");
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } else if(strcmp(node->native_function_name, "__isoc99_scanf") == 0) {
            external_function->arguments[0] = build_string_expr("scanf");
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } else if(strcmp(node->native_function_name, "__isoc99_fscanf") == 0) {
            external_function->arguments[0] = build_string_expr("fscanf");
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } else if(strcmp(node->native_function_name, "__xpg_strerror_r") == 0) {
            external_function->arguments[0] = build_string_expr("strerror_r");
            external_function->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "state"));
            external_function->number_arguments = 2;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        /* } else if(strcmp(node->native_function_name, "__cxa_atexit") == 0) {
            external_function->arguments[0] = build_string_expr("atexit");
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            ); */
        } else if(strcmp(node->native_function_name, "__strtoul_internal") == 0) {
            external_function->arguments[0] = build_string_expr("strtoul");
            external_function->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "state"));
            external_function->number_arguments = 2;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } else if(strcmp(node->native_function_name, "__strtol_internal") == 0) {
            external_function->arguments[0] = build_string_expr("strtol");
            external_function->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "state"));
            external_function->number_arguments = 2;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } else if(strcmp(node->native_function_name, "__asprintf_chk") == 0) {
            external_function->arguments[0] = build_string_expr("__asprintf_chk");
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } else if(strcmp(node->native_function_name, "__vasprintf_chk") == 0) {
            external_function->arguments[0] = build_string_expr("__vasprintf_chk");
            //external_function->arguments[1] = build_var_expr(symbol_table_lookup(translation_unit->global_vars, "state"));
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        } /*else if(strstr(node->native_function_name, "_chk") != 0) {
            char buf[128];
            sprintf(buf, "__builtin_%s", node->native_function_name);
            external_function->arguments[0] = build_string_expr(strdup(buf));
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        }*/ else {
            external_function->arguments[0] = build_string_expr(node->native_function_name);
            external_function->number_arguments = 1;
            external_function_call = build_expr_stmt(
                    build_call_expr(external_function)
            );
        }

        append_to_stmt_list(&fret, external_function_call);

        if(!node->linked) {
            append_to_stmt_list(&fret, build_return_stmt(NULL));

            if (strcmp(function->name, "main") == 0) {
                ast_decl *decl = (ast_decl *) symbol_table_lookup(translation_unit->global_vars, "x0");
                fret.tail->return_stmt.ret = build_var_expr(decl);
            }
        }

        list->head = fret.head;
        list->tail = fret.tail;
    }else {
        fprintf(stderr, "Lift: CFG node type %d not implemented in build_ast_dfs!\n", node->type);
        exit(-1);
    }

    return 0;
}

void build_full_ast(cfg_node_linked_list *functions, ast_translation_unit *translation_unit) {
    cfg_node_linked_list *functions_iter = functions;
    while (functions_iter != NULL) {
        ast_function* function = build_or_return_function(functions_iter->node->start_addr, translation_unit);

        if(function != NULL) {
#if MLDEBUG >= 1
            printf("build_full_ast: Building function %s\n", function->name);
#endif
            ast_stmt_list next_block;
            build_ast_dfs(&next_block, functions_iter->node, translation_unit, function);
            function->body = next_block.head;
        }

        functions_iter = functions_iter->next;
    }
}

void build_basic_blocks(cfg_node** nodes, uint64_t count, ast_translation_unit *translation_unit, mambo_ht_t *memory_profiles) {
    ast_function* function = build_or_return_function(nodes[0]->start_addr, translation_unit);

    if(stack_vars == NULL) {
        stack_vars = (mambo_ht_t *) malloc(sizeof(mambo_ht_t));
        mambo_ht_init(stack_vars, 1024, 0, 80, true);
    }

    if(function != NULL) {
#if MLDEBUG >= 1
        printf("build_basic_blocks: Building basic blocks function %s\n", function->name);
#endif
        function->index = nodes[0]->order_id; // TODO: Careful about it

        for(int index = 0; index < count; index++) {
            initialize_stmt_list(&nodes[index]->stmts, NULL);

            build_basic_block(&nodes[index]->stmts, nodes[index], memory_profiles, function, translation_unit);
        }

        function->body = NULL;
        function->number_basic_blocks = count;
        function->basic_blocks = nodes;
    }
}
