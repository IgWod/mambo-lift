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

#include "pie/pie-a64-field-decoder.h"

#include "options.h"

#include "tcg_to_ast.h"

extern char* gcode;

// PRIVATE STRUCTS

static inline uint64_t sign_extend64(unsigned int bits, uint64_t value)
{
    uint64_t C = (-1) << (bits - (uint64_t) 1);
    return (value + C) ^ C;
}

/*
 * Struct represents data stored in the TCG context helper table.
 */
typedef struct tcg_helper_metadata {
    void *func;
    const char *name;
    unsigned flags;
    unsigned size_mask;
} tcg_helper_metadata;

#pragma clang diagnostic pop

// TCG HELPERS

/*
 * Get name of the helper function called from TCG.
 */
static char *tcg_helper_lookup(TCGContext *ctx, TCGArg arg) {
    const char *ret = NULL;

    if (ctx->helper_table) {
        tcg_helper_metadata *info = g_hash_table_lookup(ctx->helper_table, (gpointer) arg);
        if (info) {
            ret = info->name;
        }
    }

    return (char *) ret;
}

/*
 * Get name of the TCG variable. For global variables the name is stored in the variable itself, but for locals and
 * temps we build the name using the position of the variable in the temps array.
 */
static char *get_temp_name(TCGContext *ctx, TCGTemp *temp) {
    ptrdiff_t idx = temp - ctx->temps;

    // With 32 character we can represent numbers up to 26 digits - this should be more than enough to cover any
    // sane number of temporary variables.
    char buffer[32];

    // TCG reuses temps names between basic blocks for vars of different size. To avoid scoping variables with basic
    // block granularity we add size to the var name, so each var name has a unique non-changing type.
    char* size = NULL;
    if(temp->type == TCG_TYPE_I32) {
        size = "i32";
    } else if(temp->type == TCG_TYPE_I64) {
        size = "i64";
    } else if(temp->type == TCG_TYPE_V64) {
        size = "v64";
    } else if(temp->type == TCG_TYPE_V128) {
        size = "v128";
    } else {
        fprintf(stderr, "Size not supported!\n");
        exit(-1);
    }

    if (temp->temp_global) {
        return strdup(temp->name);
    } else if (temp->temp_local) {
        snprintf(buffer, 32, "loc%ld_%s", idx - ctx->nb_globals, size);
    } else {
        snprintf(buffer, 32, "tmp%ld_%s", idx - ctx->nb_globals, size);
    }

    return strdup(buffer);
}

// AST HELPERS

// TODO: Using switch is not the most optimal. Explore matching values of TCGType and ast_var_type.
static ast_var_type tcg_to_ast_type(TCGType type) {
    switch(type) {
        case TCG_TYPE_I32:
            return AST_VAR_INT32;
        case TCG_TYPE_I64:
            return AST_VAR_INT64;
        case TCG_TYPE_V64:
            return AST_VAR_VEC64;
        case TCG_TYPE_V128:
            return AST_VAR_VEC128;
        case TCG_TYPE_V256:
        default:
            fprintf(stderr, "tcg_to_ast_type: Type %d no supported\n!", type);
            exit(-1);
    }
}

// TODO: Using switch is not the most optimal. Explore matching values of TCGCond and ast_op.
static ast_op tcg_to_ast_cond(TCGCond cond) {
    switch(cond) {
        case TCG_COND_EQ:
            return AST_EQ_OP;
        case TCG_COND_NE:
            return AST_NE_OP;
        case TCG_COND_LT:
            return AST_LT_OP;
        case TCG_COND_GE:
            return AST_GE_OP;
        case TCG_COND_LE:
            return AST_LE_OP;
        case TCG_COND_GT:
            return AST_GT_OP;
        case TCG_COND_LTU:
            return AST_CC_OP;
        case TCG_COND_GEU:
            return AST_CS_OP;
        case TCG_COND_LEU:
            return AST_LS_OP;
        case TCG_COND_GTU:
            return AST_HI_OP;
        case TCG_COND_NEVER:
        case TCG_COND_ALWAYS:
        default:
            fprintf(stderr, "tcg_to_ast_cond: Cond %d no supported!\n", cond);
            exit(-1);
    }
}

/*
 * Get local or global variable from the symbol table. If the variable does not exist a new entry in the symbol
 * table is created.
 */
static ast_decl *get_or_create_var(TCGContext *ctx, symbol_table *globals_vars, symbol_table *local_vars,
                                   TCGTemp *temp) {
    char *name = get_temp_name(ctx, temp);

    symbol_table *vars;
    if (temp->temp_global) {
        vars = globals_vars;
    } else {
        vars = local_vars;
    }

    ast_decl *decl = (ast_decl *) symbol_table_lookup(vars, name);

    if (decl == NULL) {
        decl = build_var_decl(name, AST_VAR_NOTYPE);

        symbol_table_check_insert(vars, name, (void *) decl);

        if (temp->temp_global) {
            decl->var_decl.scope = AST_VAR_REG_GLOBAL;
        } else {
            decl->var_decl.scope = AST_VAR_TEMP_LOCAL;
        }

        decl->var_decl.type = tcg_to_ast_type(temp->type);
    }

    assert(decl->var_decl.type == tcg_to_ast_type(temp->type));

    return decl;
}

static ast_expr *build_var(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, TCGArg arg, ast_var_type dest_type) {
    ast_decl *decl = get_or_create_var(ctx, global_vars, local_vars, (TCGTemp *) arg);

    if (dest_type == AST_VAR_INT32 && decl->var_decl.type == AST_VAR_INT64) {
        return build_cast_expr(
                build_var_expr(
                        decl
                ),
                AST_CAST_TO_INT32
        );
    } else {
        return build_var_expr(
                decl
        );
    }
}

static ast_expr * build_ternary_expr_3vars(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, ast_op lop, ast_op rop,
                         TCGArg *args, ast_var_type dest_type) {
    return build_binary_expr(
            build_var(ctx, global_vars, local_vars, args[0], dest_type),
            lop,
            build_binary_expr(
                    build_var(ctx, global_vars, local_vars, args[1], dest_type),
                    rop,
                    build_var(ctx, global_vars, local_vars, args[2], dest_type)
            )
    );
}

static ast_expr *build_binary_expr_2vars(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, ast_op op, TCGArg *args,
                        ast_var_type dest_type) {
    return build_binary_expr(
            build_var(ctx, global_vars, local_vars, args[0], dest_type),
                    op,
                    build_var(ctx, global_vars, local_vars, args[1], dest_type)
            );
}

static ast_expr *build_binary_expr_2vars_neg(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, ast_op op, TCGArg *args,
                        ast_var_type dest_type) {
    return build_binary_expr(
            build_var(ctx, global_vars, local_vars, args[0], dest_type),
            op,
            build_unary_expr(
                    AST_SUB_OP,
                    build_var(ctx, global_vars, local_vars, args[1], dest_type)
            )
    );
}

static ast_expr *build_binary_expr_2vars_not(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, ast_op op, TCGArg *args,
                            ast_var_type dest_type) {
    return build_binary_expr(
            build_var(ctx, global_vars, local_vars, args[0], dest_type),
            op,
            build_unary_expr(
                    AST_NOT_OP,
                    build_var(ctx, global_vars, local_vars, args[1], dest_type)
            )
    );
}

static ast_expr *build_binary_expr_var_imm(TCGContext *ctx, symbol_table *global_vars, symbol_table *locals_vars, ast_op op,
                          TCGArg *args, ast_expr *imm, ast_var_type dest_type) {
    return build_binary_expr(
            build_var(ctx, global_vars, locals_vars, args[0], dest_type),
            op,
            imm
    );
}

static ast_expr *build_cmp(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, TCGArg *args, TCGArg cond, ast_var_type dest_type) {
    return build_binary_expr(
            build_var(ctx, global_vars, local_vars, args[0], dest_type),
            tcg_to_ast_cond(cond),
            build_var(ctx, global_vars, local_vars, args[1], dest_type)
    );
}

static ast_expr *build_ext(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, TCGArg *args, ast_var_type dest_type,
          ast_cast_type cast, ast_cast_type dest_cast) {
    return build_binary_expr(
            build_var(ctx, global_vars, local_vars, args[0], dest_type),
            AST_ASS_OP,
            build_cast_expr(
                    build_cast_expr(
                            build_var(ctx, global_vars, local_vars, args[1], dest_type),
                            cast
                    ),
                    dest_cast
            )
    );
}

static ast_expr *build_memory(TCGContext *ctx, symbol_table *global_vars, symbol_table *local_vars, TCGArg *args, ast_var_type dest_type,
             bool is_load) {
    ast_expr *dest = build_var(ctx, global_vars, local_vars, args[0], dest_type);

    MemOp mop = get_memop(args[2]) & (MO_BSWAP | MO_SSIZE);

    // No support for big endian
    assert(mop | MO_BSWAP);

    ast_expr *mem = build_memory_expr(
            build_var(ctx, global_vars, local_vars, args[1], dest_type),
            mop & MO_SIZE,
            (mop & MO_SIGN) >> 2,
            0
    );

    return build_binary_expr(
            is_load ? dest : mem,
            AST_ASS_OP,
            is_load ? mem : dest
    );
}

ast_decl* get_or_create_mmap(symbol_table* vars_table, int64_t base, char* object) {
    char buf[64];
    sprintf(buf, "gv_%lx", base);

    ast_decl* decl = (ast_decl*) symbol_table_lookup(vars_table, buf);

    if(decl == NULL) {
        char* symbol = strdup(buf);

        decl = build_var_decl(symbol, AST_VAR_INT64);

        symbol_table_check_insert(vars_table, symbol, (void *) decl);

        decl->var_decl.scope = AST_VAR_MAP;
        decl->var_decl.object = object;
    }

    return decl;
}

ast_decl* get_or_create_var_from_str(symbol_table* vars_table, char* str) {
    ast_decl *ret_decl = (ast_decl *) symbol_table_lookup(vars_table, str);
    if(ret_decl == NULL) {
        ret_decl = build_var_decl(strdup(str), AST_VAR_INT64);
        symbol_table_check_insert(vars_table, str, (void *) ret_decl);
        ret_decl->var_decl.scope = AST_VAR_REG_GLOBAL;
    }
    return ret_decl;
}

void translate_tcg_to_ast(TCGContext *ctx, ast_stmt_list *stmts, symbol_table *local_vars, symbol_table *global_vars) {
    TCGOp *op;

    ast_stmt* stmt = NULL;
    void* addr = NULL;

    bool skip_to_next_start = 0;

    int64_t lit_offset = 0;

    bool opt_vfp = options.vfp_opts;

    QTAILQ_FOREACH(op, &ctx->ops, link)
    {
        switch (op->opc) {
            /* Instruction Start */
            case INDEX_op_insn_start:
                stmt = NULL;
                addr = (void*) op->args[0];
                skip_to_next_start = 0;
                lit_offset = 0;
                if(a64_decode(addr) == A64_LDX_STX) {
                    // TODO: Use the actual exclusive LDST
                    unsigned int size, o2, l, o1, rs, o0, rt2, rn, rt;
                    a64_LDX_STX_decode_fields (addr, &size, &o2, &l, &o1, &rs, &o0, &rt2, &rn, &rt);

                    char buf[32];
                    sprintf(buf, "x%d", rs);
                    ast_decl *rs_decl = get_or_create_var_from_str(global_vars, buf);
                    sprintf(buf, "x%d", rn);
                    ast_decl *rn_decl = get_or_create_var_from_str(global_vars, buf);
                    sprintf(buf, "x%d", rt);
                    ast_decl *rt_decl = get_or_create_var_from_str(global_vars, buf);

                    // 0x3 = 64-bits, 0x2 = 32-bits
                    if ((size == 0x3 || size == 0x2 || size == 0x0) && o1 == 0x0) {
                        ast_ldst_size ldsize;
                        if(size == 0x3) {
                            ldsize = AST_LDST_DOUBLE;
                        } else if(size == 0x2) {
                            ldsize = AST_LDST_SINGLE;
                        } else if(size == 0x0) {
                            ldsize = AST_LDST_BYTE;
                        }
                        if (l == 0x0) {
                            // Store
                            stmt = build_expr_stmt(
                                    build_binary_expr(
                                            build_memory_expr(
                                                    build_var_expr(rn_decl),
                                                    ldsize,
                                                    AST_LDST_SIGNED,
                                                    0
                                            ),
                                            AST_ASS_OP,
                                            build_var_expr(rt_decl)
                                    )
                            );
                            stmt->insn_addr = addr;
                            append_to_stmt_list(stmts, stmt);
                            stmt = build_expr_stmt(
                                    build_binary_expr(
                                            build_var_expr(rs_decl),
                                            AST_ASS_OP,
                                            build_int32_expr(0)
                                    )
                            );
                        } else {
                            // Load
                            stmt = build_expr_stmt(
                                    build_binary_expr(
                                            build_var_expr(rt_decl),
                                            AST_ASS_OP,
                                            build_memory_expr(
                                                    build_var_expr(rn_decl),
                                                    ldsize,
                                                    AST_LDST_SIGNED,
                                                    0
                                            )
                                    )
                            );
                        }
                    } else {
                        fprintf(stderr, "Exclusive o1=%u o2=%u size=%u not supported!\n", o1, o2, size);
                        exit(-1);
                    }
                } else if(a64_decode(addr) == A64_ADD_SUB_EXT_REG || a64_decode(addr) == A64_ADD_SUB_SHIFT_REG) {
                    int32_t inst = *(int32_t*)addr;
                    if(inst & 0x20000000) {
                        char buf[32];

                        int32_t rhs = (inst & 0x001f0000) >> 16;
                        if(rhs == 30) {
                            sprintf(buf, "lr");
                        } else {
                            sprintf(buf, "x%d", rhs);
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var_expr(get_or_create_var_from_str(global_vars, "rhs")),
                                        AST_ASS_OP,
                                        build_var_expr(get_or_create_var_from_str(global_vars, buf))
                                )
                        );

                        append_to_stmt_list(stmts, stmt);

                        int32_t lhs = (inst & 0x000003e0) >> 5;
                        if(lhs != 31) {
                            if(lhs == 30) {
                                sprintf(buf, "lr");
                            } else {
                                sprintf(buf, "x%d", lhs);
                            }
                            stmt = build_expr_stmt(
                                    build_binary_expr(
                                            build_var_expr(get_or_create_var_from_str(global_vars, "lhs")),
                                            AST_ASS_OP,
                                            build_var_expr(get_or_create_var_from_str(global_vars, buf))
                                    )
                            );
                        } else {
                            stmt = build_expr_stmt(
                                    build_binary_expr(
                                            build_var_expr(get_or_create_var_from_str(global_vars, "lhs")),
                                            AST_ASS_OP,
                                            build_int64_expr(0)
                                    )
                            );
                        }

                        append_to_stmt_list(stmts, stmt);
                        stmt = NULL;
                    }
                } else if(a64_decode(addr) == A64_LOGICAL_REG) {
                    int32_t inst = *(int32_t*)addr;
                    if((inst & 0x60000000) == 0x60000000) {
                        char buf[32];

                        int32_t rhs = (inst & 0x001f0000) >> 16;
                        if(rhs == 30) {
                            sprintf(buf, "lr");
                        } else {
                            sprintf(buf, "x%d", rhs);
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var_expr(get_or_create_var_from_str(global_vars, "rhs")),
                                        AST_ASS_OP,
                                        build_var_expr(get_or_create_var_from_str(global_vars, buf))
                                )
                        );

                        append_to_stmt_list(stmts, stmt);

                        int32_t lhs = (inst & 0x000003e0) >> 5;
                        if(lhs == 30) {
                            sprintf(buf, "lr");
                        } else {
                            sprintf(buf, "x%d", lhs);
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var_expr(get_or_create_var_from_str(global_vars, "lhs")),
                                        AST_ASS_OP,
                                        build_var_expr(get_or_create_var_from_str(global_vars, buf))
                                )
                        );

                        append_to_stmt_list(stmts, stmt);
                        stmt = NULL;
                    }
                } else if(a64_decode(addr) == A64_ADD_SUB_IMMED) {
                    int32_t inst = *(int32_t*)addr;
                    if(inst & 0x20000000) {
                        char buf[32];

                        int32_t lhs = (inst & 0x000003e0) >> 5;
                        if(lhs == 30) {
                            sprintf(buf, "lr");
                        } else {
                            sprintf(buf, "x%d", lhs);
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var_expr(get_or_create_var_from_str(global_vars, "lhs")),
                                        AST_ASS_OP,
                                        build_var_expr(get_or_create_var_from_str(global_vars, buf))
                                )
                        );

                        append_to_stmt_list(stmts, stmt);
                        stmt = NULL;
                    }
                } else if(a64_decode(addr) == A64_LOGICAL_IMMED) {
                    int32_t inst = *(int32_t*)addr;
                    if((inst & 0x60000000) == 0x60000000) {
                        char buf[32];

                        int32_t lhs = (inst & 0x000003e0) >> 5;
                        if(lhs == 30) {
                            sprintf(buf, "lr");
                        } else {
                            sprintf(buf, "x%d", lhs);
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var_expr(get_or_create_var_from_str(global_vars, "lhs")),
                                        AST_ASS_OP,
                                        build_var_expr(get_or_create_var_from_str(global_vars, buf))
                                )
                        );

                        append_to_stmt_list(stmts, stmt);
                        stmt = NULL;
                    }
                }
                break;

            /* Misc */
            case INDEX_op_movi_i32:
                stmt = build_expr_stmt(
                        build_binary_expr_var_imm(ctx, global_vars, local_vars, AST_ASS_OP, op->args,
                                                  build_int32_expr((int32_t) op->args[1]), AST_VAR_INT32)
                );
                break;
            case INDEX_op_movi_i64:
                // ADRP/ADR
                if(((*(int32_t*)addr) & 0x9f000000) == 0x90000000 || ((*(int32_t*)addr) & 0x9f000000) == 0x10000000) {
                    int32_t iop, immlo, immhi, Rd;
                    a64_ADR_decode_fields((int32_t*)addr, &iop, &immlo, &immhi, &Rd);
                    int32_t imm = (immhi << 2) | immlo;

                    uint64_t read_address = (uint64_t) addr - (uint64_t) gcode;
                    uint64_t offset;

                    if (iop == 0){ // ADR
                      imm = sign_extend64(21, imm);
                      offset = (uint64_t)read_address;
                    } else { // ADRP
                      imm = sign_extend64(21, imm) << 12;
                      offset = (uint64_t)read_address & ~(0xFFF);
                    }

                    offset += imm;

                    char *object = "__executable_start";
                    stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                    AST_ASS_OP,
                                    build_binary_expr(
                                            build_var_expr(
                                                    get_or_create_var_from_str(global_vars, object)
                                            ),
                                            AST_ADD_OP,
                                            build_int64_expr(offset)
                                    )
                            )
                    );
                    break;
                }
                stmt = build_expr_stmt(
                        build_binary_expr_var_imm(ctx, global_vars, local_vars, AST_ASS_OP, op->args,
                                                  build_uint64_expr((uint64_t) op->args[1]), AST_VAR_INT64)
                );
                break;

            case INDEX_op_mov_i32:
                stmt = build_expr_stmt(
                        build_binary_expr_2vars(ctx, global_vars, local_vars, AST_ASS_OP, op->args, AST_VAR_INT32)
                );
                break;
            case INDEX_op_mov_i64:
                stmt = build_expr_stmt(
                        build_binary_expr_2vars(ctx, global_vars, local_vars, AST_ASS_OP, op->args, AST_VAR_INT64)
                );
                break;

            case INDEX_op_ext8u_i64:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, AST_CAST_TO_UINT8, AST_CAST_TO_UINT64)
                );
                break;
            case INDEX_op_ext8u_i32:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT32, AST_CAST_TO_UINT8, AST_CAST_TO_UINT32)
                );
                break;
            case INDEX_op_ext16u_i64:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, AST_CAST_TO_UINT16, AST_CAST_TO_UINT64)
                );
                break;
            case INDEX_op_extu_i32_i64:
            case INDEX_op_ext32u_i64:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, AST_CAST_TO_UINT32, AST_CAST_TO_UINT64)
                );
                break;
            case INDEX_op_ext_i32_i64:
            case INDEX_op_ext32s_i64:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, AST_CAST_TO_INT32, AST_CAST_TO_INT64)
                );
                break;
            case INDEX_op_ext16s_i64:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, AST_CAST_TO_INT16, AST_CAST_TO_INT64)
                );
                break;
            case INDEX_op_ext16u_i32:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT32, AST_CAST_TO_UINT16, AST_CAST_TO_INT32)
                );
                break;
            case INDEX_op_ext8s_i64:
                stmt = build_expr_stmt(
                        build_ext(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, AST_CAST_TO_INT8, AST_CAST_TO_INT64)
                );
                break;

            /* Arithmetic */
            case INDEX_op_add_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_ADD_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_add_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_ADD_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            case INDEX_op_sub_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_SUB_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_sub_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_SUB_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            case INDEX_op_neg_i32:
                stmt = build_expr_stmt(
                        build_binary_expr_2vars_neg(ctx, global_vars, local_vars, AST_ASS_OP, op->args, AST_VAR_INT32)
                );
                break;
            case INDEX_op_neg_i64:
                stmt = build_expr_stmt(
                        build_binary_expr_2vars_neg(ctx, global_vars, local_vars, AST_ASS_OP, op->args, AST_VAR_INT64)
                );
                break;

            case INDEX_op_mul_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_MUL_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_mul_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_MUL_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            /* Logical */
            case INDEX_op_and_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_AND_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_and_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_AND_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            case INDEX_op_or_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_ORR_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_or_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_ORR_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;


            case INDEX_op_xor_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_EOR_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_xor_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_EOR_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            case INDEX_op_not_i32:
                stmt = build_expr_stmt(
                        build_binary_expr_2vars_not(ctx, global_vars, local_vars, AST_ASS_OP, op->args, AST_VAR_INT32)
                );
                break;
            case INDEX_op_not_i64:
                stmt = build_expr_stmt(
                        build_binary_expr_2vars_not(ctx, global_vars, local_vars, AST_ASS_OP, op->args, AST_VAR_INT64)
                );
                break;

            /* Shift */
            case INDEX_op_shl_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_LSL_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_shl_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_LSL_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            case INDEX_op_shr_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_LSR_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_shr_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_LSR_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            case INDEX_op_sar_i32:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_ASR_OP, op->args,
                                                 AST_VAR_INT32)
                );
                break;
            case INDEX_op_sar_i64:
                stmt = build_expr_stmt(
                        build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_ASR_OP, op->args,
                                                 AST_VAR_INT64)
                );
                break;

            /* Conditional Moves */
            case INDEX_op_setcond_i32:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                AST_ASS_OP,
                                build_ternary_conditional_expr(
                                        build_cmp(ctx, global_vars, local_vars, &op->args[1], op->args[3], AST_VAR_INT32),
                                        build_int32_expr(1),
                                        build_int32_expr(0)
                                )
                        )
                );
                break;
            case INDEX_op_setcond_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_ternary_conditional_expr(
                                        build_cmp(ctx, global_vars, local_vars, &op->args[1], op->args[3], AST_VAR_INT64),
                                        build_int64_expr(1),
                                        build_int64_expr(0)
                                )
                        )
                );
                break;

            case INDEX_op_movcond_i32:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                AST_ASS_OP,
                                build_ternary_conditional_expr(
                                        build_cmp(ctx, global_vars, local_vars, &op->args[1], op->args[5], AST_VAR_INT32),
                                        build_var(ctx, global_vars, local_vars, op->args[3], AST_VAR_INT32),
                                        build_var(ctx, global_vars, local_vars, op->args[4], AST_VAR_INT32)
                                )
                        )
                );
                break;
            case INDEX_op_movcond_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_ternary_conditional_expr(
                                        build_cmp(ctx, global_vars, local_vars, &op->args[1], op->args[5], AST_VAR_INT64),
                                        build_var(ctx, global_vars, local_vars, op->args[3], AST_VAR_INT64),
                                        build_var(ctx, global_vars, local_vars, op->args[4], AST_VAR_INT64)
                                )
                        )
                );
                break;

            /* QEMU specific */
            case INDEX_op_qemu_ld_i64:
                // TODO: Revisit
                if(a64_decode(addr) == A64_LDR_LIT) {
                    unsigned int scratch, imm19;
                    a64_LDR_lit_decode_fields (addr, &scratch, &scratch, &imm19, &scratch);
                    uint64_t offset = sign_extend64(21, imm19 << 2);
                    uint64_t val = *(uint64_t*)(addr + offset + lit_offset);
                    // QEMU splits loads to q registers into two 64-bits loads, so we need to avoid loading the same
                    // value twice. The offset signals that the next ldr at the same inst addr should be from the next
                    // half.
                    lit_offset += 8;
                    stmt = build_expr_stmt(
                            build_binary_expr_var_imm(ctx, global_vars, local_vars, AST_ASS_OP, op->args,
                                                      build_uint64_expr((uint64_t) val), AST_VAR_INT64)
                    );
                } else {
                    stmt = build_expr_stmt(
                            build_memory(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, 1)
                    );
                }
                break;
            case INDEX_op_qemu_st_i64:
                stmt = build_expr_stmt(
                        build_memory(ctx, global_vars, local_vars, op->args, AST_VAR_INT64, 0)
                );
                break;

            /* Jumps */
            case INDEX_op_brcond_i32:
                // FCCMP
                if(((*(int32_t*)addr) & 0x5e200400) != 0x1e200400) {
                    stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var_expr(get_or_create_branch_cond(local_vars)),
                                    AST_ASS_OP,
                                    build_cmp(ctx, global_vars, local_vars, op->args, op->args[2], AST_VAR_INT32)
                            )
                    );
                } else {
                    stmt = build_conditional_goto_stmt(
                            build_cmp(ctx, global_vars, local_vars, op->args, op->args[2], AST_VAR_INT32),
                            (void*) (uint64_t)(arg_label(op->args[3])->id + 1),
                            NULL
                    );
                    stmt->conditional_goto_stmt.allow_fall_through = 1;
                }
            case INDEX_op_brcond_i64:
                if(((*(int32_t*)addr) & 0x5e200400) != 0x1e200400) {
                    stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var_expr(get_or_create_branch_cond(local_vars)),
                                    AST_ASS_OP,
                                    build_cmp(ctx, global_vars, local_vars, op->args, op->args[2], AST_VAR_INT64)
                            )
                    );
                } else {
                    stmt = build_conditional_goto_stmt(
                            build_cmp(ctx, global_vars, local_vars, op->args, op->args[2], AST_VAR_INT64),
                            (void*) (uint64_t)(arg_label(op->args[3])->id + 1),
                            NULL
                    );
                    stmt->conditional_goto_stmt.allow_fall_through = 1;
                }
                break;

            /* Vector */
            case INDEX_op_ld_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_ASS_OP,
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        (TCGOP_VECL(op) == 1) ? AST_LDST_QVEC : AST_LDST_VEC,
                                        AST_LDST_SIGNED,
                                        8 << TCGOP_VECE(op)
                                )
                        )
                );
                break;
            case INDEX_op_st_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        (TCGOP_VECL(op) == 1) ? AST_LDST_QVEC : AST_LDST_VEC,
                                        AST_LDST_SIGNED,
                                        8 << TCGOP_VECE(op)
                                ),
                                AST_ASS_OP,
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64)
                        )
                );
                break;
            case INDEX_op_dup_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                ast_var_type type = -1;
                if (TCGOP_VECE(op) == 0) {
                    type = AST_VAR_INT8;
                } else if (TCGOP_VECE(op) == 1) {
                    type = AST_VAR_INT16;
                } else if (TCGOP_VECE(op) == 2) {
                    type = AST_VAR_INT32;
                } else if (TCGOP_VECE(op) == 3) {
                    type = AST_VAR_INT64;
                }
                assert(type != -1);
                stmt = build_expr_stmt(
                        build_dup_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], type),
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_dupm_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                type = -1;
                if (TCGOP_VECE(op) == 0) {
                    type = AST_VAR_INT8;
                } else if (TCGOP_VECE(op) == 1) {
                    type = AST_VAR_INT16;
                } else if (TCGOP_VECE(op) == 2) {
                    type = AST_VAR_INT32;
                } else if (TCGOP_VECE(op) == 3) {
                    type = AST_VAR_INT64;
                }
                assert(type != -1);
                stmt = build_expr_stmt(
                        build_dup_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                        AST_ADD_OP,
                                        build_uint64_expr(op->args[2])
                                ),
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_dupi_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                type = -1;
                ast_expr *scalar = NULL;
                if (TCGOP_VECE(op) == 0) {
                    type = AST_VAR_INT8;
                } else if (TCGOP_VECE(op) == 1) {
                    type = AST_VAR_INT16;
                } else if (TCGOP_VECE(op) == 2) {
                    type = AST_VAR_INT32;
                    scalar = build_int32_expr((int32_t) op->args[1]);
                } else if (TCGOP_VECE(op) == 3) {
                    type = AST_VAR_INT64;
                    scalar = build_int64_expr((int64_t) op->args[1]);
                }
                assert(type != -1);
                assert(scalar != NULL);
                stmt = build_expr_stmt(
                        build_dup_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                scalar,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_add_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_ADD_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_sub_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_SUB_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_mul_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_MUL_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_sari_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_int32_expr((int32_t)op->args[2]),
                                AST_ASR_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_shli_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_int32_expr((int32_t)op->args[2]),
                                AST_LSL_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_shlv_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_LSL_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_aa64_sshl_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_SLSL_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_shri_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_int32_expr((int32_t)op->args[2]),
                                AST_LSR_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_and_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_AND_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_andc_vec:
                assert(TCGOP_VECL(op) == 1);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_ANDC_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_orc_vec:
                assert(TCGOP_VECL(op) == 1);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_ORC_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_or_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_ORR_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_xor_vec:
                assert(TCGOP_VECL(op) == 1);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_EOR_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_cmp_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                tcg_to_ast_cond(op->args[3]),
                                8 << TCGOP_VECE(op)
                        )
                );

                if(stmt->expr_stmt->vec_expr.op == AST_NE_OP) {
                    stmt->expr_stmt->vec_expr.op = AST_EQ_OP;
                    append_to_stmt_list(stmts, stmt);
                    stmt = build_expr_stmt(
                            build_vec_expr(
                                    build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                    build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                    NULL,
                                    AST_NOT_OP,
                                    8 << TCGOP_VECE(op)
                            )
                    );
                }
                break;
            case INDEX_op_smax_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_MAX_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_umax_vec:
                assert(TCGOP_VECL(op) == 1);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_UMAX_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_smin_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_MIN_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_umin_vec:
                assert(TCGOP_VECL(op) == 1);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_VEC128),
                                build_var(ctx, global_vars, local_vars, op->args[2], AST_VAR_VEC128),
                                AST_UMIN_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_abs_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                NULL,
                                AST_ABS_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_not_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                NULL,
                                AST_NOT_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_neg_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                NULL,
                                AST_NEG_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                break;
            case INDEX_op_bitsel_vec:
                assert(TCGOP_VECL(op) == 1 || TCGOP_VECL(op) == 0);
                stmt = build_expr_stmt(
                        build_vec_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[1], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                build_var(ctx, global_vars, local_vars, op->args[2], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64),
                                AST_BSL_OP,
                                8 << TCGOP_VECE(op)
                        )
                );
                stmt->expr_stmt->vec_expr.v3 = build_var(ctx, global_vars, local_vars, op->args[3], (TCGOP_VECL(op) == 1) ? AST_VAR_VEC128 : AST_VAR_VEC64);
                break;

            /* Call */
            case INDEX_op_call:
                ;
                unsigned func_in_nb = op->param1;
                unsigned func_out_nb = op->param2;
                char *func_name = tcg_helper_lookup(ctx, op->args[func_in_nb + func_out_nb]);
                if (strcmp(func_name, "lookup_tb_ptr") == 0) {
                    // Skip jumps between basic blocks
                    stmt = NULL;
                } else if (strcmp(func_name, "udiv64") == 0) {
                    stmt = build_expr_stmt(
                            build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_UDIV_OP, op->args,
                                                     AST_VAR_INT64)
                    );
                } else if (strcmp(func_name, "sdiv64") == 0) {
                    stmt = build_expr_stmt(
                            build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_ASS_OP, AST_DIV_OP, op->args,
                                                     AST_VAR_INT64)
                    );
                } else if (strcmp(func_name, "clz_i64") == 0 || strcmp(func_name, "rbit64") == 0 || strcmp(func_name, "clz_i32") == 0 || strcmp(func_name, "rbit") == 0) {
                    ast_function *helper;
                    if (strcmp(func_name, "clz_i64") == 0) {
                        helper = build_function("mambo_lift_clz64");
                    } else if (strcmp(func_name, "rbit64") == 0) {
                        helper = build_function("mambo_lift_rbit64");
                    } else if (strcmp(func_name, "rbit") == 0) {
                        helper = build_function("mambo_lift_rbit");
                    } else {
                        helper = build_function("mambo_lift_clz32");
                    }
                    helper->arguments[0] = build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64);
                    helper->number_arguments = 1;
                    stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                    AST_ASS_OP,
                                    build_call_expr(helper)
                            )
                    );
                } else if(((*(int32_t*)addr) & 0xd53b420d) == 0xd53b420d) {
                    // mrs x13, nzvc
                    // TODO: Implement
                    ast_function *helper = build_function("mambo_mrs_nzvc");
                    char buf[32];
                    sprintf(buf, "x%d", 13);
                    ast_decl *ret_decl = get_or_create_var_from_str(global_vars, buf);
                    helper->arguments[0] = build_var_expr(ret_decl);
                    helper->number_arguments++;
                    stmt = build_expr_stmt(
                            build_call_expr(helper)
                    );
                } else if(((*(int32_t*)addr) & 0xd51b420d) == 0xd51b420d) {
                    // msr nzvc, x13
                    // TODO: Implement
                    ast_function *helper = build_function("mambo_msr_nzvc");
                    char buf[32];
                    sprintf(buf, "x%d", 13);
                    ast_decl *ret_decl = get_or_create_var_from_str(global_vars, buf);
                    helper->arguments[0] = build_var_expr(ret_decl);
                    helper->number_arguments++;
                    stmt = build_expr_stmt(
                            build_call_expr(helper)
                    );
                } else if(((*(int32_t*)addr) & 0xfff00000) == 0xd5300000) {
                    // MRS
                    ast_function *helper = NULL;
                    unsigned int r, o0, op1, crn, crm, op2, rt;
                    a64_MRS_MSR_reg_decode_fields (addr,&r,&o0,&op1,&crn,&crm,&op2,&rt);
                    o0 += 2;
                    if (o0 == 3 && op1 == 3) {
                        if (crn == 4 && crm == 4) {
                            if(op2 == 0) {
                                helper = build_function("mambo_lift_mrs_fpcr");
                            } else if(op2 == 1) {
                                helper = build_function("mambo_lift_mrs_fpsr");
                            }
                        } else if (crn == 0 && crm == 0 && op2 == 7) {
                            helper = build_function("mambo_lift_mrs_dczid");
                        } else if (crn == 0xe && crm == 0 && op2 == 2) {
                            helper = build_function("mambo_lift_mrs_cntvct");
                        } else if (crn == 0xd && crm == 0 && op2 == 2) {
                            helper = build_function("mambo_lift_mrs_tpidr");
                        }
                    }
                    if(helper == NULL) {
                        fprintf(stderr, "Invalid MRS register!\n");
                        exit(-1);
                    }
                    char buf[32];
                    sprintf(buf, "x%d", (*(int32_t*)addr) & 0x0000001f);
                    stmt = build_expr_stmt(
                            build_binary_expr(
                                    build_var_expr(get_or_create_var_from_str(global_vars, buf)),
                                    AST_ASS_OP,
                                    build_call_expr(helper)
                            )
                    );
                } else if(((*(int32_t*)addr) & 0xd51bd040) == 0xd51bd040) {
                    // msr     tpidr_el0, x0
                    ast_function *helper = build_function("mambo_lift_msr_tpidr");
                    char buf[32];
                    sprintf(buf, "x%d", 0);
                    ast_decl *ret_decl = get_or_create_var_from_str(global_vars, buf);
                    helper->arguments[0] = build_var_expr(ret_decl);
                    helper->number_arguments++;
                    stmt = build_expr_stmt(
                            build_call_expr(helper)
                    );
                } else if(((*(int32_t*)addr) & 0xd51b4400) == 0xd51b4400) {
                    // msr     fpcr, x0
                    ast_function *helper = build_function("mambo_lift_msr_fpcr");
                    char buf[32];
                    sprintf(buf, "x%d", 0);
                    ast_decl *ret_decl = get_or_create_var_from_str(global_vars, buf);
                    helper->arguments[0] = build_var_expr(ret_decl);
                    helper->number_arguments++;
                    stmt = build_expr_stmt(
                            build_call_expr(helper)
                    );
                } else if(((*(int32_t*)addr) & 0xffe0001f) == 0xd4000001) {
                    // SVC
                    stmt = NULL;
                } else if(((*(int32_t*)addr) & 0xffffffe0) == 0xd50b7420) {
                    // DC ZVA
                    ast_function *helper = build_function("mambo_lift_dc_zva");
                    char buf[32];
                    sprintf(buf, "x%d", (*(int32_t *) addr) & 0x0000001f);
                    ast_decl *ret_decl = get_or_create_var_from_str(global_vars, buf);
                    helper->arguments[0] = build_var_expr(ret_decl);
                    helper->number_arguments++;
                    stmt = build_expr_stmt(
                            build_call_expr(helper)
                    );
                } else if(opt_vfp && strncmp(func_name, "vfp", 3) == 0) {
                    if(strcmp(func_name, "vfp_addd") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_ADD_OP, op->args,
                                                         AST_VAR_INT64)
                        );
                    }  else if(strcmp(func_name, "vfp_adds") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_ADD_OP, op->args,
                                                         AST_VAR_INT32)
                        );
                    } else if(strcmp(func_name, "vfp_subd") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_SUB_OP, op->args,
                                                         AST_VAR_INT64)
                        );
                    } else if(strcmp(func_name, "vfp_subs") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_SUB_OP, op->args,
                                                         AST_VAR_INT32)
                        );
                    } else if(strcmp(func_name, "vfp_muld") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_MUL_OP, op->args,
                                                         AST_VAR_INT64)
                        );
                    } else if(strcmp(func_name, "vfp_muls") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_MUL_OP, op->args,
                                                         AST_VAR_INT32)
                        );
                    } else if(strcmp(func_name, "vfp_divd") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_DIV_OP, op->args,
                                                         AST_VAR_INT64)
                        );
                    } else if(strcmp(func_name, "vfp_divs") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_DIV_OP, op->args,
                                                         AST_VAR_INT32)
                        );
                    } else if(strcmp(func_name, "vfp_negd") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr_2vars_neg(ctx, global_vars, local_vars, AST_FASS_OP, op->args, AST_VAR_INT64)
                        );
                    } else if(strcmp(func_name, "vfp_negs") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr_2vars_neg(ctx, global_vars, local_vars, AST_FASS_OP, op->args, AST_VAR_INT32)
                        );
                    } else if(strcmp(func_name, "vfp_maxnumd") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_MAX_OP, op->args,
                                                         AST_VAR_INT64)
                        );
                    } else if(strcmp(func_name, "vfp_minnumd") == 0) {
                        stmt = build_expr_stmt(
                                build_ternary_expr_3vars(ctx, global_vars, local_vars, AST_FASS_OP, AST_MIN_OP, op->args,
                                                         AST_VAR_INT64)
                        );
                    } else if(strcmp(func_name, "vfp_sqtod") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_FASS_OP,
                                        build_cast_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],
                                                                  AST_VAR_INT64),
                                                        AST_ASR_OP,
                                                        build_var(ctx, global_vars, local_vars, op->args[2],
                                                                  AST_VAR_INT32)
                                                ),
                                                AST_CAST_TO_DOUBLE
                                        )
                                )
                        );
                    } else if(strcmp(func_name, "vfp_uqtod") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_FASS_OP,
                                        build_cast_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],
                                                                  AST_VAR_INT64),
                                                        AST_LSR_OP,
                                                        build_var(ctx, global_vars, local_vars, op->args[2],
                                                                  AST_VAR_INT32)
                                                ),
                                                AST_CAST_TO_DOUBLE
                                        )
                                )
                        );
                    } else if(strcmp(func_name, "vfp_sqtos") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                        AST_FASS_OP,
                                        build_cast_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],
                                                                  AST_VAR_INT32),
                                                        AST_ASR_OP,
                                                        build_var(ctx, global_vars, local_vars, op->args[2],
                                                                  AST_VAR_INT32)
                                                ),
                                                AST_CAST_TO_FLOAT
                                        )
                                )
                        );
                    }  else if(strcmp(func_name, "vfp_sitos") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                        AST_FASS_OP,
                                        build_cast_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT32),
                                                AST_CAST_TO_FLOAT
                                        )
                                )
                        );
                    } else if(strcmp(func_name, "vfp_uitos") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                        AST_FASS_OP,
                                        build_cast_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT32),
                                                AST_CAST_TO_FLOAT
                                        )
                                )
                        );
                    } else if (strcmp(func_name, "vfp_tosld") == 0 || strcmp(func_name, "vfp_tosqd") == 0
                               || strcmp(func_name, "vfp_tosls") == 0 || strcmp(func_name, "vfp_tould") == 0 ||
                               strcmp(func_name, "vfp_touqd") == 0 || strcmp(func_name, "vfp_uqtos") == 0
                               || strcmp(func_name, "vfp_touqs") == 0 || strcmp(func_name, "vfp_tosqs") == 0
                               || strcmp(func_name, "vfp_touls") == 0) {
                        // TODO: Probably need to copy FPSR.
                        char buf[256];
                        sprintf(buf, "helper_%s_aarch64", func_name);
                        ast_function *helper = build_function(strdup(buf));
                        for (int i = 0; i < func_in_nb; i++) {
                            // TODO: Check var size
                            helper->arguments[i] = build_var(ctx, global_vars, local_vars, op->args[func_out_nb + i],
                                                             AST_VAR_INT64);
                            helper->number_arguments++;
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_ASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_muladdd") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_FASS_OP,
                                        build_binary_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],
                                                                  AST_VAR_INT64),
                                                        AST_MUL_OP,
                                                        build_var(ctx, global_vars, local_vars, op->args[2],
                                                                  AST_VAR_INT64)
                                                ),
                                                AST_ADD_OP,
                                                build_var(ctx, global_vars, local_vars, op->args[3], AST_VAR_INT64)
                                        )
                                )
                        );
                    } else if(strcmp(func_name, "vfp_muladds") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                        AST_FASS_OP,
                                        build_binary_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],
                                                                  AST_VAR_INT32),
                                                        AST_MUL_OP,
                                                        build_var(ctx, global_vars, local_vars, op->args[2],
                                                                  AST_VAR_INT32)
                                                ),
                                                AST_ADD_OP,
                                                build_var(ctx, global_vars, local_vars, op->args[3], AST_VAR_INT32)
                                        )
                                )
                        );
                    } else if(strcmp(func_name, "vfp_cmpd_a64") == 0 || strcmp(func_name, "vfp_cmped_a64") == 0) {
                        // TODO: Probably need to copy FPSR.
                        char buf[256];
                        sprintf(buf, "helper_fcmpd_aarch64");
                        ast_function *helper = build_function(strdup(buf));
                        for(int i = 0; i < func_in_nb - 1; i++) {
                            // TODO: Check var size
                            helper->arguments[i] = build_var(ctx, global_vars, local_vars, op->args[func_out_nb + i], AST_VAR_INT64);
                            helper->number_arguments++;
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_ASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_cmps_a64") == 0 || strcmp(func_name, "vfp_cmpes_a64") == 0) {
                        // TODO: Probably need to copy FPSR.
                        char buf[256];
                        sprintf(buf, "helper_fcmps_aarch64");
                        ast_function *helper = build_function(strdup(buf));
                        for(int i = 0; i < func_in_nb - 1; i++) {
                            // TODO: Check var size
                            helper->arguments[i] = build_var(ctx, global_vars, local_vars, op->args[func_out_nb + i], AST_VAR_INT64);
                            helper->number_arguments++;
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_ASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_fcvtds") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_FASS_OP,
                                        build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT32)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_fcvtsd") == 0) {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                        AST_FASS_OP,
                                        build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_sqrtd") == 0) {
                        ast_function *helper = build_function("sqrt");
                        helper->arguments[0] = build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64);
                        helper->number_arguments++;
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_FASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_absd") == 0) {
                        ast_function *helper = build_function("fabs");
                        helper->arguments[0] = build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64);
                        helper->number_arguments++;
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_FASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    } else if(strcmp(func_name, "vfp_abss") == 0) {
                        ast_function *helper = build_function("fabsf");
                        helper->arguments[0] = build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT32);
                        helper->number_arguments++;
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                        AST_FASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    } else {
                        // TODO: Probably need to copy FPSR.
                        char buf[256];
                        sprintf(buf, "helper_%s_aarch64", func_name);
                        ast_function *helper = build_function(strdup(buf));
                        for (int i = 0; i < func_in_nb; i++) {
                            // TODO: Check var size
                            helper->arguments[i] = build_var(ctx, global_vars, local_vars, op->args[func_out_nb + i],
                                                             AST_VAR_INT64);
                            helper->number_arguments++;
                        }
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_ASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                        // fprintf(stderr, "MAMBO Lift: %s helper not supported!\n", func_name);
                        // exit(-1);
                    }
                } else if (func_name[0] == 'g' || strcmp(func_name, "set_rmode") == 0 ||
                           strcmp(func_name, "rintd") == 0 || strcmp(func_name, "mulsh_i64") == 0 ||
                           strcmp(func_name, "muluh_i64") == 0 || strcmp(func_name, "rbit64") == 0 || func_name[0] == 'n' || func_name[0] == 'v'
                           || strcmp(func_name, "simd_tbl") == 0 || strcmp(func_name, "rints") == 0 || strcmp(func_name, "rbit") == 0) {
                    // vfp, gvec
                    // set_rmode - Set rounding mode
                    // rintd - Round to integer (double)
                    // rints - Round to integer (single)
                    if(func_out_nb > 1) {
                        fprintf(stderr, "Failed\n");
                        exit(-1);
                    }
                    char buf[256];
                    sprintf(buf, "helper_%s_aarch64", func_name);
                    ast_function *helper = build_function(strdup(buf));
                    for(int i = 0; i < func_in_nb; i++) {
                        // TODO: Check var size
                        helper->arguments[i] = build_var(ctx, global_vars, local_vars, op->args[func_out_nb + i], AST_VAR_INT64);
                        helper->number_arguments++;
                    }
                    if(func_out_nb == 0) {
                        stmt = build_expr_stmt(
                                build_call_expr(helper)
                        );
                    } else {
                        stmt = build_expr_stmt(
                                build_binary_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_ASS_OP,
                                        build_call_expr(helper)
                                )
                        );
                    }
                } else if(strcmp(func_name, "exception_bkpt_insn") == 0) {
                    ast_function *helper = build_function("helper_aarch64_brk");
                    stmt = build_expr_stmt(
                                    build_call_expr(helper)
                    );
                } else {
                    stmt = NULL;
                    fprintf(stderr, "Found helper %s %x\n", func_name, *(int32_t*)addr);
                    exit(-1);
                }
                break;

            /* Load/Store */
            case INDEX_op_ld_i32:
                ;
                ast_expr* base = build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64);
                ast_expr* offset = build_uint64_expr(op->args[2]);
                ast_expr* dest = build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32);;
                stmt = build_expr_stmt(
                        build_binary_expr(
                                dest,
                                AST_ASS_OP,
                                build_memory_expr(
                                        build_binary_expr(
                                                base,
                                                AST_ADD_OP,
                                                offset
                                        ),
                                        AST_LDST_SINGLE,
                                        AST_LDST_SIGNED,
                                        0
                                )
                        )
                );
                break;
            case INDEX_op_ld_i64:
                base = build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64);
                offset = build_uint64_expr(op->args[2]);
                dest = build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64);;
                stmt = build_expr_stmt(
                        build_binary_expr(
                                dest,
                                AST_ASS_OP,
                                build_memory_expr(
                                        build_binary_expr(
                                                base,
                                                AST_ADD_OP,
                                                offset
                                        ),
                                        AST_LDST_DOUBLE,
                                        AST_LDST_SIGNED,
                                        0
                                )
                        )
                );
                break;
            case INDEX_op_ld32u_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_SINGLE,
                                                AST_LDST_UNSIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT64
                                )
                        )
                );
                break;
            case INDEX_op_ld16u_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_HALF,
                                                AST_LDST_UNSIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT64
                                )
                        )
                );
                break;
            case INDEX_op_ld16u_i32:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_HALF,
                                                AST_LDST_UNSIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT32
                                )
                        )
                );
                break;
            case INDEX_op_ld8u_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_BYTE,
                                                AST_LDST_UNSIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT64
                                )
                        )
                );
                break;
            case INDEX_op_ld32s_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_SINGLE,
                                                AST_LDST_SIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT64
                                )
                        )
                );
                break;
            case INDEX_op_ld16s_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_HALF,
                                                AST_LDST_SIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT64
                                )
                        )
                );
                break;
            case INDEX_op_ld8s_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_memory_expr(
                                                build_binary_expr(
                                                        build_var(ctx, global_vars, local_vars, op->args[1],AST_VAR_INT64),
                                                        AST_ADD_OP,
                                                        build_uint64_expr(op->args[2])
                                                ),
                                                AST_LDST_BYTE,
                                                AST_LDST_SIGNED,
                                                0
                                        ),
                                        AST_CAST_TO_INT64
                                )
                        )
                );
                break;
            case INDEX_op_st_i32:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        AST_LDST_SINGLE,
                                        AST_LDST_SIGNED,
                                        0
                                ),
                                AST_ASS_OP,
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT32)
                        )
                );
                break;
            case INDEX_op_st32_i64:
                // TODO: Probably should be size double
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        AST_LDST_SINGLE,
                                        AST_LDST_SIGNED,
                                        0
                                ),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_CAST_TO_INT32
                                )
                        )
                );
                break;
            case INDEX_op_st16_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        AST_LDST_DOUBLE,
                                        AST_LDST_SIGNED,
                                        0
                                ),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_CAST_TO_INT16
                                )
                        )
                );
                break;
            case INDEX_op_st8_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        AST_LDST_DOUBLE,
                                        AST_LDST_SIGNED,
                                        0
                                ),
                                AST_ASS_OP,
                                build_cast_expr(
                                        build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64),
                                        AST_CAST_TO_INT8
                                )
                        )
                );
                break;
            case INDEX_op_st_i64:
                stmt = build_expr_stmt(
                        build_binary_expr(
                                build_memory_expr(
                                        build_binary_expr(
                                                build_var(ctx, global_vars, local_vars, op->args[1], AST_VAR_INT64),
                                                AST_ADD_OP,
                                                build_uint64_expr(op->args[2])
                                        ),
                                        AST_LDST_DOUBLE,
                                        AST_LDST_SIGNED,
                                        0
                                ),
                                AST_ASS_OP,
                                build_var(ctx, global_vars, local_vars, op->args[0], AST_VAR_INT64)
                        )
                );
                break;

            /* Internal TCG jumps (e.g., used to implement complex instructions requiring control flow, e.g., fccmp */
            case INDEX_op_br:
                if(((*(int32_t*)addr) & 0x5e200400) == 0x1e200400) {
                    stmt = build_conditional_goto_stmt(NULL, (void *) (uint64_t)(arg_label(op->args[0])->id + 1), NULL);
                } else {
                    stmt = NULL;
                }
                break;
            case INDEX_op_goto_ptr:
                stmt = NULL;
                break;
            case INDEX_op_set_label:
                if(((*(int32_t*)addr) & 0x5e200400) == 0x1e200400) {
                    stmt = build_label_stmt((void *) (uint64_t)(arg_label(op->args[0])->id + 1));
                } else {
                    stmt = NULL;
                }
                break;

            /* Default */
            default:
                fprintf(stderr, "MAMBO Lift: TCG opc %s not implemented!\n", ctx->tcg_op_defs[op->opc].name);
                exit(-1);
                stmt = NULL;
                break;
        }

        if(a64_decode(addr) == A64_LDX_STX) {
            if(!skip_to_next_start) {
                skip_to_next_start = 1;
                stmt->insn_addr = addr;
                append_to_stmt_list(stmts, stmt);
            }
            continue;
        }

        if(stmt != NULL) {
            stmt->insn_addr = addr;
            append_to_stmt_list(stmts, stmt);
        }
    }
}
