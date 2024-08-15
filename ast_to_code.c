/*
  Copyright 2024 Igor Wodiany
  Copyright 2024 The University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this trace except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <assert.h>
#include <ctype.h>
#include <float.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "utils/hashmap_utils.h"
#include "utils/print_utils.h"

#include "ast/ast_utils.h"

#include "options.h"

#include "ast_to_code.h"

symbol_table* gvars;
extern void** taddrs;

int dump_expr(FILE *file, ast_expr *expr, void (*dump_variable)(FILE *, ast_decl *));

static const char *const op_names[] = {
        [AST_EQ_OP] = "==",
        [AST_NE_OP] = "!=",
        [AST_CS_OP] = ">=",
        [AST_CC_OP] = "<",
        [AST_MI_OP] = "nop",
        [AST_PL_OP] = "nop",
        [AST_VS_OP] = "nop",
        [AST_VC_OP] = "nop",
        [AST_HI_OP] = ">",
        [AST_LS_OP] = "<=",
        [AST_GE_OP] = ">=",
        [AST_LT_OP] = "<",
        [AST_GT_OP] = ">",
        [AST_LE_OP] = "<=",
        [AST_AL_OP] = "nop",
        [AST_ALT_OP] = "nop",
        [AST_ADD_OP] = "+",
        [AST_SUB_OP] = "-",
        [AST_MUL_OP] = "*",
        [AST_DIV_OP] = "/",
        [AST_UDIV_OP] = "/",
        [AST_AND_OP] = "&",
        [AST_ORR_OP] = "|",
        [AST_EOR_OP] = "^",
        [AST_NOT_OP] = "~",
        [AST_LSL_OP] = "<<",
        [AST_ASR_OP] = ">>",
        [AST_LSR_OP] = ">>",
        [AST_LNG_OP] = "!",
        [AST_ASS_OP] = "=",
        [AST_FASS_OP] = "="
};

static void dump_op(FILE *file, ast_op op) {
    fprintf(file, "%s", op_names[op]);
}

static void dump_unsigned_variable(FILE *file, ast_decl *decl) {
    assert(decl->type == AST_VAR_DECL);

    fprintf(file, "%s.u", decl->var_decl.symbol);
}

static void dump_signed_variable(FILE *file, ast_decl *decl) {
    assert(decl->type == AST_VAR_DECL);

    fprintf(file, "%s.s", decl->var_decl.symbol);
}

static void dump_floating_variable(FILE *file, ast_decl *decl) {
    assert(decl->type == AST_VAR_DECL);

    switch (decl->var_decl.type) {
        case AST_VAR_INT8:
        case AST_VAR_INT16:
        case AST_VAR_INT32:
        case AST_VAR_INT64:
            fprintf(file, "%s.f", decl->var_decl.symbol);
            break;
        case AST_VAR_VEC64:
        case AST_VAR_VEC128:
        case AST_VAR_NOTYPE:
        default:
            fprintf(stderr, "MAMBO Lift: Variable type %d not supported in dump_variable!\n", decl->var_decl.type);
             exit(-1);
    }
}

static void dump_variable(FILE *file, ast_decl *decl) {
    assert(decl->type == AST_VAR_DECL);

    switch (decl->var_decl.type) {
        case AST_VAR_INT8:
        case AST_VAR_INT16:
        case AST_VAR_INT32:
        case AST_VAR_INT64:
            fprintf(file, "%s.s", decl->var_decl.symbol);
            break;
        case AST_VAR_VEC64:
        case AST_VAR_VEC128:
        case AST_VAR_STRUCT:
            fprintf(file, "%s", decl->var_decl.symbol);
            break;
        case AST_VAR_NOTYPE:
        default:
            fprintf(stderr, "MAMBO Lift: Variable type %d not supported in dump_variable!\n", decl->var_decl.type);
            exit(-1);
    }
}

static void dump_string(FILE *file, char *string) {
    fprintf(file, "\"");
    int index = 0;
    while (string[index] != 0) {
        if (isprint(string[index]) && string[index] != '\\') {
            fprintf(file, "%c", string[index]);
        } else if (string[index] == '\n') {
            fprintf(file, "\\n");
        } else {
            fprintf(file, "\\x%02x", string[index]);
        }

        index++;
    }
    fprintf(file, "\"");
}

static void dump_variable_type(FILE *file, ast_var_type type) {
    switch (type) {
        case AST_VAR_INT32:
            fprintf(file, "int32_var ");
            break;
        case AST_VAR_INT64:
            fprintf(file, "int64_var ");
            break;
        case AST_VAR_VEC64:
            fprintf(file, "int64x1_t ");
            break;
        case AST_VAR_VEC128:
            fprintf(file, "int64x2_t ");
            break;
        case AST_VAR_STRUCT:
            fprintf(file, "cpu_state* ");
            break;
        case AST_VAR_INT8:
        case AST_VAR_INT16:
        case AST_VAR_NOTYPE:
            fprintf(stderr, "MAMBO Lift: Variable type %d not supported in dump_variable_type!\n",
                    type);
            exit(-1);
        default:
            fprintf(stderr, "MAMBO Lift: Variable type %d was not expected in dump_variable_type!\n",
                    type);
            exit(-1);
    }
}

static void dump_variable_definition(FILE *file, ast_decl *decl) {
    assert(decl->type == AST_VAR_DECL);

    dump_variable_type(file, decl->var_decl.type);
    fprintf(file, "%s", decl->var_decl.symbol);
}

static const char *const cast_names[] = {
        [AST_CAST_TO_UINT64] = "(uint64_t)",
        [AST_CAST_TO_INT64]  = "(int64_t)",
        [AST_CAST_TO_UINT32] = "(uint32_t)",
        [AST_CAST_TO_INT32] = "(int32_t)",
        [AST_CAST_TO_UINT16] = "(uint16_t)",
        [AST_CAST_TO_INT16] = "(int16_t)",
        [AST_CAST_TO_UINT8] = "(uint8_t)",
        [AST_CAST_TO_INT8] = "(int8_t)",
        [AST_CAST_TO_DOUBLE] = "(double)",
        [AST_CAST_TO_FLOAT] = "(float)",
        [AST_CAST_DOUBLE_TO_INT] = "(int64_t)",
        [AST_CAST_FLOAT_TO_INT] = "(int64_t)"
};

static void dump_cast_expr(FILE *file, ast_expr *expr) {
    if(expr->cast_expr.type == AST_CAST_DOUBLE_TO_INT || expr->cast_expr.type == AST_CAST_FLOAT_TO_INT) {
        fprintf(file, "%s", cast_names[expr->cast_expr.type]);
        dump_expr(file, expr->cast_expr.expr, dump_floating_variable);
    } else {
        fprintf(file, "%s", cast_names[expr->cast_expr.type]);
        dump_expr(file, expr->cast_expr.expr, dump_variable);
    }
}

static const char *const types_names[] = {
        [AST_VAR_INT8] = "int8_t",
        [AST_VAR_INT16] = "int16_t",
        [AST_VAR_INT32] = "int32_t",
        [AST_VAR_INT64] = "int64_t"
};

static void dump_memory_expr(FILE *file, ast_expr *expr) {
    assert(expr->memory_expr.type == AST_LDST_SIGNED || expr->memory_expr.type == AST_LDST_UNSIGNED || expr->memory_expr.type == AST_LDST_FLOAT);

#ifdef _COLLECT_MEMORY_PROFILES
    if(expr->memory_expr.lv != NULL) {
        if(expr->memory_expr.lv->var_expr.var->var_decl.symbol[0] == 'l') {
            dump_variable(file, expr->memory_expr.lv->var_expr.var);
            return;
        }
    }

    if(expr->memory_expr.memory_profile != NULL) {
        fprintf(file, "/* --> ");
        for (int i = 0; i < expr->memory_expr.memory_profile->number_accesses; i++) {
            fprintf(file, "%lx ", (int64_t) expr->memory_expr.memory_profile->address[i]);
        }
        fprintf(file, "<-- */");
    }
#endif

    fprintf(file, "*(");

    if (expr->memory_expr.type == AST_LDST_UNSIGNED) {
        fprintf(file, "u");
    } else if(expr->memory_expr.type == AST_LDST_FLOAT) {
        if(expr->memory_expr.size == AST_LDST_SINGLE) {
            fprintf(file, "float");
        } else if(expr->memory_expr.size == AST_LDST_DOUBLE) {
            fprintf(file, "double");
        } else {
            fprintf(stderr, "MAMBO Lift: LDST type is not supported!\n");
            exit(-1);
        }
        fprintf(file, "*)");
        dump_expr(file, expr->memory_expr.addr, dump_variable);
        return;
    }

    if (expr->memory_expr.size == AST_LDST_QVEC) {
        fprintf(file, "int%dx%d_t", expr->memory_expr.element_size,
                128 / expr->memory_expr.element_size);
    } else if (expr->memory_expr.size == AST_LDST_VEC) {
        fprintf(file, "int%dx%d_t", expr->memory_expr.element_size,
                64 / expr->memory_expr.element_size);
    } else if(expr->memory_expr.size >= AST_LDST_BYTE && expr->memory_expr.size <= AST_LDST_DOUBLE) {
        fprintf(file, "%s", types_names[expr->memory_expr.size + 1]);
    } else {
        fprintf(stderr, "MAMBO Lift: LDST type is not supported!\n");
        exit(-1);
    }

    fprintf(file, "*)");
    dump_expr(file, expr->memory_expr.addr, dump_variable);
}

static void dump_function_call(FILE *file, ast_expr** arguments, uint32_t size, void (*current_dump_variable)(FILE *, ast_decl *), bool non_union) {
    for(int i = 0; i < size; i++) {
        if (arguments[i]->type == AST_VAR_EXPR) {
            if(non_union) {
                current_dump_variable(file, arguments[i]->var_expr.var);//fprintf(file, "%s.s", arguments[i]->var_expr.var->var_decl.symbol);
            } else {
                fprintf(file, "%s", arguments[i]->var_expr.var->var_decl.symbol);
            }
        } else if(arguments[i]->type == AST_MEMORY_EXPR) {
            dump_memory_expr(file, arguments[i]);
        } else if(arguments[i]->type == AST_STRING_EXPR) {
            fprintf(file, "%s", arguments[i]->string_expr);
        } else if(arguments[i]->type == AST_INT64_EXPR) {
            fprintf(file, "%ld", arguments[i]->int64_expr);
        } else {
            fprintf(stderr, "MAMBO Lift: dump_function_call argument not supported!\n");
            exit(-1);
        }

        // We need to make sure comma is not printed for the last argument
        if (i != (size - 1)) {
            fprintf(file, ",");
        }
    }
}

int dump_expr(FILE *file, ast_expr *expr, void (*current_dump_variable)(FILE *, ast_decl *)) {
    if(expr == NULL) {
        return 0;
    }

    switch(expr->type) {
        case AST_BINARY_EXPR:
            if(expr->binary_expr.op != AST_ASS_OP && expr->binary_expr.op != AST_FASS_OP)
                fprintf(file, "(");
            if(expr->binary_expr.op == AST_ASS_OP && expr->binary_expr.rhs->type == AST_VAR_EXPR
                && expr->binary_expr.lhs->type == AST_VAR_EXPR) {
                dump_expr(file, expr->binary_expr.lhs, dump_variable);
                dump_op(file, expr->binary_expr.op);
                dump_expr(file, expr->binary_expr.rhs, dump_variable);
            }
            else if(expr->binary_expr.op == AST_LSR_OP) {
                dump_expr(file, expr->binary_expr.lhs, dump_unsigned_variable);
                dump_op(file, expr->binary_expr.op);
                dump_expr(file, expr->binary_expr.rhs, dump_variable);
            } else if (expr->binary_expr.op == AST_UDIV_OP || expr->binary_expr.op == AST_LS_OP ||
                       expr->binary_expr.op == AST_HI_OP || expr->binary_expr.op == AST_CC_OP ||
                       expr->binary_expr.op == AST_CS_OP) {
                dump_expr(file, expr->binary_expr.lhs, dump_unsigned_variable);
                dump_op(file, expr->binary_expr.op);
                dump_expr(file, expr->binary_expr.rhs, dump_unsigned_variable);
            } else if(expr->binary_expr.op == AST_LSL_OP) {
                dump_expr(file, expr->binary_expr.lhs, dump_unsigned_variable);
                dump_op(file, expr->binary_expr.op);
                dump_expr(file, expr->binary_expr.rhs, dump_signed_variable);
            } else if(expr->binary_expr.op == AST_FASS_OP) {
                dump_expr(file, expr->binary_expr.lhs, dump_floating_variable);
                dump_op(file, expr->binary_expr.op);
                if(expr->binary_expr.rhs->type == AST_BINARY_EXPR && expr->binary_expr.rhs->binary_expr.op == AST_MAX_OP) {
                  fprintf(file, "fmax(");
                  dump_expr(file, expr->binary_expr.rhs->binary_expr.lhs, dump_floating_variable);
                  fprintf(file, ",");
                  dump_expr(file, expr->binary_expr.rhs->binary_expr.rhs, dump_floating_variable);
                  fprintf(file, ")");
                } else if(expr->binary_expr.rhs->type == AST_BINARY_EXPR && expr->binary_expr.rhs->binary_expr.op == AST_MIN_OP) {
                  fprintf(file, "fmin(");
                  dump_expr(file, expr->binary_expr.rhs->binary_expr.lhs, dump_floating_variable);
                  fprintf(file, ",");
                  dump_expr(file, expr->binary_expr.rhs->binary_expr.rhs, dump_floating_variable);
                  fprintf(file, ")");
                }
                else {
                  dump_expr(file, expr->binary_expr.rhs, dump_floating_variable);
                }
            }
            else {
                dump_expr(file, expr->binary_expr.lhs, current_dump_variable);
                dump_op(file, expr->binary_expr.op);
                dump_expr(file, expr->binary_expr.rhs, current_dump_variable);
            }
            if(expr->binary_expr.op != AST_ASS_OP && expr->binary_expr.op != AST_FASS_OP)
                fprintf(file, ")");
            break;
        case AST_CALL_EXPR:
            if(strcmp(expr->call_expr.function->name, "assert") == 0 ||
            (strstr(expr->call_expr.function->name, "helper") != NULL && strstr(expr->call_expr.function->name, "aarch64") != NULL) ||
            strcmp(expr->call_expr.function->name, "fabs") == 0 ||
            strcmp(expr->call_expr.function->name, "fabsf") == 0 ||
                    strcmp(expr->call_expr.function->name, "sqrt") == 0) {
                fprintf(file, "%s(", expr->call_expr.function->name);
                dump_function_call(file, expr->call_expr.function->arguments, expr->call_expr.function->number_arguments, current_dump_variable, 1);
            } else if(strcmp(expr->call_expr.function->name, "native_call") == 0) {
                fprintf(file, "%s(", expr->call_expr.function->name);
                dump_function_call(file, expr->call_expr.function->arguments, expr->call_expr.function->number_arguments, current_dump_variable, 0);
            } else {
                fprintf(file, "x0 = %s(", expr->call_expr.function->name);
                dump_function_call(file, expr->call_expr.function->arguments, expr->call_expr.function->number_arguments, current_dump_variable, 0);
            }
            fprintf(file, ")");
            break;
        case AST_CAST_EXPR:
            dump_cast_expr(file, expr);
            break;
        case AST_DUP_EXPR:
            if(expr->dup_expr.scalar->type == AST_BINARY_EXPR) {
                dump_expr(file, expr->dup_expr.vector, dump_variable);
                if(expr->dup_expr.vector->var_expr.var->var_decl.type == AST_VAR_VEC128) {
                    fprintf(file, " = vld1q_dup_s%d((const int%d_t*)", expr->dup_expr.element_size, expr->dup_expr.element_size);
                } else {
                    fprintf(file, " = vld1_dup_s%d((const int%d_t*)", expr->dup_expr.element_size, expr->dup_expr.element_size);
                }
                dump_expr(file, expr->dup_expr.scalar, dump_variable);
                fprintf(file, ")");
            } else {
                dump_expr(file, expr->dup_expr.vector, dump_variable);
                if(expr->dup_expr.vector->var_expr.var->var_decl.type == AST_VAR_VEC128) {
                    fprintf(file, " = vdupq_n_s%d(", expr->dup_expr.element_size);
                } else {
                    fprintf(file, " = vdup_n_s%d(", expr->dup_expr.element_size);
                }
                dump_expr(file, expr->dup_expr.scalar, dump_variable);
                fprintf(file, ")");
            }
            break;
        case AST_FP32_EXPR:
            fprintf(file, expr->fp32_expr < 0 ? "(%.*ff)" : "%.*ff", DECIMAL_DIG, expr->fp32_expr);
            break;
        case AST_FP64_EXPR:
            fprintf(file, expr->fp64_expr < 0 ? "(%.*lf)" : "%.*lf", DECIMAL_DIG, expr->fp64_expr);
            break;
        case AST_INT32_EXPR:
            fprintf(file, expr->int32_expr < 0 ? "(%d)" : "%d", expr->int32_expr);
            break;
        case AST_UINT32_EXPR:
            fprintf(file, "%uu", expr->uint32_expr);
            break;
        case AST_INT64_EXPR:
            fprintf(file, expr->int64_expr < 0 ? "(%ldl)" : "%ldl", expr->int64_expr);
            break;
        case AST_UINT64_EXPR:
            fprintf(file, "%lulu", expr->uint64_expr);
            break;
        case AST_MEMORY_EXPR:
            dump_memory_expr(file, expr);
            break;
        case AST_UNARY_EXPR:
            fprintf(file, "(");
            dump_op(file, expr->unary_expr.op);
            dump_expr(file, expr->unary_expr.expr, current_dump_variable);
            fprintf(file, ")");
            break;
        case AST_VAR_EXPR:
            current_dump_variable(file, expr->var_expr.var);
            break;
        case AST_VEC_EXPR:
            dump_expr(file, expr->vec_expr.v0, dump_variable);
            if(expr->vec_expr.op == AST_ADD_OP) {
                fprintf(file, " = vadd");
            } else if(expr->vec_expr.op == AST_SUB_OP) {
                fprintf(file, " = vsub");
            } else if(expr->vec_expr.op == AST_MUL_OP) {
                fprintf(file, " = vmul");
            }  else if(expr->vec_expr.op == AST_AND_OP) {
                fprintf(file, " = vand");
            } else if(expr->vec_expr.op == AST_ORR_OP) {
                fprintf(file, " = vorr");
            } else if(expr->vec_expr.op == AST_EOR_OP) {
                fprintf(file, " = veor");
            } else if(expr->vec_expr.op == AST_EQ_OP) {
                fprintf(file, " = vceq");
            } else if(expr->vec_expr.op == AST_CS_OP) {
                fprintf(file, " = vcgt");
            } else if(expr->vec_expr.op == AST_CC_OP) {
                fprintf(file, " = vclt");
            } else if(expr->vec_expr.op == AST_GE_OP) {
                fprintf(file, " = vcge");
            } else if(expr->vec_expr.op == AST_GT_OP) {
                fprintf(file, " = vcgt");
            } else if(expr->vec_expr.op == AST_LT_OP) {
                fprintf(file, " = vclt");
            } else if(expr->vec_expr.op == AST_HI_OP) {
                fprintf(file, " = vcge");
            } else if(expr->vec_expr.op == AST_MAX_OP) {
                fprintf(file, " = vmax");
            } else if(expr->vec_expr.op == AST_UMAX_OP) {
                fprintf(file, " = vmax");
            } else if(expr->vec_expr.op == AST_MIN_OP) {
                fprintf(file, " = vmin");
            } else if(expr->vec_expr.op == AST_UMIN_OP) {
                fprintf(file, " = vmin");
            } else if(expr->vec_expr.op == AST_BSL_OP) {
                fprintf(file, " = vbsl");
            } else if(expr->vec_expr.op == AST_ANDC_OP) {
                fprintf(file, " = vbic");
            } else if(expr->vec_expr.op == AST_ORC_OP) {
                fprintf(file, " = vorn");
            } else if(expr->vec_expr.op == AST_ASR_OP) {
                fprintf(file, " = vshr");
            } else if(expr->vec_expr.op == AST_LSR_OP) {
                fprintf(file, " = vshr");
            } else if(expr->vec_expr.op == AST_LSL_OP) {
                fprintf(file, " = vshl");
            } else if(expr->vec_expr.op == AST_SLSL_OP) {
                fprintf(file, " = vshl");
            } else if(expr->vec_expr.op == AST_ABS_OP) {
                fprintf(file, " = vabs");
            } else if(expr->vec_expr.op == AST_NEG_OP) {
                fprintf(file, " = vneg");
            } else if(expr->vec_expr.op == AST_NOT_OP) {
                fprintf(file, " = vmvn");
            } else {
                fprintf(stderr, "vec_expr failed %d\n", expr->vec_expr.op);
                exit(-1);
            }
            assert(expr->vec_expr.v0->type == AST_VAR_EXPR);
            if(expr->vec_expr.v0->var_expr.var->var_decl.type == AST_VAR_VEC128) {
                fprintf(file, "q");
            }
            if(expr->vec_expr.v2 != NULL && expr->vec_expr.v2->type == AST_INT32_EXPR) {
                fprintf(file, "_n");
            }

            if(expr->vec_expr.op == AST_LSR_OP || expr->vec_expr.op == AST_UMIN_OP || expr->vec_expr.op == AST_LSL_OP
                || expr->vec_expr.op == AST_HI_OP || expr->vec_expr.op == AST_CS_OP || expr->vec_expr.op == AST_UMAX_OP) {
                fprintf(file, "_u%d(", expr->vec_expr.element_size);
            } else {
                fprintf(file, "_s%d(", expr->vec_expr.element_size);
            }

            dump_expr(file, expr->vec_expr.v1, dump_variable);
            if(expr->vec_expr.v2 != NULL) {
                fprintf(file, ", ");
                dump_expr(file, expr->vec_expr.v2, dump_variable);
            }
            if(expr->vec_expr.v3 != NULL) {
                fprintf(file, ", ");
                dump_expr(file, expr->vec_expr.v3, dump_variable);
            }
            fprintf(file, ")");
            break;
        case AST_STRING_EXPR:
            dump_string(file, expr->string_expr);
            break;
        case AST_TERNARY_CONDITIONAL_EXPR:
            dump_expr(file, expr->ternary_conditional_expr.cond, dump_variable);
            fprintf(file, " ? ");
            dump_expr(file, expr->ternary_conditional_expr.true_expr, dump_variable);
            fprintf(file, " : ");
            dump_expr(file, expr->ternary_conditional_expr.false_expr, dump_variable);
            break;
        default:
            fprintf(stderr, "Lift: Unimplemented expression type in dump_expr!\n");
            exit(-1);
    }
}

static void dump_stmt(FILE *file, ast_stmt *stmt, mambo_ht_t *functions, uint32_t depth) {
    while (stmt != NULL) {
        switch (stmt->type) {
            case AST_BREAK_STMT:
                print_tabs(file, depth);
                fprintf(file, "break;\n");
                break;
            case AST_EXPR_STMT:
                print_tabs(file, depth);
                dump_expr(file, stmt->expr_stmt, dump_variable);
                fprintf(file, ";\n");
                break;
            case AST_CONDITIONAL_GOTO_STMT:
                if(stmt->conditional_goto_stmt.cond == NULL) {
                    print_tabs(file, depth);
                    if(stmt->conditional_goto_stmt.taken != NULL) {
                        fprintf(file, "goto L%p;\n", stmt->conditional_goto_stmt.taken);
                    } else {
                        fprintf(file, "assert(0);\n");
                    }
                }
                else {
                    /*if(stmt->conditional_goto_stmt.cond->type == AST_UNARY_EXPR && stmt->conditional_goto_stmt.cond->unary_expr.expr->type != AST_UNARY_EXPR) {
                        fprintf(file, "assert(!brcond.s == ");
                        dump_expr(file, stmt->conditional_goto_stmt.cond, dump_variable);
                        fprintf(file, ");\n");
                    } else {
                        fprintf(file, "assert(brcond.s == ");
                        dump_expr(file, stmt->conditional_goto_stmt.cond, dump_variable);
                        fprintf(file, ");\n");
                    }*/
                    print_tabs(file, depth);
                    fprintf(file, "if(");
                    dump_expr(file, stmt->conditional_goto_stmt.cond, dump_variable);
                    fprintf(file, ") {\n");
                    print_tabs(file, depth + 1);
                    fprintf(file, "goto L%p;\n", stmt->conditional_goto_stmt.taken);
                    print_tabs(file, depth);
                    fprintf(file, "}\n");
                    if(stmt->conditional_goto_stmt.skipped != NULL) {
                        print_tabs(file, depth);
                        fprintf(file, "else {\n");
                        print_tabs(file, depth + 1);
                        fprintf(file, "goto L%p;\n", stmt->conditional_goto_stmt.skipped);
                        print_tabs(file, depth);
                        fprintf(file, "}\n");
                    } else {
                        if(options.asserts && !stmt->conditional_goto_stmt.allow_fall_through) {
                            print_tabs(file, depth);
                            fprintf(file, "else {\n");
                            print_tabs(file, depth + 1);
                            fprintf(file, "assert(0);\n");
                            print_tabs(file, depth);
                            fprintf(file, "}\n");
                        }
                    }
                }
                break;
            case AST_IF_ELSE_STMT:
                print_tabs(file, depth);
                fprintf(file, "if(");
                dump_expr(file, stmt->if_else_stmt.cond, dump_variable);
                fprintf(file, ") {\n");
                dump_stmt(file, stmt->if_else_stmt.if_body, functions, depth + 1);
                print_tabs(file, depth);
                fprintf(file, "}\n");
                if (stmt->if_else_stmt.else_body != NULL) {
                    print_tabs(file, depth);
                    fprintf(file, "else {\n");
                    dump_stmt(file, stmt->if_else_stmt.else_body, functions, depth + 1);
                    print_tabs(file, depth);
                    fprintf(file, "}\n");
                }
                break;
            case AST_INDIRECT_GOTO_STMT:
                print_tabs(file, depth);
                if(stmt->indirect_goto_stmt.number_jumps == 0) {
                        fprintf(file, "assert(0);\n");
                        break;
                }
                if(!options.asserts && stmt->indirect_goto_stmt.number_jumps == 1) {
                    if(stmt->indirect_goto_stmt.is_call) {
                        ast_function *function = NULL;
                        mambo_ht_get_nolock(functions, (uintptr_t) stmt->indirect_goto_stmt.jumps[0], (void *) (&function));
                        fprintf(file, "x0 = %s(", function->name);
                        dump_function_call(file, function->arguments, function->number_arguments, dump_variable, 0);
                        fprintf(file, ");\n");
                    } else {
                        fprintf(file, "goto L%p;\n", stmt->indirect_goto_stmt.jumps[0]);
                    }
                    break;
                }
                uint64_t base = 0;
                fprintf(file, "switch(");
                dump_expr(file, stmt->indirect_goto_stmt.cond, dump_variable);
                fprintf(file, " - (intptr_t) &__executable_start) {\n");
                for(int idx = 0; idx < stmt->indirect_goto_stmt.number_jumps; idx++) {
                    print_tabs(file, depth + 1);
                    fprintf(file, "case 0x%lx:\n", (uint64_t) stmt->indirect_goto_stmt.jumps[idx] - base);
                    print_tabs(file, depth + 2);
                    if(stmt->indirect_goto_stmt.is_call) {
                        ast_function *function = NULL;
                        mambo_ht_get_nolock(functions, (uintptr_t) stmt->indirect_goto_stmt.jumps[idx], (void *) (&function));
                        if(function == NULL || function->name == NULL)
                          fprintf(file, "x0 = wrong(");
                        else {
                          fprintf(file, "x0 = %s(", function->name);
                          dump_function_call(file, function->arguments, function->number_arguments, dump_variable, 0);
                        }
                        fprintf(file, ");\n");
                        print_tabs(file, depth + 2);
                        fprintf(file, "break;\n");
                    } else {
                        fprintf(file, "goto L%p;\n", stmt->indirect_goto_stmt.jumps[idx]);
                    }
                }
                if(options.asserts) {
                    print_tabs(file, depth + 1);
                    fprintf(file, "default:\n");
                    print_tabs(file, depth + 2);
                    fprintf(file, "assert(0);\n");
                }
                print_tabs(file, depth);
                fprintf(file, "}\n");
                break;
            case AST_LABEL_STMT:
                fprintf(file, "L%p:\n", stmt->label_stmt.addr);
                // TODO: This needs to go before create call, so old state is copied into new without race cond.
                /*for(int i = 0; i < 32; i++) {
                    if(taddrs[i] == stmt->label_stmt.addr) {
                        print_tabs(file, depth);
                        fprintf(file, ";\n");

                        print_tabs(file, 1);
                        fprintf(file, "sp.s = (int64_t) aligned_alloc(64, MAX_STACK_SIZE);\n");
                        print_tabs(file, 1);
                        fprintf(file, "env.s = (int64_t) aligned_alloc(64, MAX_ENV_SIZE);\n");
                        fprintf(file, "\n");

                        print_tabs(file, 1);
                        fprintf(file, "sp.u = ((uint64_t) sp.u + MAX_STACK_SIZE);\n");

                        break;
                    }
                }*/
                break;
            case AST_RETURN_STMT:
                if(stmt->return_stmt.ret != NULL) {
                    print_tabs(file, depth);
                    fprintf(file, "free((void*) (sp.s - MAX_STACK_SIZE));\n");
                    print_tabs(file, depth);
                    fprintf(file, "free((void*) env.s);\n");
                }
                print_tabs(file, depth);
                fprintf(file, "return ");
                if(stmt->return_stmt.ret != NULL) {
                    dump_expr(file, stmt->return_stmt.ret, dump_variable);
                } else {
                    fprintf(file, "(pair) {.a = x0, .b = x1}");
                }
                fprintf(file, ";\n");
                break;
            case AST_WHILE_STMT:
                print_tabs(file, depth);
                fprintf(file, "while(");
                dump_expr(file, stmt->while_stmt.cond, dump_variable);
                fprintf(file, ") {\n");
                dump_stmt(file, stmt->while_stmt.body, functions, depth + 1);
                print_tabs(file, depth);
                fprintf(file, "}\n");
                break;
            default:
                fprintf(stderr, "Lift: Unimplemented statement type %d in dump_stmt!\n", stmt->type);
                exit(-1);
        }
        stmt = stmt->next;
    }
}

static void dump_function_arguments(FILE *file, ast_expr** arguments, uint32_t size) {
    for(int i = 0; i < size; i++) {
        if (arguments[i]->type == AST_VAR_EXPR) {
            dump_variable_definition(file, arguments[i]->var_expr.var);
        }

        // We need to make sure comma is not printed for the last argument
        if (i != (size - 1)) {
            fprintf(file, ",");
        }
    }
}

static void dump_variables_definitions(FILE* file, symbol_table* vars, ast_var_type type, ast_var_scope scope, int depth, bool non_static) {
    bool is_first = 1, is_printed = 0;

    iterate_symbol_table(ast_decl, vars)
    {
        if(val->var_decl.scope != scope || val->var_decl.type != type) {
            continue;
        }

        if(is_first) {
            print_tabs(file, depth);
            if((scope == AST_VAR_REG_GLOBAL || scope == AST_VAR_MAP) && !non_static) {
                if(options.longjmps) {
                    // fprintf(file, "static ");
                }
            }
            dump_variable_type(file, type);
            is_first = 0;
        }

        if(non_static) {
            if((val->var_decl.symbol[0] == 'x' && val->var_decl.symbol[2] == '\0' && val->var_decl.symbol[1] - 48 <= 7 && val->var_decl.symbol[1] - 48 >= 0) || strcmp(val->var_decl.symbol, "sp") == 0 || strcmp(val->var_decl.symbol, "env") == 0) {
                if(is_printed) {
                    fprintf(file, ", ");
                }
                fprintf(file, "%s", val->var_decl.symbol);
                is_printed = 1;
            }
        } else {
            if(!((val->var_decl.symbol[0] == 'x' && val->var_decl.symbol[2] == '\0' && val->var_decl.symbol[1] - 48 <= 7 && val->var_decl.symbol[1] - 48 >= 0) || strcmp(val->var_decl.symbol, "sp") == 0 || strcmp(val->var_decl.symbol, "env") == 0)) {
                if(is_printed) {
                    fprintf(file, ", ");
                }
                fprintf(file, "%s", val->var_decl.symbol);
                is_printed = 1;
            }
        }

        if(val->var_decl.initial_value != NULL) {
            fprintf(file, " = ");
            dump_expr(file, val->var_decl.initial_value, dump_variable);
        }
    }
    iterate_symbol_table_end()

    if(!is_first) {
        fprintf(file, ";\n");
    }
}

static void dump_function(FILE* file, mambo_ht_t* functions, ast_function* function, symbol_table* global_vars, ast_translation_unit* translation_unit) {
    if(strcmp(function->name, "main") == 0) {
        fprintf(file, "int %s(", function->name);
        fprintf(file, "int argc, char** argv");
    } else {
        if(function->is_callback) {
            fprintf(file, "pair %s(", function->name);
        } else {
            fprintf(file, "static pair %s(", function->name);
        }
        dump_function_arguments(file, function->arguments, function->number_arguments);
    }
    fprintf(file, ") {\n");

    // Main function has to preload the original binary and map global data
    if(strcmp(function->name, "main") == 0) {
        print_tabs(file, 1);
        if(options.longjmps) {
            fprintf(file, "static ");
        }
        for(int i = 0; i <= 8; i ++) {
            print_tabs(file, 1);
            fprintf(file, "int64_var x%d;\n", i);
        }

        print_tabs(file, 1);
        fprintf(file, "int64_var sp;\n");
        print_tabs(file, 1);
        fprintf(file, "int64_var env;\n");

        print_tabs(file, 1);
        fprintf(file, "sp.s = (int64_t) aligned_alloc(64, MAX_STACK_SIZE);\n");
        //if(symbol_table_lookup(global_vars, "env") != NULL) {
        print_tabs(file, 1);
        fprintf(file, "env.s = (int64_t) aligned_alloc(64, MAX_ENV_SIZE);\n");
        //}
        fprintf(file, "\n");

        iterate_symbol_table(ast_decl, global_vars)
        {
            if(val->var_decl.scope == AST_VAR_MAP) {
                // print_tabs(file, 1);
                // fprintf(file, "%s.s = get_base_addr(\"%s\");\n", val->var_decl.symbol, val->var_decl.object);
            }
        }
        iterate_symbol_table_end()

        fprintf(file, "\n");

        print_tabs(file, 1);
        fprintf(file, "sp.u = ((uint64_t) sp.u + MAX_STACK_SIZE);\n");
        print_tabs(file, 1);
        fprintf(file, "x0.s = argc;\n");
        print_tabs(file, 1);
        fprintf(file, "x1.u = (uint64_t) argv;\n");

        for(int i = 0; i < translation_unit->num_ctr; i++) {
            ast_function *function = NULL;
            mambo_ht_get_nolock(translation_unit->function_table, translation_unit->constructors[i], (void *) (&function));
            fprintf(file, "%s(", function->name);
            dump_function_call(file, function->arguments, function->number_arguments, dump_signed_variable, 0);
            fprintf(file, ");\n");
        }

        for(int i = 0; i < translation_unit->num_cb; i++) {
            ast_function *function = NULL;
            mambo_ht_get_nolock(translation_unit->function_table, (uintptr_t) translation_unit->callbacks[i], (void *) (&function));

            // TODO: See comment in trampoline generation.
            if(strstr(function->name, "frame_dummy") != NULL) {
                continue;
            }

            fprintf(file, "mprotect((uintptr_t) &trampoline_0x%lx_addr & (uintptr_t) 0xfffffffffffff000, 16, PROT_EXEC);\n", translation_unit->callbacks[i]);
        }
    }

    fprintf(file, "\n");

    // Dump local variable
    if(function->local_vars != NULL) {
        dump_variables_definitions(file, function->local_vars, AST_VAR_INT32, AST_VAR_TEMP_LOCAL, 1, 0);
        dump_variables_definitions(file, function->local_vars, AST_VAR_INT64, AST_VAR_TEMP_LOCAL, 1, 0);
        dump_variables_definitions(file, function->local_vars, AST_VAR_VEC64, AST_VAR_TEMP_LOCAL, 1, 0);
        dump_variables_definitions(file, function->local_vars, AST_VAR_VEC128, AST_VAR_TEMP_LOCAL, 1, 0);
        dump_variables_definitions(file, function->local_vars, AST_VAR_INT32, AST_VAR_STACK_LOCAL, 1, 0);
        dump_variables_definitions(file, function->local_vars, AST_VAR_INT64, AST_VAR_STACK_LOCAL, 1, 0);
    }

    for(int i = 9; i <= 29; i ++) {
        print_tabs(file, 1);
        fprintf(file, "int64_var x%d;\n", i);
    }

    print_tabs(file, 1);
    fprintf(file, "int32_var NF;\n");
    print_tabs(file, 1);
    fprintf(file, "int32_var ZF;\n");
    print_tabs(file, 1);
    fprintf(file, "int32_var VF;\n");
    print_tabs(file, 1);
    fprintf(file, "int32_var CF;\n");
    print_tabs(file, 1);
    fprintf(file, "int64_var lr;\n");
    print_tabs(file, 1);
    fprintf(file, "int64_var pc;\n");
    print_tabs(file, 1);
    fprintf(file, "int64_var lhs;\n");
    print_tabs(file, 1);
    fprintf(file, "int64_var rhs;\n");
    print_tabs(file, 1);
    fprintf(file, "pair ret;\n");

    dump_stmt(file, function->body, functions, 1);

    fprintf(file, "}\n\n");
}

void convert_ast_to_code(FILE* file, ast_translation_unit* translation_unit) {
    // Dump preamble
    fprintf(file, "//\n");
    fprintf(file, "// This file was generated automatically by MAMBO Lift\n");
    fprintf(file, "//\n\n");

    // Dump definitions of variables types
    fprintf(file, "// Definitions of variables types\n\n");
    fprintf(file, "typedef union int32_var {\n    int32_t s;\n    uint32_t u;\n    float f;\n} int32_var;\n\n");
    fprintf(file, "typedef union int64_var {\n    int64_t s;\n    uint64_t u;\n    double f;\n} int64_var;\n\n");

    // Dump emulated stack and env size
    fprintf(file, "// Emulated stack and env size\n\n");
    fprintf(file, "#define MAX_STACK_SIZE (1 << 24)\n"); // Maximum stack 8912 kbytes
    fprintf(file, "#define MAX_ENV_SIZE (1 << 14)\n\n"); // Maximum state 16 kbytes

    if(options.longjmps) {
        // Dump setjmp/longjmp save space
        fprintf(file, "// Setjmp/Longjmp save space\n");
        fprintf(file, "#define MAX_JMP_SAVE_SIZE (4096 * 4096)\n\n"); // Maximum 32 setjmps supported
        fprintf(file, "char save[MAX_JMP_SAVE_SIZE] __attribute__ ((aligned (64)));\n\n");
    } else {
        fprintf(file, "char save[0] __attribute__ ((aligned (64)));\n\n");
    }

    // Dump global variables
    fprintf(file, "// Global variables\n\n");

    if(translation_unit->global_vars != NULL) {
        dump_variables_definitions(file, translation_unit->global_vars, AST_VAR_INT64, AST_VAR_MAP, 0, 0);
    }

    for(int i = 0; i < translation_unit->num_cb; i++) {
        fprintf(file, "extern char trampoline_0x%lx_addr;\n", translation_unit->callbacks[i]);
    }

    fprintf(file, "int64_var ");
    for(int i = 0; i < 64; i++) {
      fprintf(file, "d%d, ", i);
    }
    fprintf(file, "junk;\n\n");

    fprintf(file, "\n");

    // Dump emulation data structure
    fprintf(file, "// Wrapper for returned values from the function\n\n");

    fprintf(file, "typedef struct pair {\n");
    print_tabs(file, 1);
    fprintf(file, "int64_var a;\n");
    print_tabs(file, 1);
    fprintf(file, "int64_var b;\n");
    fprintf(file, "} pair;\n\n");

    // Dump functions declarations
    fprintf(file, "// Functions declarations\n\n");

    iterate_mambo_hashmap(ast_function, translation_unit->function_table)
    {
        if(strcmp("main", val->name) == 0) {
            continue;
        }

        if(val->is_callback) {
            fprintf(file, "pair %s(", val->name);
        } else {
            fprintf(file, "static pair %s(", val->name);
        }
        dump_function_arguments(file, val->arguments, val->number_arguments);
        fprintf(file, ");\n");
    }
    iterate_mambo_hashmap_end()

    fprintf(file, "\n");

    // Dump functions definitions
    fprintf(file, "// Functions\n\n");

    gvars = translation_unit->global_vars;

    iterate_mambo_hashmap(ast_function, translation_unit->function_table)
    {
        dump_function(file, translation_unit->function_table, val, translation_unit->global_vars, translation_unit);
    }
    iterate_mambo_hashmap_end()
}

void generate_trampolines(FILE* file, ast_translation_unit* translation_unit) {

    iterate_mambo_hashmap(ast_function, translation_unit->function_table)
    {
        if(val->is_callback) {
            fprintf(file, ".global %s_trampoline\n", val->name);
            fprintf(file, "#ifdef HAVE_AS_FUNC\n");
            fprintf(file, ".func %s_trampoline\n", val->name);
            fprintf(file, "#endif\n");
            fprintf(file, ".type %s_trampoline, %%function\n", val->name);

            fprintf(file, "%s_trampoline:\n", val->name);
            fprintf(file, "    stp x29, x30, [sp, #-16]!\n");
            fprintf(file, "    mov x29, sp\n");
            fprintf(file, "    stp x8, x29, [sp, #-48]!\n");
            fprintf(file, "    str xzr, [sp, #16]\n");
            fprintf(file, "    bl %s\n", val->name);
            fprintf(file, "    add sp, sp, #48\n");
            fprintf(file, "    ldp x29, x30, [sp], #16\n");
            fprintf(file, "    ret\n");

            fprintf(file, "#ifdef HAVE_AS_FUNC\n");
            fprintf(file, ".endfunc\n");
            fprintf(file, "#endif\n\n");
        }
    }
    iterate_mambo_hashmap_end()
}

void generate_linker_trampolines(FILE* file, ast_translation_unit* translation_unit) {


    for(int i = 0; i < translation_unit->num_cb; i++) {
        ast_function *function = NULL;
        mambo_ht_get_nolock(translation_unit->function_table, (uintptr_t) translation_unit->callbacks[i], (void *) (&function));

        char addr_str[128];
        sprintf(addr_str, "%p", (void*) translation_unit->callbacks[i]); 

        // TODO: We need a better implementation here e.g., a smaller trampoline. For now remove known functions that are too
        // small to replace, and we know we don't need them.
        if(strstr(function->name, "frame_dummy") != NULL) {
            continue;
        }

        fprintf(file, "  . = __executable_start + 0x%lx;\n", translation_unit->callbacks[i]);
        fprintf(file, "  trampoline_0x%lx_addr = __executable_start + 0x%lx;\n", translation_unit->callbacks[i], translation_unit->callbacks[i]);
        fprintf(file, "  .trampoline_0x%lx :\n", translation_unit->callbacks[i]);
        fprintf(file, "  {\n");
        if(strstr(options.trampolines, addr_str) != NULL) {
            fprintf(file, "    LONG(0xd65f03c0)\n");
        } else {
            fprintf(file, "    LONG(0x10000090)\n");
            fprintf(file, "    LONG(0xf9400211)\n");
            fprintf(file, "    LONG(0x8b110210)\n");
            fprintf(file, "    LONG(0xd61f0200)\n");
            fprintf(file, "    QUAD(__executable_start + %s_trampoline - trampoline_0x%lx_addr - 16);\n", function->name, translation_unit->callbacks[i]);
        }
        fprintf(file, "  }\n");
    }
}
