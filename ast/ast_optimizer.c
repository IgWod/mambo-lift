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

#include <stdio.h>
#include <string.h>

#include "cfg/cfg.h"
#include "ast/ast_utils.h"
#include "ast/symbol_table.h"
#include "utils/hashmap_utils.h"

#include "ast_optimizer.h"

// HELPERS

static void reset_vars_values(symbol_table* global_vars, symbol_table* local_vars) {
    iterate_symbol_table(ast_decl, global_vars)
    {
        val->var_decl.use_def = NULL;
        val->var_decl.stmt = NULL;
        val->var_decl.written = 0;
        val->var_decl.accessed = 0;
    }
    iterate_symbol_table_end()

    iterate_symbol_table(ast_decl, local_vars)
    {
        val->var_decl.use_def = NULL;
        val->var_decl.stmt = NULL;
        val->var_decl.written = 0;
        val->var_decl.accessed = 0;
    }
    iterate_symbol_table_end()
}

// WEAK PROPAGATION

// This function performs the actual propagation where any variable with the simple (constant or another variable) value
// is replaced with that value.
static bool weak_propagate_var(ast_expr* expr) {
    if(expr->var_expr.var->var_decl.use_def == NULL) {
        return false;
    }

    ast_expr_type type = expr->var_expr.var->var_decl.use_def->type;

    switch(type) {
        case AST_FP32_EXPR:
            expr->type = AST_FP32_EXPR;
            expr->fp32_expr = expr->var_expr.var->var_decl.use_def->fp32_expr;
            break;
        case AST_FP64_EXPR:
            expr->type = AST_FP64_EXPR;
            expr->fp64_expr = expr->var_expr.var->var_decl.use_def->fp64_expr;
            break;
        case AST_INT32_EXPR:
            expr->type = AST_INT32_EXPR;
            expr->int32_expr = expr->var_expr.var->var_decl.use_def->int32_expr;
            break;
        case AST_UINT32_EXPR:
            expr->type = AST_UINT32_EXPR;
            expr->uint32_expr = expr->var_expr.var->var_decl.use_def->uint32_expr;
            break;
        case AST_INT64_EXPR:
            expr->type = AST_INT64_EXPR;
            expr->int64_expr = expr->var_expr.var->var_decl.use_def->int64_expr;
            break;
        case AST_UINT64_EXPR:
            expr->type = AST_UINT64_EXPR;
            expr->uint64_expr = expr->var_expr.var->var_decl.use_def->uint64_expr;
            break;
        case AST_STRING_EXPR:
            expr->type = AST_STRING_EXPR;
            expr->string_expr = expr->var_expr.var->var_decl.use_def->string_expr;
            break;
        case AST_VAR_EXPR:
            // TODO: Doesn't produce correct results
            // expr->var_expr.var = expr->var_expr.var->var_decl.use_def->var_expr.var;
            break;
        default:
            return false;
    }

    return true;
}

// Function recursively looks for the variables in the expression and when found it attempts to perform the propagation.
static bool weak_propagate_expr(ast_expr* expr) {
    switch (expr->type) {
        case AST_BINARY_EXPR:
            return weak_propagate_expr(expr->binary_expr.lhs) | weak_propagate_expr(expr->binary_expr.rhs);
        case AST_MEMORY_EXPR:
            return weak_propagate_expr(expr->memory_expr.addr);
        case AST_UNARY_EXPR:
            return weak_propagate_expr(expr->unary_expr.expr);
        case AST_VAR_EXPR:
            return weak_propagate_var(expr);
        case AST_CAST_EXPR:
            return weak_propagate_expr(expr->cast_expr.expr);
        default:
            return false;
    }
}

// The function picks up an expression in the form of x = expr_stmt, recursively propagates the expression, and saves the
// value of x. We rely on the fact that only the statements in form of x = expression can modify the value of x within
// a single basic block.
static bool weak_propagate_stmt(ast_stmt* stmt) {
    if(stmt->type != AST_EXPR_STMT) {
        return false;
    }

    ast_expr* expr = stmt->expr_stmt;

    if(expr->type == AST_BINARY_EXPR && (expr->binary_expr.op == AST_ASS_OP || expr->binary_expr.op == AST_FASS_OP) && expr->binary_expr.lhs->type == AST_VAR_EXPR) {
        bool code_updated = weak_propagate_expr(expr->binary_expr.rhs);

        ast_expr* var_expr = expr->binary_expr.lhs;
        if(var_expr->var_expr.var->var_decl.scope == AST_VAR_TEMP_LOCAL) {
            var_expr->var_expr.var->var_decl.use_def = expr->binary_expr.rhs;
        }

        return code_updated;
    }

    return false;
}

// Weak propagate performs constant and copy propagation on TCG temps. TCG Temps are only used within a single basic
// block (although their scope is function, the construction of the TCG guarantees that none of the temp variables will
// outlive the basic block), so we can simply propagate them down the basic block. Without those assumptions a data-
// flow analysis on the CFG on the function needs to be performed. The function returns true if any optimization
// has been done.
static bool weak_propagate(ast_translation_unit *translation_unit, ast_stmt* stmt, symbol_table* local_vars) {
#if MLDEBUG >= 2
    printf("weak_propagate: propagating TCG temps in function %s\n", function->decl->function_decl.name);
#endif
    bool code_updated = false;

    while(stmt != NULL) {
        switch (stmt->type) {
            case AST_EXPR_STMT:
                code_updated |= weak_propagate_stmt(stmt);
                break;
            case AST_LABEL_STMT:
                reset_vars_values(translation_unit->global_vars, local_vars);
                break;
            default:
                break;
        }

        stmt = stmt->next;
    }

    return code_updated;
}

// CONSTANT FOLDING

// Generic implementation that can fold two constants of the same type. This implementation is far from the ideal, but
// with lack of support for generics in C it has to be implemented with macro.
#define fold(VAR_TYPE, EXPR_TYPE, FIELD) {                                                                  \
    VAR_TYPE lhs = expr->binary_expr.lhs->FIELD;                                                            \
    VAR_TYPE rhs = expr->binary_expr.rhs->FIELD;                                                            \
                                                                                                            \
    free_ast_expr(expr);                                                                                    \
                                                                                                            \
    expr->type = (EXPR_TYPE);                                                                               \
                                                                                                            \
    switch(expr->binary_expr.op) {                                                                          \
        case AST_ADD_OP:                                                                                    \
            expr->FIELD = lhs + rhs;                                                                        \
            break;                                                                                          \
        case AST_AND_OP:                                                                                    \
            expr->FIELD = lhs & rhs;                                                                        \
            break;                                                                                          \
        default:                                                                                            \
            fprintf(stderr, "MAMBO Lift: Cannot fold constants with operator %d!\n", expr->binary_expr.op); \
            exit(-1);                                                                                       \
    }                                                                                                       \
                                                                                                            \
    return true;                                                                                            \
}

// For the given binary expression we check if both sides of it are constants of the same type, and if that is true
// we pass them to the folding macro.
static bool constant_folding_binary_expr(ast_expr *expr) {
    if (expr->binary_expr.lhs->type == AST_INT64_EXPR && expr->binary_expr.rhs->type == AST_INT64_EXPR) {
        fold(int64_t, AST_INT64_EXPR, int64_expr)
    }

    if (expr->binary_expr.lhs->type == AST_INT32_EXPR && expr->binary_expr.rhs->type == AST_INT32_EXPR) {
        fold(int32_t, AST_INT32_EXPR, int32_expr)
    }

    return false;
}

// Function finds binary expressions and attempts the constant folding. If folding fails it attempts to recursively
// process the expression in the case where the expression consists of other nested expressions. The function skips
// any non-foldable expressions.
static bool constant_folding_expr(ast_expr* expr) {
    switch(expr->type) {
        case AST_BINARY_EXPR:
            if(constant_folding_binary_expr(expr)) {
                return true;
            } else {
                return constant_folding_expr(expr->binary_expr.lhs) | constant_folding_expr(expr->binary_expr.rhs);
            }
        case AST_CAST_EXPR:
            return constant_folding_expr(expr->cast_expr.expr);
        case AST_MEMORY_EXPR:
            return constant_folding_expr(expr->memory_expr.addr);
        case AST_UNARY_EXPR:
            return constant_folding_expr(expr->unary_expr.expr);
        default:
            return false;
    }
}

// The constant folding optimization simply finds all binary expressions processing two constants of the same type and
// replaces them with a result of evaluating the statement.
static bool constant_folding(ast_stmt* stmt) {
#if MLDEBUG >= 2
    printf("constant_folding: constant folding in function %s\n", function->decl->function_decl.name);
#endif
    bool code_updated = false;

    while(stmt != NULL) {
        if(stmt->type == AST_EXPR_STMT) {
            code_updated |= constant_folding_expr(stmt->expr_stmt);
        }

        stmt = stmt->next;
    }

    return code_updated;
}

// SEMANTIC DEAD CODE ELIMINATION

static void remove_stmt(ast_stmt* stmt, ast_stmt_list* list) {
    if (stmt->prev != NULL) {
        stmt->prev->next = stmt->next;
    } else {
        list->head = stmt->next;
    }
    if (stmt->next != NULL) {
        stmt->next->prev = stmt->prev;
    } else {
        list->tail = stmt->prev;
    }
}

// In the generated code we do not use LR and PC lifted through QEMU, so we can remove statements changing or accessing
// them.
static void semantic_dce(ast_stmt_list* list) {
#if MLDEBUG >= 2
    printf("semantic_dce: semantic dead code elimination\n");
#endif
    ast_stmt* stmt = list->head;

    while(stmt != NULL) {
        if(stmt->type == AST_EXPR_STMT) {
            ast_expr* expr = stmt->expr_stmt;

            if(expr->type == AST_BINARY_EXPR && expr->binary_expr.op == AST_ASS_OP) {
                ast_expr* rlhs[2] = {expr->binary_expr.lhs, expr->binary_expr.rhs};

                for(int idx = 0; idx < 2; idx++) {
                    if (rlhs[idx]->type == AST_VAR_EXPR && strcmp(rlhs[idx]->var_expr.var->var_decl.symbol, "pc") == 0) {
                        remove_stmt(stmt, list);
                        break;
                    }
                }
            }
        }

        stmt = stmt->next;
    }
}

// WEAK DEAD CODE ELIMINATION

// Descent into any expression and mark variables used there as accessed.
static bool weak_dce_expr(ast_expr* expr) {
    switch (expr->type) {
        case AST_BINARY_EXPR:
            weak_dce_expr(expr->binary_expr.rhs);
            weak_dce_expr(expr->binary_expr.lhs);
            break;
        case AST_MEMORY_EXPR:
            weak_dce_expr(expr->memory_expr.addr);
            break;
        case AST_UNARY_EXPR:
            weak_dce_expr(expr->unary_expr.expr);
            break;
        case AST_VAR_EXPR:
            expr->var_expr.var->var_decl.accessed = 1;
            break;
        case AST_CAST_EXPR:
            weak_dce_expr(expr->cast_expr.expr);
            break;
        case AST_TERNARY_CONDITIONAL_EXPR:
            weak_dce_expr(expr->ternary_conditional_expr.cond);
            weak_dce_expr(expr->ternary_conditional_expr.true_expr);
            weak_dce_expr(expr->ternary_conditional_expr.false_expr);
            break;
        case AST_DUP_EXPR:
            weak_dce_expr(expr->dup_expr.scalar);
            weak_dce_expr(expr->dup_expr.vector);
            break;
        case AST_VEC_EXPR:
            weak_dce_expr(expr->vec_expr.v0);
            weak_dce_expr(expr->vec_expr.v1);
            weak_dce_expr(expr->vec_expr.v2);
            if(expr->vec_expr.v3 != NULL) weak_dce_expr(expr->vec_expr.v3);
            break;
        default:
            break;
    }
}

static void weak_dce(ast_translation_unit *translation_unit, ast_stmt_list* list, symbol_table* local_vars) {
#if MLDEBUG >= 2
    printf("weak_dce: weak dead code elimination in function %s\n", function->decl->function_decl.name);
#endif
    ast_stmt* stmt = list->head;

    while(stmt != NULL) {
        switch (stmt->type) {
            case AST_LABEL_STMT:
                reset_vars_values(translation_unit->global_vars, local_vars);
                break;
            case AST_EXPR_STMT:
                if(stmt->expr_stmt->type == AST_BINARY_EXPR && stmt->expr_stmt->binary_expr.op == AST_ASS_OP) {
                    weak_dce_expr(stmt->expr_stmt->binary_expr.rhs);

                    ast_expr* lhs = stmt->expr_stmt->binary_expr.lhs;

                    if(lhs->type == AST_VAR_EXPR) {
                        if(lhs->var_expr.var->var_decl.scope == AST_VAR_TEMP_LOCAL &&
                        lhs->var_expr.var->var_decl.written && !lhs->var_expr.var->var_decl.accessed) {
                            remove_stmt(lhs->var_expr.var->var_decl.stmt, list);
                        }

                        lhs->var_expr.var->var_decl.written = 1;
                        lhs->var_expr.var->var_decl.accessed = 0;
                        lhs->var_expr.var->var_decl.stmt = stmt;
                    }

                    if(lhs->type == AST_MEMORY_EXPR) {
                        weak_dce_expr(stmt->expr_stmt->binary_expr.lhs);
                    }
                } else if(stmt->expr_stmt->type == AST_DUP_EXPR || stmt->expr_stmt->type == AST_VEC_EXPR) {
                    weak_dce_expr(stmt->expr_stmt);
                }
                break;
            default:
                break;
        }

        stmt = stmt->next;
    }

    iterate_symbol_table(ast_decl, local_vars)
    {
        if(val->var_decl.scope == AST_VAR_TEMP_LOCAL && val->var_decl.written && !val->var_decl.accessed) {
            remove_stmt(val->var_decl.stmt, list);
        }
    }
    iterate_symbol_table_end()
}

// FP PROMOTION

static ast_decl *get_or_create_var(symbol_table *globals_vars, uint32_t reg_no, ast_var_type type) {

    symbol_table *vars = globals_vars;

    char name[8];
    snprintf(name, 8, "d%d", reg_no); 

    ast_decl *decl = (ast_decl *) symbol_table_lookup(vars, name);

    if (decl == NULL) {
        decl = build_var_decl(strdup(name), type);

        symbol_table_check_insert(vars, name, (void *) decl);

        decl->var_decl.scope = AST_VAR_REG_GLOBAL;
    }

    return decl;
}

static bool fp_promote_expr(ast_expr* expr, symbol_table* global_vars) {
    switch (expr->type) {
        case AST_MEMORY_EXPR:
            if(expr->memory_expr.addr->type == AST_BINARY_EXPR) {
              ast_expr *address = expr->memory_expr.addr;
              if(address->binary_expr.lhs->type == AST_VAR_EXPR && strcmp(address->binary_expr.lhs->var_expr.var->var_decl.symbol, "env") == 0) {
                if(address->binary_expr.rhs->type == AST_UINT64_EXPR) {
                  uint32_t reg_no = address->binary_expr.rhs->uint64_expr - 3088;
                  if(reg_no % 256 == 0) {
                    reg_no /= 256;
                    ast_decl* decl = get_or_create_var(global_vars, reg_no, expr->memory_expr.type + 1);
                    expr->type = AST_VAR_EXPR;
                    expr->var_expr.var = decl;
                  } else {
                    reg_no /= 256;
                    reg_no += 32;
                    ast_decl* decl = get_or_create_var(global_vars, reg_no, expr->memory_expr.type + 1);
                    expr->type = AST_VAR_EXPR;
                    expr->var_expr.var = decl;
                  }
                }
              }
            }
            break;
        case AST_BINARY_EXPR:
              if(expr->binary_expr.lhs->type == AST_VAR_EXPR && strcmp(expr->binary_expr.lhs->var_expr.var->var_decl.symbol, "env") == 0) {
                if(expr->binary_expr.rhs->type == AST_UINT64_EXPR) {
                  uint32_t reg_no = expr->binary_expr.rhs->uint64_expr - 3088;
                  if(reg_no == (11976 - 3088)) {
                    ;
                  } else if(reg_no % 256 == 0) {
                    reg_no /= 256;
                    ast_decl* decl = get_or_create_var(global_vars, reg_no, expr->memory_expr.type + 1);
                    expr->type = AST_UNARY_EXPR;
                    expr->unary_expr.op = AST_AND_OP;
                    expr->unary_expr.expr = build_var_expr(decl);
                  } else {
                    reg_no /= 256;
                    reg_no += 32;
                    ast_decl* decl = get_or_create_var(global_vars, reg_no, expr->memory_expr.type + 1);
                    expr->type = AST_UNARY_EXPR;
                    expr->unary_expr.op = AST_AND_OP;
                    expr->unary_expr.expr = build_var_expr(decl);
                  }
                }
              }
            break;
        default:
            break;
    }
}

static void fp_promote(ast_translation_unit *translation_unit, ast_stmt_list* list, symbol_table* local_vars) {
#if MLDEBUG >= 2
    printf("weak_dce: weak dead code elimination in function %s\n", function->decl->function_decl.name);
#endif
    ast_stmt* stmt = list->head;

    while(stmt != NULL) {
        switch (stmt->type) {
            case AST_EXPR_STMT:
                if(stmt->expr_stmt->type == AST_BINARY_EXPR && stmt->expr_stmt->binary_expr.op == AST_ASS_OP) {
                    fp_promote_expr(stmt->expr_stmt->binary_expr.lhs, translation_unit->global_vars);
                    fp_promote_expr(stmt->expr_stmt->binary_expr.rhs, translation_unit->global_vars);
                }
                break;
            default:
                break;
        }

        stmt = stmt->next;
    }
}

// TOP LEVEL FUNCTION

void optimize_ast(ast_translation_unit *translation_unit) {
#if MLDEBUG >= 1
    printf("optimize_ast: optimizing code in function %s\n", function->decl->function_decl.name);
#endif
    iterate_mambo_hashmap(ast_function, translation_unit->function_table)
    {
        for(int block_idx = 0; block_idx < val->number_basic_blocks; block_idx++) {
            // ast_stmt* head = val->basic_blocks[block_idx]->stmts.head;

            // TODO: Currently broken needs fixing
            // semantic_dce(&val->basic_blocks[block_idx]->stmts);

            // TODO: Currently broken needs fixing
            // while (weak_propagate(translation_unit, head, val->local_vars) || constant_folding(head));
            // weak_propagate(translation_unit, head, val->local_vars);

            // TODO: Currently broken needs fixing
            // weak_dce(translation_unit, &val->basic_blocks[block_idx]->stmts, val->local_vars);

            // TODO: Currently broken needs fixing
            // fp_promote(translation_unit, &val->basic_blocks[block_idx]->stmts, val->local_vars);
        }
    }
    iterate_mambo_hashmap_end()
}
