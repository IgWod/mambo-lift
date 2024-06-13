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

#include "ast_utils.h"

void free_ast_stmt(ast_stmt* stmt) {
    while (stmt != NULL) {
        switch (stmt->type) {
            case AST_EXPR_STMT:
                free_ast_expr(stmt->expr_stmt);
                free(stmt->expr_stmt);
                break;
            case AST_CONDITIONAL_GOTO_STMT:
                free_ast_expr(stmt->conditional_goto_stmt.cond);
                free(stmt->conditional_goto_stmt.cond);
                break;
            case AST_IF_ELSE_STMT:
                free_ast_expr(stmt->if_else_stmt.cond);
                free_ast_stmt(stmt->if_else_stmt.if_body);
                free_ast_stmt(stmt->if_else_stmt.else_body);
                free(stmt->if_else_stmt.cond);
                free(stmt->if_else_stmt.if_body);
                free(stmt->if_else_stmt.else_body);
                break;
            case AST_RETURN_STMT:
                free_ast_expr(stmt->return_stmt.ret);
                free(stmt->return_stmt.ret);
                break;
            case AST_WHILE_STMT:
                free_ast_expr(stmt->while_stmt.cond);
                free_ast_stmt(stmt->while_stmt.body);
                free(stmt->while_stmt.cond);
                free(stmt->while_stmt.body);
                break;
            case AST_INDIRECT_GOTO_STMT:
                free_ast_expr(stmt->indirect_goto_stmt.cond);
                free(stmt->indirect_goto_stmt.cond);
                break;
            case AST_LABEL_STMT:
            case AST_BREAK_STMT:
                break;
            default:
                fprintf(stderr, "MAMBO Lift: Unsupported stmt type in free_ast_stmt!\n");
                exit(-1);
        }
        stmt = stmt->next;
    }
}

void free_ast_expr(ast_expr* expr) {
    switch(expr->type) {
        case AST_BINARY_EXPR:
            free_ast_expr(expr->binary_expr.lhs);
            free_ast_expr(expr->binary_expr.rhs);
            free(expr->binary_expr.lhs);
            free(expr->binary_expr.rhs);
            break;
        case AST_MEMORY_EXPR:
            free_ast_expr(expr->memory_expr.addr);
            free(expr->memory_expr.addr);
            break;
        case AST_STRING_EXPR:
            free(expr->string_expr);
            break;
        case AST_UNARY_EXPR:
            free_ast_expr(expr->unary_expr.expr);
            free(expr->unary_expr.expr);
            break;
        case AST_TERNARY_CONDITIONAL_EXPR:
            free_ast_expr(expr->ternary_conditional_expr.cond);
            free_ast_expr(expr->ternary_conditional_expr.true_expr);
            free_ast_expr(expr->ternary_conditional_expr.false_expr);
            free(expr->ternary_conditional_expr.cond);
            free(expr->ternary_conditional_expr.true_expr);
            free(expr->ternary_conditional_expr.false_expr);
            break;
        case AST_CAST_EXPR:
            free_ast_expr(expr->cast_expr.expr);
            free(expr->cast_expr.expr);
            break;
        case AST_DUP_EXPR:
            free_ast_expr(expr->dup_expr.vector);
            free_ast_expr(expr->dup_expr.scalar);
            free(expr->dup_expr.vector);
            free(expr->dup_expr.scalar);
            break;
        case AST_VEC_EXPR:
            free_ast_expr(expr->vec_expr.v0);
            free_ast_expr(expr->vec_expr.v1);
            free_ast_expr(expr->vec_expr.v2);
            if(expr->vec_expr.v2 != NULL) {
                free_ast_expr(expr->vec_expr.v2);
            }
            if(expr->vec_expr.v3 != NULL) {
                free_ast_expr(expr->vec_expr.v3);
            }
            free(expr->vec_expr.v0);
            free(expr->vec_expr.v1);
            free(expr->vec_expr.v2);
            if(expr->vec_expr.v2 != NULL) {
                free(expr->vec_expr.v2);
            }
            if(expr->vec_expr.v3 != NULL) {
                free(expr->vec_expr.v3);
            }
            break;
        case AST_CALL_EXPR:
        case AST_FP32_EXPR:
        case AST_FP64_EXPR:
        case AST_INT64_EXPR:
        case AST_INT32_EXPR:
        case AST_UINT32_EXPR:
        case AST_VAR_EXPR:
        case AST_UINT64_EXPR:
            break;
        default:
            fprintf(stderr, "MAMBO Lift: Unsupported expr type %d in free_ast_expr!\n", expr->type);
            exit(-1);
    }
}
