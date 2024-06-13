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

#include "ast.h"

ast_decl* build_var_decl(char* symbol, ast_var_type type) {
    ast_decl* var_decl = (ast_decl*) malloc(sizeof(ast_decl));
    var_decl->type = AST_VAR_DECL;

    var_decl->var_decl.symbol= symbol;
    var_decl->var_decl.type = type;
    var_decl->var_decl.scope = AST_VAR_NOSCOPE;

    var_decl->var_decl.use_def = NULL;
    var_decl->var_decl.stmt = NULL;

    var_decl->var_decl.written = 0;
    var_decl->var_decl.accessed = 0;

    var_decl->var_decl.initial_value = NULL;

    return var_decl;
}

ast_expr* build_binary_expr(ast_expr* lhs, ast_op op, ast_expr* rhs) {
    ast_expr* binary_expr = (ast_expr*) malloc(sizeof(ast_expr));
    binary_expr->type = AST_BINARY_EXPR;

    binary_expr->binary_expr.lhs = lhs;
    binary_expr->binary_expr.op = op;
    binary_expr->binary_expr.rhs = rhs;

    return binary_expr;
}

ast_expr* build_call_expr(ast_function* function) {
    ast_expr* call_expr = (ast_expr*) malloc(sizeof(ast_expr));
    call_expr->type = AST_CALL_EXPR;

    call_expr->call_expr.function = function;

    return call_expr;
}

ast_expr* build_cast_expr(ast_expr* expr, ast_cast_type type) {
    ast_expr* cast_expr = (ast_expr*) malloc(sizeof(ast_expr));
    cast_expr->type = AST_CAST_EXPR;

    cast_expr->cast_expr.expr = expr;
    cast_expr->cast_expr.type = type;

    return cast_expr;
}

ast_expr* build_dup_expr(ast_expr* vector, ast_expr* scalar, int size) {
    ast_expr* dup_expr = (ast_expr*) malloc(sizeof(ast_expr));
    dup_expr->type = AST_DUP_EXPR;

    dup_expr->dup_expr.vector = vector;
    dup_expr->dup_expr.scalar = scalar;
    dup_expr->dup_expr.element_size = size;

    return dup_expr;
}

ast_expr* build_fp32_expr(float value) {
    ast_expr* fp32_expr = (ast_expr*) malloc(sizeof(ast_expr));
    fp32_expr->type = AST_FP32_EXPR;

    fp32_expr->fp32_expr = value;

    return fp32_expr;
}

ast_expr* build_fp64_expr(double value) {
    ast_expr* fp64_expr = (ast_expr*) malloc(sizeof(ast_expr));
    fp64_expr->type = AST_FP64_EXPR;

    fp64_expr->fp64_expr = value;

    return fp64_expr;
}

ast_expr* build_int32_expr(int32_t value) {
    ast_expr* int32_expr = (ast_expr*) malloc(sizeof(ast_expr));
    int32_expr->type = AST_INT32_EXPR;

    int32_expr->int32_expr = value;

    return int32_expr;
}

ast_expr* build_uint32_expr(uint32_t value) {
    ast_expr* uint32_expr = (ast_expr*) malloc(sizeof(ast_expr));
    uint32_expr->type = AST_UINT32_EXPR;

    uint32_expr->uint32_expr = value;

    return uint32_expr;
}

ast_expr* build_int64_expr(int64_t value) {
    ast_expr* int64_expr = (ast_expr*) malloc(sizeof(ast_expr));
    int64_expr->type = AST_INT64_EXPR;

    int64_expr->int64_expr = value;

    return int64_expr;
}

ast_expr* build_uint64_expr(uint64_t value) {
    ast_expr* uint64_expr = (ast_expr*) malloc(sizeof(ast_expr));
    uint64_expr->type = AST_UINT64_EXPR;

    uint64_expr->uint64_expr = value;

    return uint64_expr;
}

ast_expr* build_memory_expr(ast_expr* addr, ast_ldst_size size, ast_ldst_type type, uint8_t element_size) {
    ast_expr* memory_expr = (ast_expr*) malloc(sizeof(ast_expr));
    memory_expr->type = AST_MEMORY_EXPR;

    memory_expr->memory_expr.addr = addr;

    memory_expr->memory_expr.size = size;
    memory_expr->memory_expr.type = type;

    memory_expr->memory_expr.element_size = element_size;

    memory_expr->memory_expr.lv = NULL;

    return memory_expr;
}

ast_expr* build_ternary_conditional_expr(ast_expr* cond, ast_expr* true_expr, ast_expr* false_expr) {
    ast_expr* ternary_expr = (ast_expr*) malloc(sizeof(ast_expr));
    ternary_expr->type = AST_TERNARY_CONDITIONAL_EXPR;

    ternary_expr->ternary_conditional_expr.cond = cond;
    ternary_expr->ternary_conditional_expr.true_expr = true_expr;
    ternary_expr->ternary_conditional_expr.false_expr = false_expr;

    return ternary_expr;
}

ast_expr* build_string_expr(char* value) {
    ast_expr* string_expr = (ast_expr*) malloc(sizeof(ast_expr));
    string_expr->type = AST_STRING_EXPR;

    string_expr->string_expr = value;

    return string_expr; 
}

ast_expr* build_unary_expr(ast_op op, ast_expr* expr) {
    ast_expr* unary_expr = (ast_expr*) malloc(sizeof(ast_expr));
    unary_expr->type = AST_UNARY_EXPR;

    unary_expr->unary_expr.op = op;
    unary_expr->unary_expr.expr = expr;

    return unary_expr;    
}

ast_expr* build_var_expr(ast_decl* var) {
    ast_expr* var_expr = (ast_expr*) malloc(sizeof(ast_expr));
    var_expr->type = AST_VAR_EXPR;

    var_expr->var_expr.var = var;

    return var_expr;
}

ast_expr* build_vec_expr(ast_expr* v0, ast_expr* v1, ast_expr* v2, ast_op op, int size) {
    ast_expr* vec_expr = (ast_expr*) malloc(sizeof(ast_expr));
    vec_expr->type = AST_VEC_EXPR;

    vec_expr->vec_expr.v0 = v0;
    vec_expr->vec_expr.v1 = v1;
    vec_expr->vec_expr.v2 = v2;
    vec_expr->vec_expr.v3 = NULL;
    vec_expr->vec_expr.op = op;
    vec_expr->vec_expr.element_size = size;

    return vec_expr;
}

ast_function* build_function(char* symbol) {
    ast_function* function = (ast_function*) malloc(sizeof(ast_function));

    function->name = symbol;

    function->number_arguments = 0;
    function->body = NULL;
    function->index = -1;
    function->basic_blocks = NULL;
    function->number_basic_blocks = 0;
    function->is_callback = 0;

    return function;
}

ast_stmt* build_break_stmt() {
    ast_stmt* break_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    break_stmt->type = AST_BREAK_STMT;

    break_stmt->prev = NULL;
    break_stmt->next = NULL;

    return break_stmt;
}

ast_stmt* build_expr_stmt(ast_expr* expr) {
    ast_stmt* expr_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    expr_stmt->type = AST_EXPR_STMT;

    expr_stmt->expr_stmt = expr;

    expr_stmt->prev = NULL;
    expr_stmt->next = NULL;

    return expr_stmt;
}

ast_stmt* build_conditional_goto_stmt(ast_expr* cond, void* taken, void* skipped) {
    ast_stmt* goto_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    goto_stmt->type = AST_CONDITIONAL_GOTO_STMT;

    goto_stmt->conditional_goto_stmt.cond = cond;
    goto_stmt->conditional_goto_stmt.taken = taken;
    goto_stmt->conditional_goto_stmt.skipped = skipped;

    goto_stmt->conditional_goto_stmt.allow_fall_through = 0;

    goto_stmt->prev = NULL;
    goto_stmt->next = NULL;

    return goto_stmt;
}

ast_stmt* build_if_else_stmt(ast_expr* cond, ast_stmt* if_body, ast_stmt* else_body) {
    ast_stmt* if_else_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    if_else_stmt->type = AST_IF_ELSE_STMT;

    if_else_stmt->if_else_stmt.cond = cond;
    if_else_stmt->if_else_stmt.if_body = if_body;
    if_else_stmt->if_else_stmt.else_body = else_body;

    if_else_stmt->prev = NULL;
    if_else_stmt->next = NULL;

    return if_else_stmt;
}

ast_stmt* build_indirect_goto_stmt(ast_expr* cond) {
    ast_stmt* goto_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    goto_stmt->type = AST_INDIRECT_GOTO_STMT;

    goto_stmt->indirect_goto_stmt.cond = cond;
    goto_stmt->indirect_goto_stmt.number_jumps = 0;
    goto_stmt->indirect_goto_stmt.is_call = false;

    goto_stmt->prev = NULL;
    goto_stmt->next = NULL;

    return goto_stmt;
}

ast_stmt* build_label_stmt(void* addr) {
    ast_stmt* label_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    label_stmt->type = AST_LABEL_STMT;

    label_stmt->label_stmt.addr = addr;

    label_stmt->prev = NULL;
    label_stmt->next = NULL;

    return label_stmt;
}

ast_stmt* build_return_stmt(ast_expr* ret) {
    ast_stmt* return_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    return_stmt->type = AST_RETURN_STMT;

    return_stmt->return_stmt.ret = ret;

    return_stmt->prev = NULL;
    return_stmt->next = NULL;

    return return_stmt;
}

ast_stmt* build_while_stmt(ast_expr* cond, ast_stmt* body) {
    ast_stmt* while_stmt = (ast_stmt*) malloc(sizeof(ast_stmt));
    while_stmt->type = AST_WHILE_STMT;

    while_stmt->while_stmt.cond = cond;
    while_stmt->while_stmt.body = body;

    while_stmt->prev = NULL;
    while_stmt->next = NULL;

    return while_stmt;
}

ast_translation_unit* build_translation_unit(void* main_addr, char* binary) {
    ast_translation_unit* translation_unit =
        (ast_translation_unit*) malloc(sizeof(ast_translation_unit));

    translation_unit->function_table = (mambo_ht_t*) malloc(sizeof(mambo_ht_t));

    mambo_ht_init(translation_unit->function_table, 16, 0, 80, true);

    translation_unit->global_vars = (symbol_table *) malloc(sizeof(symbol_table));

    symbol_table_init(translation_unit->global_vars, 1024 << 4);

    translation_unit->main_addr = main_addr;

    translation_unit->binary = binary;

    return translation_unit;
}

ast_decl* get_or_create_branch_cond(symbol_table* vars_table) {
    ast_decl* decl = (ast_decl*) symbol_table_lookup(vars_table, "brcond");

    if(decl == NULL) {
        decl = build_var_decl("brcond", AST_VAR_INT64);

        symbol_table_check_insert(vars_table, "brcond", (void *) decl);

        decl->var_decl.scope = AST_VAR_TEMP_LOCAL;
    }

    return decl;
}
