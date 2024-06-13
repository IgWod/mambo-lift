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

#pragma once

#include "unicorn/lift.h"

#include "ast/ast_list.h"

/**
 * Function translates QEMU TCG representation into mambo AST IR, so it can be further process and converted into C.
 *
 * @param ctx TCG Context containing the TCG code to be processed
 * @param stmts Linked list where new AST statements are appended to
 * @param local_vars Symbol table to store local variables
 * @param global_vars Symbol table to store global variables
 */
void translate_tcg_to_ast(TCGContext *ctx, ast_stmt_list *stmts, symbol_table *local_vars, symbol_table *global_vars);
