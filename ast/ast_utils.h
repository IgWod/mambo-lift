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

#pragma once

#include "ast.h"

// FUNCTIONS

/**
 * Iteratively and then recursively free a content of a single statement or a content of linked of statements starting
 * at stmt. The given statement (or a list) itself is not freed.
 *
 * @param stmt Head of the linked list or a single statement
 */
void free_ast_stmt(ast_stmt* stmt);

/**
 * Recursively free the expression. The expression itself is not freed.
 *
 * @param expr Expression to free
 */
void free_ast_expr(ast_expr* expr);
