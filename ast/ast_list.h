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

#include "../common/typedefs.h"

#include "ast.h"

// STRUCTS

/**
 * Structure holding beginning (head) and end (tail) of a linked list.
 */
struct ast_stmt_list {
    ast_stmt *head;
    ast_stmt *tail;
};

// FUNCTIONS

/**
 * Append statement to the linked list of statements. It is assumed neither the list nor the new element are NULL.
 *
 * @param list Linked list to append to
 * @param element Element to append
 */
void append_to_stmt_list(ast_stmt_list *list, ast_stmt *element);

/**
 * Prepend statement to the linked list of statements. It is assumed neither the list nor the new element are NULL.
 *
 * @param list Linked list to prepend to
 * @param element Element to prepend
 */
void prepend_to_stmt_list(ast_stmt_list *list, ast_stmt *element);

/**
 * Make the given element head and tail of the list. Effectively this creates a new list of length 1. It is assumed
 * list it not NULL.
 *
 * @param list List to be initialize
 * @param element Statement to be used for initialization
 */
void initialize_stmt_list(ast_stmt_list *list, ast_stmt *element);

/**
 * Check if both head and tail are NULL. It is assumed list it not NULL.
 *
 * @param list List to check
 * @return True if both head and tail are NULL and false otherwise
 */
bool is_stmt_list_empty(ast_stmt_list *list);

/**
 * Append linked list pointed by src to the linked list pointed by dest. After the operation the src list remains
 * unchanged, and dest holds the result of the operation. It is assumed neither dest nor src are NULL.
 *
 * @param list1 List to be appended to
 * @param list2 List to append
 */
void concatenate_stmt_lists(ast_stmt_list *dest, ast_stmt_list *src);
