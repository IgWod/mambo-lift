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

#include "ast_list.h"

void append_to_stmt_list(ast_stmt_list* list, ast_stmt* element){
    assert(list != NULL && element != NULL);

    list->tail->next = element;
    element->prev = list->tail;
    list->tail = element;
}

void prepend_to_stmt_list(ast_stmt_list* list, ast_stmt* element) {
    assert(list != NULL && element != NULL);

    list->head->prev = element;
    element->next = list->head;
    list->head = element;
}

void initialize_stmt_list(ast_stmt_list *list, ast_stmt *element) {
    assert(list != NULL);

    list->head = element;
    list->tail = element;
}

bool is_stmt_list_empty(ast_stmt_list *list) {
    assert(list != NULL);

    return list->head == NULL && list->tail == NULL;
}

void concatenate_stmt_lists(ast_stmt_list *dest, ast_stmt_list *src) {
    assert(dest != NULL && src != NULL);

    dest->tail->next = src->head;
    src->head->prev = dest->tail;
    dest->tail = src->tail;
}
