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

#include <stddef.h>

#include "cfg.h"

void initialize_node(cfg_node* node) {
    node->start_addr = 0x0;
    node->end_addr = 0x0;
    node->edges = NULL;
    node->type = CFG_BASIC_BLOCK;
    node->order_id = -1;
    node->visited = 0;
    node->in_degree = 0;
    node->profile = CFG_NODE_COLD;
    node->stmts.head = NULL;
    node->stmts.tail = NULL;
    node->branch_reg = -1;
    node->calls = NULL;
    node->function_id = -1;
    node->native_function_name = NULL;
    node->linked = 1;
    node->original_function = 0;
}

void initialize_edge(cfg_edge* edge, cfg_edge_type type) {
    edge->node = NULL;
    edge->next = NULL;
    edge->type = type;
    edge->taken_count = 0;
}
