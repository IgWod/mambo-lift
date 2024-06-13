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

#include "cfg.h"

// FUNCTIONS

/**
 * Recursively clear visited flags in nodes using DFS algorithm.
 *
 * @param head First node in the graph
 */
void clear_visited_flags(cfg_node* head);

/**
 * Count number of CFG nodes reachable from head.
 *
 * @param head First node in the graph
 * @return Number of nodes reachable from head
 */
uint64_t count_cfg_nodes(cfg_node* head);

/**
 * Create a list of nodes reachable from head
 *
 * @param head First node in the graph
 * @param count Number of nodes that should be visited
 * @return List of visited nodes
 */
cfg_node** list_cfg_nodes(cfg_node* head, uint64_t count, FILE* file);

/**
 * Remove nodes from the hashmap where the visited flag is zero.
 *
 * @param ctx MAMBO context
 * @param cfg Hashmap with nodes in the control-flow graph
 */
void remove_unvisited_nodes(mambo_ht_t* cfg);
