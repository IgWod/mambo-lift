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
 * TODO: Fix descritpion. It's not correct now.
 * Build a list of functions from the control-flow graph. Function starts from the main function and follows all
 * function calls recursively and build the list. This can be thought as a traversal of the call graph of the
 * application. The head/source of the graph is main function.
 *
 * Note: The function does not clear the visited flag!
 *
 * @param cfg TODO: Add
 * @param main First basic block of the main function
 * @return List of functions in the form of a linked list
 */
cfg_node_linked_list* extract_functions(mambo_ht_t* cfg, uintptr_t* entries, size_t num);

/**
 * Recover addresses of the static branches and patch function calls to use calls field. For example the function
 * produces:
 *
 * BB0
 *  |
 * BB1 -> foo
 *  |
 * BB2
 *
 * Rather than:
 *
 * BB0
 *  |
 * BB1
 *  |
 * foo
 *  |
 * ...
 *  |
 * BB2
 *
 * @param cfg Hash map with all nodes in the control flow graph
 * @param binary TODO
 */
void recover_branch_targets(mambo_ht_t* cfg, char* binary);

/**
 * Replace source code address of basic blocks stored in the edges of control-flow graph with pointers to actual
 * nodes, e.g., replace integer number 0x400748 with the pointer to cfg_node struct ({..., start_address=0x400748,...}).
 *
 * @param cfg Hash map with the nodes of the control flow graph
 * @param binary TODO
 */
void replace_addresses_with_nodes(mambo_ht_t* cfg, char* binary);

/**
 * Function promotes any indirect jumps that are most likely a function call through a lookup table to an actual call
 * and updates the list of function if any new function was discovered. More detailed explanation below.
 *
 * In some cases it in the control flow it may appear that the function is jumped to in the middle (surely it would
 * violate ABI and all stack stuff), e.g.,
 *
 *  BB0
 *   |
 * fcall
 *   |
 *  BB1
 *   |
 *  BB2
 *   |
 * indir
 *   |
 *  BB3 <-- fcall -- BB5
 *   |
 *  BB4
 *
 * In this example BB0 calls function starting in BB1, and also BB5 calls the same function (BB1) but jumps in the
 * middle of it. This may seems like an error, but with more detailed examination we can notice that:
 *
 * 1) BB1 has a corresponding symbol named `func1`
 * 2) BB3 has a corresponding symbol named `func2`
 * 3) BB5 does a standard `BL`
 * 4) BB2 jumps using `BR`
 *
 * For this we can infer that in fact `indir` (indirect jump) is in fact an indirect function call and this CFG has two
 * functions not only one, and the ambiguity occurs because function BB1 uses a jump table to call function BB3, and
 * compiler generate simple `BR` that obscures this is a function call. We could probably assume that any indirect jump
 * to the block that is called by other parts of the CFG with `BL/BLR` is also a function call.
 *
 * @param cfg Hash table with all nodes in the control flow graph
 * @param list List of all discovered functions
 */
void promote_indirect_branches_to_calls(mambo_ht_t* cfg, cfg_node_linked_list* list);

/**
 * This function promotes branches that cross functions boundary to function calls.
 *
 * For example:
 *     BB0
 *      |
 * BB2-BB1-BB6
 *  |   |
 * BB3  |
 *  |   |
 * BB4-BB5
 *  |
 *
 * Let's now assume BB3 to BB4 edges is a function call, and all other edges are non-calling branches. So now BB5 to
 * BB1 edge jumps in between two function which is behavior that should not occur. One of the solution is to make BB1
 * a head of a new function and make edges from BB5 and BB0 a function call.
 *
 * @param cfg Hash table with all nodes in the control flow graph
 * @param list List of all discovered functions
 */
void promote_inter_function_branches_to_calls(mambo_ht_t* cfg, cfg_node_linked_list* list);

// TODO: Add description
// Sometimes the function never continues, but we always set edges to the next address. This function removes this spurious edge.
void remove_fall_through_edges(mambo_ht_t* cfg);

// TODO: Description
// Unconditional static branch crossing functions boundary needs fixing
void extract_functions_on_b(mambo_ht_t* cfg, cfg_node_linked_list* list);

void rerank_function(cfg_node* cfg);

void prune_leaves(cfg_node_linked_list *functions, cfg_node* node);

void static_recover(mambo_ht_t* cfg, char* binary);
