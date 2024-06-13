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

#include "ast/ast.h"
#include "cfg/cfg.h"

// TODO: Clean up
extern void** tcalls;
extern void** taddrs;

/**
 *
 * Generate AST IR for each basic block in the list.
 *
 * @param nodes List of nodes to lift
 * @param count Number of nodes in the list
 * @param translation_unit AST IR lifting context
 * @param memory_profiles Addresses accessed by load/store operations (NULL if _COLLECT_MEMORY_PROFILES not defined)
 */
void build_basic_blocks(cfg_node** nodes, uint64_t count, ast_translation_unit *translation_unit, mambo_ht_t *memory_profiles);

/**
 * Connect basic blocks within functions with control flow constructs to create a full application.
 *
 * @param functions List of functions with already build basic blocks
 * @param translation_unit AST IR lifting context.
 */
void build_full_ast(cfg_node_linked_list *functions, ast_translation_unit *translation_unit);
