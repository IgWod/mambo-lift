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
 * Print CFG of the applications from the given list of functions. The output is in the .dot format that can be viewed
 * with:
 *
 * dot -Tpng cfg.dot > cfg.png
 *
 * @param file Destination where to write the CFG
 * @param functions Linked list of first the first node of each function
 */
void print_graph(FILE* file, cfg_node_linked_list *functions);
