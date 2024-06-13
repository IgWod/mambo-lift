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
#include <stdio.h>

#include "cfg_utils.h"
#include "../utils/print_utils.h"

#include "cfg_print.h"

#define _HIGHLIGHT_TYPE ///< Color nodes depending on their type
// #define _HIGHLIGHT_HOTNESS ///< Highlight nodes that form part of the trace
#define _PRINT_ID ///< Print order id (when the node executed for the first time) and function_id alongside node's address

/*
 * Recursively print CFG in the .dot format.
 */
void print_graph_dfs(FILE *file, cfg_node *node, uint32_t depth) {
    node->visited = 1;

    void *from_address = node->start_addr;

#ifdef _HIGHLIGHT_TYPE
    print_tabs(file, depth);
    if (node->type & CFG_CONDITIONAL_BLOCK) {
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"yellow\"];\n", from_address);
    } else if (node->type & CFG_SVC) {
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"purple\"];\n", from_address);
    } else if (node->type & CFG_FUNCTION_CALL) {
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"red\"];\n", from_address);
    } else if (node->type & CFG_RETURN) {
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"grey\"];\n", from_address);
    } else if (node->type & CFG_INDIRECT_BLOCK) {
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"blue\"];\n", from_address);
    } else if (node->type & CFG_NATIVE_CALL) {
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"orange\"];\n", from_address);
    } else {
        fprintf(file, "\"%p\";\n", from_address);
    }
#endif

#ifdef _HIGHLIGHT_HOTNESS
    if(node->profile == CFG_NODE_HOT_HEAD || node->profile == CFG_NODE_HOT) {
        print_tabs(file, depth);
        fprintf(file, "\"%p\" [style=\"filled\", fillcolor=\"red\"];\n", from_address);
    }
#endif

#ifdef _PRINT_ID
    print_tabs(file, depth);
    fprintf(file, "\"%p\" [label=\"%p (%lu, %lu)\"];\n", from_address, from_address, node->order_id, node->function_id);
#endif

    cfg_edge *edge = node->edges;

    if(node->type == CFG_RETURN) {
        edge = NULL;
    }

    while (edge != NULL) {

        cfg_node *next_node = edge->node;

        print_tabs(file, depth);
        fprintf(file, "\"%p\" -> \"%p\";\n", from_address, next_node->start_addr);

        if (next_node->visited == 0) {
            print_graph_dfs(file, next_node, depth);
        }

        edge = edge->next;
    }

    // Print dashed lines to functions that are called by the node.
    cfg_edge *func = node->calls;
    while (func != NULL && func->node != NULL) {
        print_tabs(file, depth);
        fprintf(file, "\"%p\" -> \"%p\" [style=dashed];\n", node->start_addr, func->node->start_addr);
        func = func->next;
    }
}

void print_graph(FILE *file, cfg_node_linked_list *functions) {
    cfg_node_linked_list *functions_iter = functions;
    fprintf(file, "strict digraph cfg {\n");
    while (functions_iter != NULL) {
        print_graph_dfs(file, functions_iter->node, 1);
        clear_visited_flags(functions_iter->node);
        functions_iter = functions_iter->next;
    }
    fprintf(file, "}\n");
}
