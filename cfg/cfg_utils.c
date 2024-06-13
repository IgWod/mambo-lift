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

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

#include "../utils/hashmap_utils.h"

#include "cfg_utils.h"

void clear_visited_flags(cfg_node *head) {
    head->visited = 0;

    cfg_edge *edge = head->edges;

    while (edge != NULL) {

        cfg_node *next_node = edge->node;

        if (next_node->visited == 1) {
            clear_visited_flags(next_node);
        }

        edge = edge->next;
    }
}

/*
 * Reversely count nodes in the graph using DFS.
 */
static uint64_t count_cfg_nodes_dfs(cfg_node *node) {
    if (node->visited == 1) {
        return 0;
    }

    node->visited = 1;

    cfg_edge *edge = node->edges;

    uint64_t count = 0;

    while (edge != NULL) {

        cfg_node *next_node = edge->node;

        count += count_cfg_nodes_dfs(next_node);

        edge = edge->next;
    }

    return count + 1;
}

uint64_t count_cfg_nodes(cfg_node *head) {
    uint64_t count = count_cfg_nodes_dfs(head);
    clear_visited_flags(head);
    return count;
}

/*
 * Recursively list nodes in the graph using DFS.
 */
static void list_cfg_nodes_dfs(cfg_node *node, cfg_node **nodes, uint64_t *index, FILE* file) {
    if (node->visited == 1) {
        return;
    }

    nodes[*index] = node;

    fprintf(file, "%p %p\n", node->start_addr, node->end_addr);

    *index += 1;

    node->visited = 1;

    cfg_edge *edge = node->edges;

    while (edge != NULL) {

        cfg_node *next_node = edge->node;

        list_cfg_nodes_dfs(next_node, nodes, index, file);

        edge = edge->next;
    }
}

cfg_node **list_cfg_nodes(cfg_node *head, uint64_t count, FILE* file) {
    static uint64_t index;

    assert(count > 0);

    cfg_node **nodes = (cfg_node **) malloc(sizeof(cfg_node *) * count);

    index = 0;
    list_cfg_nodes_dfs(head, nodes, &index, file);
    clear_visited_flags(head);

    return nodes;
}

void remove_unvisited_nodes(mambo_ht_t *cfg) {
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        if (val->visited == 0) {
            // TODO: Free the node
            cfg->entries[index].key = 0;
        }
    }
    iterate_mambo_hashmap_end()
}
