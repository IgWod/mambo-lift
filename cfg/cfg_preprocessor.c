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
#include <string.h>

#include "../utils/hashmap_utils.h"

#include "python/python.h"

#include "pie/pie-a64-field-decoder.h"

#include "options.h"

#include "cfg.h"

#include "cfg_preprocessor.h"

extern char* gcode;

static inline uint64_t sign_extend64(unsigned int bits, uint64_t value)
{
    uint64_t C = (-1) << (bits - (uint64_t) 1);
    return (value + C) ^ C;
}

void replace_addresses_with_nodes(mambo_ht_t *cfg, char* binary) {
    int ret;

#if MLDEBUG >= 10
    printf("digraph cfg {\n");
#endif

    for (int index = 0; index < cfg->size; index++) {
        if (cfg->entries[index].key != 0 && cfg->entries[index].key != -1) {
            cfg_node *node = (cfg_node *) cfg->entries[index].value;

            // TODO: Revisit
            char *symbol = NULL;
            get_plt_symbol_by_addr(binary, node->start_addr, &symbol);

            if(symbol != NULL) { // && strstr(symbol, "sqlite3") == NULL) {
                node->edges = NULL;
                node->start_addr = node->start_addr;
                node->end_addr = node->start_addr;
                node->type = CFG_NATIVE_CALL;
                node->native_function_name = symbol;
            }

            cfg_edge *curr = node->edges;
            cfg_edge *prev = NULL;

            while (curr != NULL) {
                // Replace code address of the node with the pointer to the actual node
                ret = mambo_ht_get_nolock(cfg, (uintptr_t) curr->node, (void *) &curr->node);

                // Process case when indirect branch calls library function without PLT. In SPEC x264 function pointer calls
                // __GI___memcpy_falkor using br as a direct call.
                /* if(ret && curr->node != NULL && (node->type & CFG_INDIRECT_BLOCK)) {
                    char *symbol = NULL;
                    get_symbol_info_by_addr((uintptr_t) curr->node, &symbol, NULL, NULL);
                    void* curr_addr = curr->node;
                    curr->node = (cfg_node*) malloc(sizeof(cfg_node));
                    initialize_node(curr->node);
                    if(symbol != NULL) {
                        curr->node->edges = NULL;
                        curr->node->start_addr = curr_addr;
                        curr->node->end_addr = curr_addr;
                        curr->node->type = CFG_NATIVE_CALL;
                        curr->node->native_function_name = symbol;
                        curr->node->linked = 0; // TODO: Make sure this work
                    }
                    ret = 0;
                } */

                if (ret) {
                    // If the node doesn't exist drop the edge, e.g., execution only explored one side of the
                    // conditional branch.
                    if (prev == NULL) {
                        if (curr->next == NULL) {
                            node->edges = NULL;
                            curr = NULL;
                        } else {
                            node->edges = curr->next;
                            curr = curr->next;
                        }
                    } else {
                        prev->next = curr->next;
                        curr = curr->next;
                    }
                } else {
#if MLDEBUG >= 10
                    printf("\t\"%p\" -> \"%p\";\n", node->start_addr, curr->node->start_addr);
#endif
                    if (curr->node->in_degree >= CFG_MAX_IN_NODES) {
                        fprintf(stderr, "MAMBO Lift: Cannot track more previous nodes!\n");
                        exit(-1);
                    }

                    curr->node->prev[curr->node->in_degree++] = node;

                    prev = curr;
                    curr = curr->next;
                }
            }

            if (node->calls != NULL) {
                curr = node->calls;

                // TODO: Revisit
                while (curr != NULL && curr->node != NULL) {
                    cfg_node* tmp_node = NULL;
                    ret = mambo_ht_get_nolock(cfg, (uintptr_t) curr->node, (void *) &tmp_node);

                    if(!ret) {
                        curr->node = tmp_node;
                    } else {
                        tmp_node = (cfg_node*) malloc(sizeof(cfg_node));
                        initialize_node(tmp_node);
                        tmp_node->type = CFG_NATIVE_CALL;
                        tmp_node->start_addr = curr->node;
                        tmp_node->end_addr = tmp_node->start_addr;
                        curr->node = tmp_node;
                    }

                    curr = curr->next;
                }
            }

#if MLDEBUG >= 10
            if(node->edges == NULL) {
                printf("\t\"%p\";\n", node->start_addr);
            }
#endif
        }
    }

#if MLDEBUG >= 10
    printf("}\n");
#endif

    // TODO: Revisit
    for (int index = 0; index < cfg->size; index++) {
        if (cfg->entries[index].key != 0 && cfg->entries[index].key != -1) {
            cfg_node *node = (cfg_node *) cfg->entries[index].value;

            if(node->type & CFG_FUNCTION_CALL && node->calls != NULL && node->calls->node != NULL) {

                // TODO: Revisit
                if(node->calls->node->type == CFG_NATIVE_CALL && node->calls->node->native_function_name != NULL
                && (strcmp(node->calls->node->native_function_name, "exit") == 0 || strcmp(node->calls->node->native_function_name, "pthread_exit") == 0
                                                                                    || strcmp(node->calls->node->native_function_name, "_exit") == 0
                                                                                       || strcmp(node->calls->node->native_function_name, "__stack_chk_fail") == 0
                                                                                          || strstr(node->calls->node->native_function_name, "__throw_") != NULL
                   || strcmp(node->calls->node->native_function_name, "_Unwind_Resume") == 0 || strcmp(node->calls->node->native_function_name, "__cxa_throw_bad_array_new_length") == 0
                  || strcmp(node->calls->node->native_function_name, "_gfortran_runtime_error_at") == 0 || strcmp(node->calls->node->native_function_name, "_gfortran_os_error") == 0
|| strcmp(node->calls->node->native_function_name, "_gfortran_runtime_error") == 0 || strcmp(node->calls->node->native_function_name, "abort") == 0 || strcmp(node->calls->node->native_function_name, "__cxa_throw") == 0|| strcmp(node->calls->node->native_function_name, "_gfortran_stop_string") == 0|| strcmp(node->calls->node->native_function_name, "_gfortran_stop_numeric") == 0 || strcmp(node->calls->node->native_function_name, "fancy_abort") == 0 || strcmp(node->calls->node->native_function_name, "_ZSt20__throw_length_errorPKc") == 0|| strcmp(node->calls->node->native_function_name, "__cxa_rethrow") == 0)) {
                    // TODO: Add _gfortran_stop_string and fix the potentially infinite loop
                    node->edges = NULL;
                }
            }

            if(node->type == CFG_NATIVE_CALL) {
                if(node->in_degree != 0) {
                    node->linked = 0;
                }
            }
        }
    }
}

/*
    Recursively follow all nodes and attach any target of the function call to the list.
*/
void extract_functions_dfs(cfg_node *node, cfg_node_linked_list *list, uint64_t* function_id) {
    node->visited = 1;

    if (node->type & CFG_FUNCTION_CALL) {
        cfg_edge *call = node->calls;
        while (call != NULL && call->node != NULL) {
            // TODO: Revisit

            if (call->node->visited == 0 && !(call->node->type == CFG_NATIVE_CALL && call->node->native_function_name == NULL)) {
                cfg_node_linked_list *new_elem = (cfg_node_linked_list *) malloc(sizeof(cfg_node_linked_list));

                new_elem->node = call->node;
                new_elem->next = NULL;

                while (list->next != NULL) {
                    list = list->next;
                }

                list->next = new_elem;
                list = list->next;

                *function_id += 1;
                call->node->function_id = *function_id;

                extract_functions_dfs(call->node, list, function_id);
            }

            call = call->next;
        }
    }

    cfg_edge *edge = node->edges;

    if(node->type & CFG_RETURN) {
        edge = NULL;
    }

    while (edge != NULL) {

        cfg_node *next_node = edge->node;

        if (next_node->visited == 0) {
            next_node->function_id = node->function_id;
            extract_functions_dfs(next_node, list, function_id);
        }

        edge = edge->next;
    }
}

cfg_node_linked_list *extract_functions(mambo_ht_t* cfg, uintptr_t* entries, size_t num) {
    static uint64_t function_id;

    cfg_node_linked_list *new_elem = (cfg_node_linked_list *) malloc(sizeof(cfg_node_linked_list));

    cfg_node* tmp_node = NULL;
    mambo_ht_get_nolock(cfg, entries[0], (void *) &tmp_node);

    new_elem->node = tmp_node;
    new_elem->next = NULL;

    function_id = 0;
    tmp_node->function_id = function_id;

    extract_functions_dfs(tmp_node, new_elem, &function_id);

    for(int i = 1; i < num; i++) {

        mambo_ht_get_nolock(cfg, (uintptr_t) entries[i], (void *) &tmp_node);

        extract_functions_dfs(tmp_node, new_elem, &function_id);

        cfg_node_linked_list *list = new_elem;
        while (list->node != tmp_node && list->next != NULL) {
            list = list->next;
        }

        if(list->node == tmp_node) {
            continue;
        }

        list->next = (cfg_node_linked_list *) malloc(sizeof(cfg_node_linked_list));

        list = list->next;

        list->node = tmp_node;
        list->next = NULL;
    }

    return new_elem;
}

/*
    Recover static branch targets of basic blocks, and patch function calls and SVCs.
*/
int recover_branch_targets_node(cfg_node *node, char* binary) {
    if (node->type == CFG_SVC) {
        cfg_edge *edge = node->edges;

        // We do not follow SVC, so the next block is directly after the call. We can later use SVC table to replace
        // the SVC call with the appropriate function call.
        edge->node = (cfg_node *) (node->end_addr + 4);
    } else {
        a64_instruction inst_type = a64_decode((uint32_t*)&gcode[(uintptr_t)node->end_addr]);

        unsigned int imm, scratch;
        int64_t offset;
        cfg_edge *taken_edge;

        switch(inst_type) {
            case A64_BLR:
            case A64_BR:
                // Rewind to the first non-zero node
                while(node->edges->node == NULL) {
                    if(node->edges->next == NULL) {
                        break;
                    }
                    node->edges = node->edges->next;
                }
                // Drop zero nodes
                cfg_edge* edge = node->edges;
                cfg_edge* prev = node->edges;
                while(edge->next != NULL) {
                    if(edge->node == NULL) {
                        prev->next = edge->next;
                    } else {
                        prev = edge;
                    }
                    edge = edge->next;
                }
                break;
            default:
                break;
        }

        switch (inst_type) {
            case A64_BR:
            case A64_RET:
            case A64_BRK:
                // No static recovery of the address is possible - branches are instrumented.
                break;
            case A64_B_BL:
                a64_B_BL_decode_fields((uint32_t*)&gcode[(uintptr_t)node->end_addr], &scratch, &imm);
                offset = (int64_t) sign_extend64(28, imm << 2);

                taken_edge = node->edges;
                taken_edge->node = (cfg_node *) (node->end_addr + offset);

            case A64_BLR:
                // For function calls we continue with the current function and just save the call address.
                if (node->type & CFG_FUNCTION_CALL) {
                    if (inst_type == A64_B_BL) {
                        node->calls = taken_edge;
                    } else {
                        node->calls = node->edges;
                    }

                    taken_edge = (cfg_edge *) malloc(sizeof(cfg_edge));

                    if (taken_edge == NULL) {
                        fprintf(stderr, "MAMBO Lift: Couldn't allocate the edge!\n");
                        exit(-1);
                    }

                    taken_edge->node = (cfg_node *) (node->end_addr + 4);
                    taken_edge->next = NULL;
                    taken_edge->type = CFG_EDGE_NOTYPE;
                    // We can calculate this value later as a sum of number of time a function was called
                    taken_edge->taken_count = 0;

                    // TODO: Refactor
                    char *symbol = NULL;
                    if(node->calls->node != NULL) {
                        get_plt_symbol_by_addr(binary, node->calls->node, &symbol);
                    }

                    // Reqired for gobmk to work for some reason without this code trailing __stack_chk_fail falls through to the next block.
                    // The check is only discovered due to mambo traces, so it gets pruned later. Somehow other terminator code doesn't pick it up.
                    if(symbol != NULL) {
                        if(strcmp(symbol, "__stack_chk_fail") == 0 || strstr(symbol, "__throw_") != NULL) {
                            taken_edge->node = NULL;
                        }
                    }

                    if(node->calls->node != NULL) {
                        get_symbol_info_by_addr(binary, node->calls->node, &symbol);
                    }

                    if(symbol != NULL) {
                        if(strcmp(symbol, "sqd_regerror") == 0 || strcmp(symbol, "xerbla_") == 0 || strcmp(symbol, "xrealloc.part.0") == 0
                                                                  || strcmp(symbol, "parse_error") == 0 || strcmp(symbol, "error") == 0 || strcmp(symbol, "abrt_") == 0
|| strcmp(symbol, "panic") == 0 || strcmp(symbol, "cleanUpAndFail.isra.0") == 0 || strcmp(symbol, "outOfMemory") == 0
|| strcmp(symbol, "configError") == 0 || strcmp(symbol, "ioError") == 0 || strcmp(symbol, "BZ2_bz__AssertH__fail") == 0|| strcmp(symbol, "abortgo") == 0|| strcmp(symbol, "no_mem_exit") == 0|| strcmp(symbol, "xalloc.part.0") == 0|| strcmp(symbol, "Perl_croak") == 0|| strcmp(symbol, "Perl_croak_nocontext") == 0|| strcmp(symbol, "Perl_die") == 0|| strcmp(symbol, "fancy_abort") == 0|| strcmp(symbol, "_fatal_insn") == 0|| strcmp(symbol, "_fatal_insn_not_found") == 0|| strcmp(symbol, "fatal_io_error") == 0|| strcmp(symbol, "xmalloc_failed") == 0|| strcmp(symbol, "xexit") == 0|| strcmp(symbol, "AT_unsigned.part.0") == 0|| strcmp(symbol, "reverse_condition.part.0") == 0|| strcmp(symbol, "add_child_die.part.0") == 0|| strcmp(symbol, "error_recursion") == 0|| strcmp(symbol, "internal_error") == 0|| strcmp(symbol, "reverse_condition.part.0") == 0) {


                            taken_edge = NULL;
                        }
                    }

                    node->edges = taken_edge;
                }

                break;
            case A64_B_COND:
            case A64_CBZ_CBNZ:
            case A64_TBZ_TBNZ:
                if (inst_type == A64_TBZ_TBNZ) {
                    a64_TBZ_TBNZ_decode_fields((uint32_t*)&gcode[(uintptr_t)node->end_addr], &scratch, &scratch, &scratch, &imm, &scratch);
                    offset = (int64_t) sign_extend64(16, imm << 2);
                } else {
                    // imm is stored at the same position for B.cond and CBZ/CBNZ.
                    a64_B_cond_decode_fields((uint32_t*)&gcode[(uintptr_t)node->end_addr], &imm, &scratch);
                    offset = (int64_t) sign_extend64(21, imm << 2);
                }

                taken_edge = node->edges;
                taken_edge->node = (cfg_node *) (node->end_addr + offset);

                cfg_edge *skipped_edge = node->edges->next;
                skipped_edge->node = (cfg_node *) (node->end_addr + 4);

                break;
            default:
                // fprintf(stderr, "MAMBO Lift: Cannot recover an address of the branch %d in the block ending %p\n", inst_type, node->end_addr);
                return -1;
        }
    }

    return 0;
}

void recover_branch_targets(mambo_ht_t *cfg, char* binary) {
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        if(recover_branch_targets_node(val, binary)) {
            cfg->entries[index].key = 0;
        }
    }
    iterate_mambo_hashmap_end()
}

void static_recover(mambo_ht_t* cfg, char* binary) {
    bool changed;
    do {
        changed = 0;
        iterate_mambo_hashmap(cfg_node, cfg)
        {
            bool first = 1;
            if(val->type & CFG_CONDITIONAL_BLOCK || val->type == CFG_BASIC_BLOCK || ((val->type == CFG_FUNCTION_CALL) && options.full_static_lifting)) {
                cfg_edge *curr = val->edges;
                cfg_node* node;
                int ret;
                while (curr != NULL && curr->node != NULL) {

                    ret = mambo_ht_get_nolock(cfg, (uintptr_t) curr->node, (void *) &node);

                    uint64_t addr = (uint64_t) curr->node;
                    uint64_t start_addr = addr;
                    if (ret) {
                        bool stop = 0;
                        while(!stop) {
                            a64_instruction inst_type = a64_decode((uint32_t*)&gcode[(uintptr_t)addr]);

                            switch (inst_type) {
                                case A64_BR:
                                    changed = 1;
                                    node = (cfg_node *) malloc(sizeof(cfg_node));
                                    initialize_node(node);
                                    node->start_addr = (void*) start_addr;
                                    node->end_addr = (void*) addr;
                                    mambo_ht_add_nolock(cfg, (uintptr_t) start_addr, (uintptr_t) node);
                                    node->type = CFG_INDIRECT_BLOCK;
                                    stop = 1;
                                    break;
                                case A64_BRK:
                                    stop = 1;
                                    break;
                                case A64_RET:
                                    changed = 1;
                                    node = (cfg_node *) malloc(sizeof(cfg_node));
                                    initialize_node(node);
                                    node->start_addr = (void*) start_addr;
                                    node->end_addr = (void*) addr;
                                    mambo_ht_add_nolock(cfg, (uintptr_t) start_addr, (uintptr_t) node);
                                    node->type = CFG_RETURN;
                                    stop = 1;
                                    break;
                                case A64_B_BL:
                                    changed = 1;
                                    node = (cfg_node *) malloc(sizeof(cfg_node));
                                    initialize_node(node);
                                    node->start_addr = (void*) start_addr;
                                    node->end_addr = (void*) addr;
                                    mambo_ht_add_nolock(cfg, (uintptr_t) start_addr, (uintptr_t) node);
                                    cfg_edge *edge = (cfg_edge *) malloc(sizeof(cfg_edge));
                                    initialize_edge(edge, CFG_EDGE_NOTYPE);
                                    node->edges = edge;
                                    uint32_t op, imm26;
                                    a64_B_BL_decode_fields((uint32_t*)&gcode[(uintptr_t)addr], &op, &imm26);
                                    if(op) {
                                        node->type = CFG_FUNCTION_CALL;
                                    } else {
                                        node->type = CFG_BASIC_BLOCK;
                                    }
                                    recover_branch_targets_node(node, binary);
                                    stop = 1;
                                    break;
                                case A64_BLR:
                                    stop = 1;
                                    break;
                                case A64_B_COND:
                                case A64_CBZ_CBNZ:
                                case A64_TBZ_TBNZ:
                                    changed = 1;
                                    node = (cfg_node *) malloc(sizeof(cfg_node));
                                    initialize_node(node);
                                    node->start_addr = (void*) start_addr;
                                    node->end_addr = (void*) addr;
                                    mambo_ht_add_nolock(cfg, (uintptr_t) start_addr, (uintptr_t) node);
                                    node->type = CFG_CONDITIONAL_BLOCK;
                                    cfg_edge *skipped = (cfg_edge *) malloc(sizeof(cfg_edge));
                                    initialize_edge(skipped, CFG_SKIPPED_BRANCH);
                                    cfg_edge *taken = (cfg_edge *) malloc(sizeof(cfg_edge));
                                    initialize_edge(taken, CFG_TAKEN_BRANCH);
                                    taken->next = skipped;
                                    node->edges = taken;
                                    recover_branch_targets_node(node, binary);
                                    stop = 1;
                                    break;
                                default:
                                    break;
                            }

                            addr += 4;
                        }
                    }

                    if(val->type == CFG_FUNCTION_CALL && first) {
                        first = 0;
                        curr = val->calls;
                    } else {
                        curr = curr->next;
                    }
                }
            }
        }
        iterate_mambo_hashmap_end()
    } while(changed);
}

void promote_indirect_branches_to_calls(mambo_ht_t* cfg, cfg_node_linked_list* list) {
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        if(val->type & CFG_FUNCTION_CALL) {
            cfg_edge* call = val->calls;
            while (call != NULL && call->node != NULL) {
                // Check if call node has any in-coming edges - that would mean we called in the middle of the function.
                if(call->node->in_degree != 0) {
                    cfg_node** prevs = call->node->prev;
                    for(int idx = 0; idx < call->node->in_degree; idx++) {
                        cfg_node* prev = prevs[idx];

                        // Promote any predecessors of the called node to the function call.
                        if((prev->type & CFG_INDIRECT_BLOCK && !(prev->type & CFG_FUNCTION_CALL)) || prev->type == CFG_BASIC_BLOCK) {
                            prev->type |= CFG_FUNCTION_CALL;

                            prev->calls = prev->edges;
                            prev->edges = NULL;

                            // In the process we may find new functions, so update the list. The function may be already
                            // present depending on the order nodes in extract_functions_dfs are visited, so we need
                            // to check that.
                            cfg_node_linked_list* curr = list;
                            while(curr->next != NULL && curr->node->start_addr != call->node->start_addr) {
                                curr = curr->next;
                            }

                            if(curr->node->start_addr == call->node->start_addr) {
                                continue;
                            }

                            cfg_node_linked_list *new_elem = (cfg_node_linked_list *) malloc(sizeof(cfg_node_linked_list));

                            new_elem->node = call->node;
                            new_elem->next = NULL;

                            curr->next = new_elem;

                            // In some benchmarks the code above does not add all discovered functions to the list,
                            // e.g., a new indirect node calls multiple functions, but only got promoted once, so
                            // only the first function is added. Not extensively tested.
                            cfg_edge* candidate = prev->calls;
                            while (candidate != NULL && candidate->node != NULL) {
                                cfg_node_linked_list *curr = list;
                                while (curr->next != NULL && curr->node->start_addr != candidate->node->start_addr) {
                                    curr = curr->next;
                                }

                                if (curr->node->start_addr != candidate->node->start_addr) {

                                    cfg_node_linked_list *new_elem = (cfg_node_linked_list *) malloc(
                                            sizeof(cfg_node_linked_list));

                                    new_elem->node = candidate->node;
                                    new_elem->next = NULL;

                                    curr->next = new_elem;
                                }

                                candidate = candidate->next;
                            }

                        }
                    }
                }
                call = call->next;
            }
        }
    }
    iterate_mambo_hashmap_end()
}

/*
    Rerank
*/
void rerank_function_dfs(cfg_node *node, uint64_t* function_id) {
    node->visited = 1;

    if (node->type & CFG_FUNCTION_CALL) {
        cfg_edge *call = node->calls;
        while (call != NULL && call->node != NULL) {
            // TODO: Revisit
            if (call->node->visited == 0 && !(call->node->type == CFG_NATIVE_CALL && call->node->native_function_name == NULL)) {
                *function_id += 1;
                call->node->function_id = *function_id;

                rerank_function_dfs(call->node, function_id);
            }

            call = call->next;
        }
    }

    cfg_edge *edge = node->edges;

    if(node->type & CFG_RETURN) {
        edge = NULL;
    }

    while (edge != NULL) {

        cfg_node *next_node = edge->node;

        if (next_node->visited == 0) {
            next_node->function_id = node->function_id;
            rerank_function_dfs(next_node, function_id);
        }

        edge = edge->next;
    }
}

void rerank_function(cfg_node *cfg) {
    static uint64_t function_id;

    function_id = 0;
    cfg->function_id = function_id;

    rerank_function_dfs(cfg, &function_id);
}

void extract_functions_on_b(mambo_ht_t* cfg, cfg_node_linked_list* list) {
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        cfg_edge* edge = val->edges;
        if (val->type == CFG_BASIC_BLOCK) {
            //assert(edge != NULL);
            if(edge == NULL) {
                continue;
            }
            // Check if branch crosses function boundary
            if(edge->node->function_id != val->function_id) {
                cfg_node** prevs = edge->node->prev;
                for(int idx = 0; idx < edge->node->in_degree; idx++) {
                    cfg_node* prev = prevs[idx];

                    // Promote any predecessors of the called node to the function call.
                    prev->type |= CFG_FUNCTION_CALL;

                    prev->calls = prev->edges;
                    prev->edges = NULL;

                    // In the process we may find new functions, so update the list. The function may be already
                    // present depending on the order nodes in extract_functions_dfs are visited, so we need
                    // to check that.
                    cfg_node_linked_list* curr = list;
                    while(curr->next != NULL && curr->node->start_addr != edge->node->start_addr) {
                        curr = curr->next;
                    }

                    if(curr->node->start_addr == edge->node->start_addr) {
                        continue;
                    }

                    cfg_node_linked_list *new_elem = (cfg_node_linked_list *) malloc(sizeof(cfg_node_linked_list));

                    new_elem->node = edge->node;
                    new_elem->next = NULL;

                    curr->next = new_elem;
                }
            }
        }
    }
    iterate_mambo_hashmap_end()
}

void promote_inter_function_branches_to_calls(mambo_ht_t* cfg, cfg_node_linked_list* list) {
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        cfg_edge* edge = val->edges;

        if(val->type & CFG_RETURN) {
            edge = NULL;
        }

        while (edge != NULL && edge->node != NULL) {
            if(val->function_id != edge->node->function_id) {
                cfg_node** prevs = edge->node->prev;
                for(int idx = 0; idx < edge->node->in_degree; idx++) {
                    cfg_node* prev = prevs[idx];

                    // Promote any predecessors of the node to the function call.
                    if((prev->type & CFG_INDIRECT_BLOCK || prev->type == CFG_BASIC_BLOCK) && !(prev->type & CFG_FUNCTION_CALL)) {
                        prev->type |= CFG_FUNCTION_CALL;

                        prev->calls = prev->edges;
                        prev->edges = NULL;
                    }
                }

                cfg_node_linked_list* curr = list;
                while(curr->next != NULL && curr->node->start_addr != edge->node->start_addr) {
                    curr = curr->next;
                }

                if(curr->node->start_addr == edge->node->start_addr) {
                    edge = edge->next;
                    continue;
                }

                cfg_node_linked_list *new_elem = (cfg_node_linked_list *) malloc(sizeof(cfg_node_linked_list));

                new_elem->node = edge->node;
                new_elem->next = NULL;

                curr->next = new_elem;
            }

            edge = edge->next;
        }
    }
    iterate_mambo_hashmap_end()
}

void remove_fall_through_edges(mambo_ht_t* cfg) {
    // TODO: Fix below:
    // In same case we still fall through (in that case val->function_id == val->edges->node->function_id)
    // It seems it happens when we fall though to the function that has not been discovered. We can probably fix it
    // by removing node from the hash map when pruning.
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        if(val->type & CFG_FUNCTION_CALL) {
            if(val->edges != NULL) {
                if(val->function_id != val->edges->node->function_id) {
                    val->edges = NULL;
                }
            }
        }
    }
    iterate_mambo_hashmap_end()
}

void prune_leaves(cfg_node_linked_list *functions, cfg_node *node) {
    node->visited = 1;

    cfg_edge *edge = node->edges;
    cfg_edge* prev = NULL;

    while (edge != NULL) {

        cfg_node *next = edge->node;

        if(next->type == CFG_NATIVE_CALL) {
            break;
        }

        bool prune = 0;
        if(next->calls != NULL && next->calls->node != NULL) {
            prune = 1;
            cfg_node_linked_list *functions_iter = functions;
            while (functions_iter != NULL) {
                if(next->calls->node->start_addr == functions_iter->node->start_addr) {
                    prune = 0;
                    break;
                }
                functions_iter = functions_iter->next;
            }
        }

        // Indirect function calls may never call if are scanned as part of the trace
        if(next->calls != NULL && next->calls->node == NULL) {
            prune = 1;
        }

        if(next->type != CFG_RETURN && ((next->edges == NULL && next->calls == NULL) || prune)) {
            if (prev == NULL) {
                if (edge->next == NULL) {
                    node->edges = NULL;
                    edge = NULL;
                } else {
                    node->edges = edge->next;
                    edge = edge->next;
                }
            } else {
                prev->next = edge->next;
                edge = edge->next;
            }
        } else {
            if (next->visited == 0) {
                prune_leaves(functions, next);
            }

            prev = edge;
            edge = edge->next;
        }
    }
}
