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

#include <dirent.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "unicorn/lift.h"

#include "python/python.h"

#include "cfg/cfg_preprocessor.h"
#if MLDEBUG >= 10
    #include "cfg/cfg_print.h"
#endif
#include "cfg/cfg_utils.h"
#include "cfg_to_ast.h"

#include "utils/hashmap_utils.h"

#include "ast_to_code.h"
#include "ast/ast_optimizer.h"

#include "options.h"

char* gcode;

void load_cfg_from_file(FILE* file, mambo_ht_t* cfg, void** main_addr) {
  uint64_t temp;

  size_t elems = fread(main_addr, sizeof(main_addr), 1, file);

  elems = fread(&temp, sizeof(uint64_t), 1, file); // Read first magic marker (-1)

  bool stop = (elems == 0);

  while(!stop) {
      void *start_addr, *end_addr;
      uint32_t branch_reg, type;

      elems = fread(&start_addr, sizeof(void*), 1, file);
      elems = fread(&end_addr, sizeof(void*), 1, file);
      elems = fread(&branch_reg, sizeof(uint32_t), 1, file);
      elems = fread(&type, sizeof(uint32_t), 1, file);

      cfg_node* node;

      int ret = mambo_ht_get_nolock(cfg, (uintptr_t) start_addr, (void *) &node);

      if(ret) {
          node = (cfg_node *) malloc(sizeof(cfg_node));
          initialize_node(node);
          node->start_addr = start_addr;
          node->end_addr = end_addr;
          node->branch_reg = branch_reg;
          node->type = type;
          mambo_ht_add_nolock(cfg, (uintptr_t) start_addr, (uintptr_t) node);

          if(type == CFG_CONDITIONAL_BLOCK) {
              cfg_edge *skipped = (cfg_edge *)malloc(sizeof(cfg_edge));
              initialize_edge(skipped, CFG_SKIPPED_BRANCH);

              cfg_edge *taken = (cfg_edge *) malloc(sizeof(cfg_edge));
              initialize_edge(taken, CFG_TAKEN_BRANCH);

              taken->next = skipped;

              node->edges = taken;
          } else if(type == CFG_BASIC_BLOCK || type == CFG_FUNCTION_CALL || type == CFG_SVC) {
              cfg_edge *edge = (cfg_edge *) malloc(sizeof(cfg_edge));
              initialize_edge(edge, CFG_EDGE_NOTYPE);

              node->edges = edge;
          }
      }

      void* succ;

      while(true) {
          elems = fread(&succ, sizeof(void*), 1, file);

          if (elems == 0) {
              stop = 1;
              break;
          }

          if ((uintptr_t) succ == (uintptr_t) -1) {
              break;
          }

          elems = fread(&type, sizeof(uint32_t), 1, file);

          if(node->edges == NULL) {
              cfg_edge *edge = (cfg_edge *) malloc(sizeof(cfg_edge));
              initialize_edge(edge, type);
              edge->node = succ;
              node->edges = edge;
          } else {
              cfg_edge *edge = node->edges;
              cfg_edge *prev;
              bool exists = 0;
              while(edge != NULL) {
                  if(edge->node == succ) {
                      exists = 1;
                      break;
                  }
                  prev = edge;
                  edge = edge->next;
              }

              if(!exists) {
                  cfg_edge *edge = (cfg_edge *) malloc(sizeof(cfg_edge));
                  initialize_edge(edge, type);
                  edge->node = succ;
                  prev->next = edge;
              }
          }
      }

      if(node->edges == NULL) {
          cfg_edge *edge = (cfg_edge *) malloc(sizeof(cfg_edge));
          initialize_edge(edge, CFG_EDGE_NOTYPE);

          node->edges = edge;
      }

  }

}

static void add_var(ast_translation_unit* translation_unit, char* var) {
    ast_decl* decl = build_var_decl(var, AST_VAR_INT64);
    decl->var_decl.scope = AST_VAR_REG_GLOBAL;
    symbol_table_check_insert(translation_unit->global_vars, var, (void *) decl);
}

int main(int argc, char* argv[]) {

    parse_options(argc, argv);

#if MLDEBUG >= 1
    printf("Reading CFG...\n");
#endif

    int section_addr, section_size;
    char* code;

    initialize_python();

    get_text_section(options.input_file, &section_addr, &section_size, &code);

    gcode = (char*) malloc(section_addr + section_size);
    memcpy(gcode + section_addr, code, section_size);
    memset(gcode, 0, section_addr);

    free(code);

    int plt_section_addr, plt_section_size;
    get_plt_section(options.input_file, &plt_section_addr, &plt_section_size, &code);

    memcpy(gcode + plt_section_addr, code, plt_section_size);

    free(code);

    mambo_ht_t* cfg = (mambo_ht_t *) malloc(sizeof(mambo_ht_t));
    if (cfg == NULL) {
        fprintf(stderr, "mclift: Couldn't allocate the hash map!\n");
        exit(-1);
    }

    int ret = mambo_ht_init(cfg, 1 << 20, 0, 80, false);
    if (ret) {
        fprintf(stderr, "mclift: Couldn't initialize the hash map!\n");
        exit(-1);
    }

    struct dirent *entry;
    DIR *dp = opendir(".");

    void* main_addr = NULL;

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) { // Check if it's a regular file
            if (strstr(entry->d_name, ".mtrace") != NULL) {
                FILE *file = fopen(entry->d_name, "rb");

                load_cfg_from_file(file, cfg, &main_addr);

                fclose(file);
            }
        }
    }

    closedir(dp);

#if MLDEBUG >= 1
    printf("Pre-Processing CFG...\n");
#endif

    uintptr_t* external_entry_point = malloc(sizeof(uintptr_t));
    size_t external_count = 0;

    iterate_mambo_hashmap(cfg_node, cfg)
    {
        if(val->type & CFG_INDIRECT_BLOCK) {
            cfg_edge* edge = val->edges;
            while(edge != NULL) {
                if(edge->node != NULL) {
                    if((uintptr_t) val->start_addr >= (uintptr_t) section_addr + section_size &&
                        (uintptr_t) edge->node < (uintptr_t) section_addr + section_size &&
                        (uintptr_t) edge->node >= (uintptr_t) section_addr &&
                        (uintptr_t) edge->node != (uintptr_t) main_addr) {
                            external_entry_point[external_count] = (uintptr_t) edge->node;
                            external_count += 1;
                            external_entry_point = realloc(external_entry_point, (external_count + 1) * sizeof(uintptr_t));
                    }
                }
                edge = edge->next;
            }
        }
    }
    iterate_mambo_hashmap_end()


    iterate_mambo_hashmap(cfg_node, cfg)
    {
        if((uintptr_t) val->start_addr >= (uintptr_t) section_addr + section_size) {
            cfg->entries[index].key = -1;
            cfg_edge* edge = val->edges;
            cfg_edge* prev;
            if(edge != NULL) {
                while(edge->next != NULL) {
                    prev = edge;
                    edge = edge->next;
                    free(prev);
                }
                free(edge);
            }
            free(val);
        }
    }
    iterate_mambo_hashmap_end()

    recover_branch_targets(cfg, options.input_file);
    if(options.static_lifting) {
        static_recover(cfg, options.input_file);
    }
    replace_addresses_with_nodes(cfg, options.input_file);

    int init_addr, init_size;
    uintptr_t* init_code;
    get_init_array_section(options.input_file, &init_addr, &init_size, (char**) &init_code);

    cfg_node* head;
    mambo_ht_get_nolock(cfg, (uintptr_t) main_addr, (void*) &head);

    init_code[0] = (uintptr_t) main_addr;

    uintptr_t* new_init = (uintptr_t*) malloc(init_size + external_count * sizeof(uintptr_t));

    memcpy(new_init, init_code, init_size);
    memcpy(new_init + (init_size / 8), external_entry_point, external_count * sizeof(uintptr_t));

    init_size += external_count * sizeof(uintptr_t);
    init_code = new_init;

    // The extract_functions does not clear visited flags, so we can call remove_unvisited_nodes, and then we clear
    // the flags.
    cfg_node_linked_list *functions = extract_functions(cfg, init_code, init_size / 8);
    cfg_node_linked_list *functions_iter = functions;

    remove_unvisited_nodes(cfg);
    remove_fall_through_edges(cfg);
    promote_indirect_branches_to_calls(cfg, functions);
    promote_indirect_branches_to_calls(cfg, functions);
    promote_inter_function_branches_to_calls(cfg, functions);

    functions_iter = functions;
    while(functions_iter != NULL) {
        clear_visited_flags(functions_iter->node);
        functions_iter = functions_iter->next;
    }
    // TODO: Rereank should take list of entry points as an argument
    rerank_function(head);
    extract_functions_on_b(cfg, functions);
    iterate_mambo_hashmap(cfg_node, cfg)
    {
        val->visited = 0;
    }
    iterate_mambo_hashmap_end()
    functions = extract_functions(cfg, init_code, init_size / 8);
    int fcount = 0;
    functions_iter = functions;
    while(functions_iter != NULL) {
        fcount++;
        clear_visited_flags(functions_iter->node);
        functions_iter = functions_iter->next;
    }

    for(int i = 0; i < 10; i++) {
        functions_iter = functions;
        while (functions_iter != NULL) {
            prune_leaves(functions, functions_iter->node);
            functions_iter = functions_iter->next;
        }

        functions_iter = functions;
        while (functions_iter != NULL) {
            clear_visited_flags(functions_iter->node);
            functions_iter = functions_iter->next;
        }
    }

#if MLDEBUG >= 10
    print_graph(stdout, functions);
#endif

#if MLDEBUG >= 1
    printf("Building basic blocks...\n");
#endif

    ast_translation_unit *translation_unit = build_translation_unit(main_addr, options.input_file);
    translation_unit->constructors = init_code + 1;
    translation_unit->num_ctr = (init_size / 8) - 1 - external_count;
    translation_unit->callbacks = external_entry_point;
    translation_unit->num_cb = external_count;

    aarch64_generate_tcg_init();

    // TODO: Clean up
    tcalls = NULL;
    taddrs = NULL;

    char* vars[] = { "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "sp", "env" };

    for(int idx = 0; idx < (sizeof(vars) / sizeof(vars[0])); idx++) {
        add_var(translation_unit, vars[idx]);
    }

    FILE* blocks = fopen("blocks.txt", "w");

    uint64_t full_count = 0;

    functions_iter = functions;
    while(functions_iter != NULL) {
        uint64_t count = count_cfg_nodes(functions_iter->node);
        full_count += count;
        cfg_node** nodes = list_cfg_nodes(functions_iter->node, count, blocks);
        build_basic_blocks(nodes, count, translation_unit, NULL);
        functions_iter = functions_iter->next;
    }

    fclose(blocks);

#if MLDEBUG >= 1
    printf("Optimize code...\n");
#endif

    optimize_ast(translation_unit);

#if MLDEBUG >= 1
    printf("Build full AST...\n");
#endif

    build_full_ast(functions, translation_unit);

#if MLDEBUG >= 1
    printf("Generate C code...\n");
#endif

    char* lifted_code_filename = basename(options.input_file);
    strcat(lifted_code_filename, ".c");
    FILE *lifted_code = fopen(lifted_code_filename, "w");
    convert_ast_to_code(lifted_code, translation_unit);
    fclose(lifted_code);

    FILE *trampolines = fopen("trampolines.S", "w");
    generate_trampolines(trampolines, translation_unit);
    fclose(trampolines);

    FILE *linker = fopen("custom.ld.part2", "w");
    generate_linker_trampolines(linker, translation_unit);
    fclose(linker);

#if MLDEBUG >= 1
    printf("Clean up...\n");
#endif

    destroy_python();

    iterate_mambo_hashmap(cfg_node, cfg)
    {
        cfg_edge* edge = val->edges;
        cfg_edge* prev;
        if(edge != NULL) {
            while(edge->next != NULL) {
                prev = edge;
                edge = edge->next;
                free(prev);
            }
            free(edge);
        }
        free(val);

    }
    iterate_mambo_hashmap_end()

    free(gcode);
    free(cfg->entries);
    free(cfg);

    return 0;
}
