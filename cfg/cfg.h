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

#include <stdint.h>

#include "../common/typedefs.h"

#include "../ast/ast_list.h"

// DEFS

#define CFG_MAX_IN_NODES 1024

// ENUMS

/// Type of the edge in the CFG
typedef enum {
    CFG_EDGE_NOTYPE, ///< Type of the edge not known yet or irrelevant
    CFG_TAKEN_BRANCH, ///< Edge followed when the branch condition is true
    CFG_SKIPPED_BRANCH ///< Edge followed when the branch condition is false
} cfg_edge_type;

/// Types of CFG nodes - one node can have multiple types, e.g., indirect function call
typedef enum {
    CFG_BASIC_BLOCK = 0x0, ///< Ends in unconditional branch
    CFG_CONDITIONAL_BLOCK = 0x1, ///< Ends in conditional branch
    CFG_FUNCTION_CALL = 0x8, ///< Ends in function call
    CFG_SVC = 0x10, ///< Ends in SVC
    CFG_RETURN = 0x20, ///< Ends in return statement
    CFG_INDIRECT_BLOCK = 0x40, ///< Ends in the indirect branch
    CFG_NATIVE_CALL = 0x80 ///< Ends in call to a library function that is not being lifted
} cfg_node_type;

/// Profile of the node obtained from MAMBO tracing
typedef enum {
    CFG_NODE_COLD = 0, ///< Node executed less than 256 times
    CFG_NODE_HOT = 1, ///< Node executed more than 256 times
    CFG_NODE_HOT_HEAD = 2 ///< Node executed more than 256 times and it is a first block of the hot section
} cfg_node_profile;

// STRUCTS

/// Edge in the CFG. NOTE: Before modifying see instrumentation.S
struct cfg_edge{
    cfg_node* node; ///< NOTE: Has to be the first field for the instrumentation to work correctly.
    cfg_edge* next;

    cfg_edge_type type;

    uint64_t taken_count;
};

/// Node in the CFG
struct cfg_node {
    void* start_addr; ///< Start address of the node in the original binary
    void* end_addr; ///< End address of the node in the original binary

    cfg_edge* edges; ///< Out edges of the node

    cfg_node_type type; ///< Type of the node

    uint64_t order_id; ///< Defines order in which basic blocks were first executed
    uint64_t function_id; ///< Defines which function the node belongs to

    uint32_t branch_reg; ///< Register used for jumping by the indirect branch

    // Function call
    cfg_edge* calls; ///< If node is function call it is used to point to the head of the called function

    // Graph Properties
    uint8_t visited; ///< Flag to check if node was visited during the graph search

    uint32_t in_degree; ///< Number of incoming nodes
    cfg_node* prev[CFG_MAX_IN_NODES]; ///< List of incoming nodes to this node

    // Profiling
    cfg_node_profile profile; ///< Profile of the node - tells if nodes executed more than 256 times

    // AST
    ast_stmt_list stmts; ///< Instructions lifted from the node / body of the basic block

    // Native call
    char* native_function_name; ///< Name of the library function to be called
    uint8_t linked; ///< Indicates whether call was done using branch or branch link. In some cases the compiler
                    ///< decides to call function without the link and it that cases the called function returns to
                    ///< the caller or its caller.
                    ///<
                    ///< For example:
                    ///<
                    ///< foo:
                    ///<   ...
                    ///<   bl bar
                    ///<   ...
                    ///< bar:
                    ///<   ...
                    ///<   b rar
                    ///<   ...
                    ///< rar:
                    ///<   ...
                    ///<   ret
                    ///<
                    ///< In this case rar returns directly to foo rather than bar. In such cases we replace regular b
                    ///< with bl followed directly by ret to achieve the same goal.
    uint8_t original_function;
};

/// Linked list to store multiple nodes
struct cfg_node_linked_list {
    cfg_node* node;
    cfg_node_linked_list* next;
};

// FUNCTIONS

void initialize_node(cfg_node* node);

void initialize_edge(cfg_edge* edge, cfg_edge_type type);
