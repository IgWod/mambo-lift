/*
  Copyright 2024 Igor Wodiany
  Copyright 2024 The University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this trace except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#pragma once

#include <float.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hash_table.h"
#include "ast/symbol_table.h"

#include "pie/pie-a64-decoder.h"

// #define MAX_INDIRECT_JUMPS 196 // 1024 for gobmk
#define MAX_FUNCTION_ARGUMENTS 16

// TODO: This redeclaration should not be here.
struct cfg_node;
typedef struct cfg_node cfg_node;

/* ENUMS */

/// Declaration of variables
typedef enum {
    AST_VAR_DECL
} ast_decl_type;

/// Variable types
typedef enum {

    // Integer types

    AST_VAR_INT8 = 1,
    AST_VAR_INT16 = 2,
    AST_VAR_INT32 = 3,
    AST_VAR_INT64 = 4,

    // Vector types

    AST_VAR_VEC64 = 5,
    AST_VAR_VEC128 = 6,

    // Other

    AST_VAR_STRUCT = 7,
    AST_VAR_NOTYPE = 0 ///< Not enough information to decide on type yet

} ast_var_type;

/// Scope of the variable
typedef enum {
    AST_VAR_REG_GLOBAL, ///< Global variables lifted from TCG, e.g., processor registers

    AST_VAR_TEMP_LOCAL, ///< Local variables lifted from TCG temporary variables. The temporary variable must be live
                        ///< only within a single basic block. It cannot out-live the basic block. This property is
                        ///< used in multiple optimizations passes
    AST_VAR_MAP,        ///< Variable used to hold an address of the libraries mappings

    AST_VAR_STACK_LOCAL, ///< Local variables lifted from the stack access

    AST_VAR_NOSCOPE ///< Undefined/Unknown scope that should not normally appear
} ast_var_scope;

/// Expressions
typedef enum {
    AST_BINARY_EXPR,
    AST_CALL_EXPR,
    AST_CAST_EXPR,
    AST_DUP_EXPR,
    AST_TERNARY_CONDITIONAL_EXPR,
    AST_FP32_EXPR,
    AST_FP64_EXPR,
    AST_INT32_EXPR,
    AST_UINT32_EXPR,
    AST_INT64_EXPR,
    AST_UINT64_EXPR,
    AST_MEMORY_EXPR,
    AST_STRING_EXPR,
    AST_UNARY_EXPR,
    AST_VAR_EXPR,
    AST_VEC_EXPR
} ast_expr_type;

/// Binary and unary operators
typedef enum {

    // Conditional

    AST_EQ_OP = 0,
    AST_NE_OP = 1,
    AST_CS_OP = 2, ///< Pseudo op
    AST_CC_OP = 3, ///< Pseudo op
    AST_MI_OP = 4, ///< Pseudo op
    AST_PL_OP = 5, ///< Pseudo op
    AST_VS_OP = 6, ///< Pseudo op
    AST_VC_OP = 7, ///< Pseudo op
    AST_HI_OP = 8, ///< Pseudo op
    AST_LS_OP = 9, ///< Pseudo op
    AST_GE_OP = 10,
    AST_LT_OP = 11,
    AST_GT_OP = 12,
    AST_LE_OP = 13,
    AST_AL_OP = 14, ///< Pseudo op
    AST_ALT_OP = 15, ///< Pseudo op

    // Signed Arithmetic

    AST_ADD_OP = 16,
    AST_SUB_OP = 17,
    AST_MUL_OP = 18,
    AST_DIV_OP = 19,
    AST_NEG_OP = 20,

    // Unsigned Arithmetic

    AST_UDIV_OP,

    // Bitwise

    AST_AND_OP,
    AST_ANDC_OP,
    AST_ORR_OP,
    AST_ORC_OP,
    AST_EOR_OP,
    AST_NOT_OP,

    // Logical

    AST_LSL_OP,
    AST_SLSL_OP,
    AST_ASR_OP,
    AST_LSR_OP,
    AST_LNG_OP, ///< Logical negation (exclamation mark)

    // Other

    AST_ASS_OP,
    AST_FASS_OP,
    AST_MAX_OP,
    AST_UMAX_OP,
    AST_MIN_OP,
    AST_UMIN_OP,
    AST_ABS_OP,
    AST_BSL_OP ///< Bit selection

} ast_op;

/// Size of the load/store
typedef enum {
    // Scalar load/store
    AST_LDST_BYTE = 0,
    AST_LDST_HALF = 1,
    AST_LDST_SINGLE = 2,
    AST_LDST_DOUBLE = 3,

    // Vector load/store
    AST_LDST_VEC = 4,
    AST_LDST_QVEC = 5
} ast_ldst_size;

/// Signedness of the load/store
typedef enum {
    AST_LDST_UNSIGNED = 0,
    AST_LDST_SIGNED = 1,
    AST_LDST_FLOAT = 2
} ast_ldst_type;

/// Type of the cast between types
typedef enum {
    AST_CAST_TO_UINT64,
    AST_CAST_TO_INT64,
    AST_CAST_TO_UINT32,
    AST_CAST_TO_INT32,
    AST_CAST_TO_UINT16,
    AST_CAST_TO_INT16,
    AST_CAST_TO_UINT8,
    AST_CAST_TO_INT8,

    AST_CAST_TO_DOUBLE,
    AST_CAST_TO_FLOAT,

    AST_CAST_DOUBLE_TO_INT,
    AST_CAST_FLOAT_TO_INT
} ast_cast_type;

/// Statement types
typedef enum {
    AST_BREAK_STMT,
    AST_EXPR_STMT,
    AST_CONDITIONAL_GOTO_STMT,
    AST_IF_ELSE_STMT,
    AST_INDIRECT_GOTO_STMT,
    AST_LABEL_STMT,
    AST_RETURN_STMT,
    AST_WHILE_STMT
} ast_stmt_type;

/* TYPEDEFS */

struct ast_var_decl;
typedef struct ast_var_decl ast_var_decl;

struct ast_decl;
typedef struct ast_decl ast_decl;


struct ast_binary_expr;
typedef struct ast_binary_expr ast_binary_expr;

struct ast_call_expr;
typedef struct ast_call_expr ast_call_expr;

struct ast_cast_expr;
typedef struct ast_cast_expr ast_cast_expr;

struct ast_dup_expr;
typedef struct ast_dup_expr ast_dup_expr;

struct ast_ternary_conditional_expr;
typedef struct ast_ternary_conditional_expr ast_ternary_conditional_expr;

struct ast_memory_expr;
typedef struct ast_memory_expr ast_memory_expr;

struct ast_unary_expr;
typedef struct ast_unary_expr ast_unary_expr;

struct ast_var_expr;
typedef struct ast_var_expr ast_var_expr;

struct ast_vec_expr;
typedef struct ast_vec_expr ast_vec_expr;


struct ast_expr;
typedef struct ast_expr ast_expr;


struct ast_function;
typedef struct ast_function ast_function;


struct ast_break_stmt;
typedef struct ast_break_stmt ast_break_stmt;

struct ast_conditional_goto_stmt;
typedef struct ast_conditional_goto_stmt ast_conditional_goto_stmt;

struct ast_if_else_stmt;
typedef struct ast_if_else_stmt ast_if_else_stmt;

struct ast_indirect_goto_stmt;
typedef struct ast_indirect_goto_stmt ast_indirect_goto_stmt;

struct ast_label_stmt;
typedef struct ast_label_stmt ast_label_stmt;

struct ast_return_stmt;
typedef struct ast_return_stmt ast_return_stmt;

struct ast_while_stmt;
typedef struct ast_while_stmt ast_while_stmt;

struct ast_stmt;
typedef struct ast_stmt ast_stmt;


struct ast_translation_unit;
typedef struct ast_translation_unit ast_translation_unit;

/* STRUCTS */

/// Variable declaration
struct ast_var_decl {
    char* symbol; ///< Variable name
    ast_var_type type; ///< Variable type
    ast_var_scope scope; ///< Variable scope

    ast_expr* use_def; ///< Current value of the variable obtained through the dataflow analysis
    ast_stmt* stmt; ///<

    int8_t accessed;
    int8_t written;

    ast_expr* initial_value; ///< Initial value of the variable

    char* object; ///< We use it store name of the mapped binary for AST_VAR_MAP
};

/// Generic declaration structure
struct ast_decl {
    ast_decl_type type; ///< Type of the declaration

    union {
        ast_var_decl var_decl;
    };
};


/// Expression in the form of A op B
struct ast_binary_expr {
    ast_expr* lhs;
    ast_op op;
    ast_expr* rhs;
};

/// Function call
struct ast_call_expr {
    ast_function* function;
};

/// Cast expression in the form of (A) x
struct ast_cast_expr {
    ast_expr* expr;
    ast_cast_type type;
};

///
struct ast_dup_expr {
    ast_expr* vector;
    ast_expr* scalar;
    int element_size;
};

///
struct ast_vec_expr {
    ast_expr* v0;
    ast_expr* v1;
    ast_expr* v2;
    ast_expr* v3;
    ast_op op;
    int element_size;
};

/// Access to/from the memory location
struct ast_memory_expr {
    ast_expr* addr; ///< Address of the load/store

    ast_ldst_size size; ///< Number of bytes loaded/stored
    ast_ldst_type type; ///< TYpe of the value loaded/stored

    uint8_t element_size;

    ast_expr* lv;
};

/// Conditional ternary expression in form of: cond ? true_expr : false_expr
struct ast_ternary_conditional_expr {
    ast_expr* cond;
    ast_expr* true_expr;
    ast_expr* false_expr;
};

/// Expression in the form op A
struct ast_unary_expr {
    ast_op op;
    ast_expr* expr;
};

/// Expression representing variable
struct ast_var_expr {
    ast_decl* var;
};

/// Generic expression type
struct ast_expr {
    ast_expr_type type; ///< Type of the expression

    /// Fields for all possible expression types packed as a union to reduce memory usage.
    union {
        // Complex expressions
        ast_binary_expr binary_expr;
        ast_call_expr call_expr;
        ast_cast_expr cast_expr;
        ast_dup_expr dup_expr;
        ast_memory_expr memory_expr;
        ast_ternary_conditional_expr ternary_conditional_expr;
        ast_unary_expr unary_expr;
        ast_var_expr var_expr;
        ast_vec_expr vec_expr;

        // Constant expressions
        float fp32_expr;
        double fp64_expr;
        int32_t int32_expr;
        uint32_t uint32_expr;
        int64_t int64_expr;
        uint64_t uint64_expr;
        char* string_expr;

    };
};


/// Representation of the function in the translation unit
struct ast_function {
    char* name;

    ast_expr *arguments[MAX_FUNCTION_ARGUMENTS];
    uint32_t number_arguments;

    ast_stmt* body;

    symbol_table* local_vars;

    uint64_t index;

    cfg_node** basic_blocks;
    uint64_t number_basic_blocks;

    bool is_callback;
};


/// Statement in the form of:
///
/// break;
///
struct ast_break_stmt {
    // Reserved for future extension
};

/// Statement in the form of:
///
/// if(cond)
///     goto L0x<taken>;
/// else
///     goto L0x<skipped>;
///
/// Note: It's a sudo AST stmt as it represents multiple C constructs, however it simplifies analyses.
struct ast_conditional_goto_stmt {
    ast_expr* cond;
    void* taken;
    void* skipped;
    bool allow_fall_through; /// < For some branches we do not define a skipped address and just allow fall through.
                             /// < We primarily use it to implement TCG internal control flow.
};

/// Statement in the form of:
///
/// if(cond)
///     if_body;
/// else
///     else_body;
///
struct ast_if_else_stmt {
    ast_expr* cond;
    ast_stmt* if_body;
    ast_stmt* else_body;
};

/// Statement in the form of:
///
/// switch(cond)
///     case jumps[0]:
///         goto L0x<jumps[0]>;
///     case jumps[1]:
///         goto L0x<jumps[1]>;
/// ...
///
/// Note: It's a sudo AST stmt as it represents multiple C constructs, however it simplifies analyses.
struct ast_indirect_goto_stmt {
    ast_expr* cond;
    void** jumps;
    uint32_t number_jumps;
    bool is_call;
};

/// Statement in the form of:
///
/// addr:
///
struct ast_label_stmt {
    void* addr;
};

/// Statement in the form of:
///
/// return ret;
///
struct ast_return_stmt {
    ast_expr* ret;
};

/// Statement in the form of:
///
/// while(cond)
///     body;
///
struct ast_while_stmt {
    ast_expr* cond;
    ast_stmt* body;
};

/// Generic statement type
struct ast_stmt {
    ast_stmt_type type; ///< Statement type

    /// Fields for all possible statements types packed as a union to reduce memory usage.
    union {
        ast_break_stmt break_stmt;
        ast_expr *expr_stmt;
        ast_conditional_goto_stmt conditional_goto_stmt;
        ast_if_else_stmt if_else_stmt;
        ast_indirect_goto_stmt indirect_goto_stmt;
        ast_label_stmt label_stmt;
        ast_return_stmt return_stmt;
        ast_while_stmt while_stmt;
    };

    /// Allow chaining statements into a linked list
    ast_stmt* prev; ///< Previous node of the linked list - NULL if statements is head.
    ast_stmt* next; ///< Next node of the linked list - NULL if statements is tail.

    void* insn_addr; ///< Address in the program binary from where the statement was lifted. Multiple statement can
                     ///< correspond to the same address, as QEMU breaks down single assembly instruction into
                     ///< multiple TCG statements, and we map TCG statements into AST IR.
};


/// Translation unit containing all functions and global variables in the application
struct ast_translation_unit {
    // TODO: Replace with symbol table
    mambo_ht_t* function_table;
    symbol_table* global_vars;
    void* main_addr;
    char* binary;
    uintptr_t* constructors;
    size_t num_ctr;
    uintptr_t* callbacks;
    size_t num_cb;
};


/* CONSTRUCTORS */

ast_decl* build_var_decl(char* symbol, ast_var_type type);

ast_expr* build_binary_expr(ast_expr* lhs, ast_op op, ast_expr* rhs);
ast_expr* build_call_expr(ast_function* function);
ast_expr* build_cast_expr(ast_expr* expr, ast_cast_type type);
ast_expr* build_dup_expr(ast_expr* vector, ast_expr* scalar, int size);
ast_expr* build_fp32_expr(float value);
ast_expr* build_fp64_expr(double value);
ast_expr* build_int32_expr(int32_t value);
ast_expr* build_uint32_expr(uint32_t value);
ast_expr* build_int64_expr(int64_t value);
ast_expr* build_uint64_expr(uint64_t value);
ast_expr* build_memory_expr(ast_expr* addr, ast_ldst_size size, ast_ldst_type type, uint8_t element_size);
ast_expr* build_string_expr(char* value);
ast_expr* build_ternary_conditional_expr(ast_expr* cond, ast_expr* true_expr, ast_expr* false_expr);
ast_expr* build_unary_expr(ast_op op, ast_expr* expr);
ast_expr* build_var_expr(ast_decl* var);
ast_expr* build_vec_expr(ast_expr* v0, ast_expr* v1, ast_expr* v2, ast_op op, int size);

ast_function* build_function(char* symbol);

ast_stmt* build_break_stmt();
ast_stmt* build_expr_stmt(ast_expr* expr);
ast_stmt* build_conditional_goto_stmt(ast_expr* cond, void* taken, void* skipped);
ast_stmt* build_if_else_stmt(ast_expr* cond, ast_stmt* if_body, ast_stmt* else_body);
ast_stmt* build_indirect_goto_stmt(ast_expr* cond);
ast_stmt* build_label_stmt(void* addr);
ast_stmt* build_return_stmt(ast_expr* ret);
ast_stmt* build_while_stmt(ast_expr* cond, ast_stmt* body);

ast_translation_unit* build_translation_unit(void* main_addr, char* binary);

/* HELPERS */

ast_decl* get_or_create_branch_cond(symbol_table* vars_table);
