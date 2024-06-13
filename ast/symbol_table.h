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

#include <stddef.h>

#include "../common/typedefs.h"

// HELPERS

/**
 * Iterate over all non-NULL elements of the symbol table.
 */
#define iterate_symbol_table(type, table) \
for(int index = 0; index < (table)->size; index++) { \
    if((table)->entries[index].name != NULL) { \
        type* val  = (type*) (table)->entries[index].symbol; \

#define iterate_symbol_table_end() \
    } \
}

// STRUCTS

/**
 * Structure holding the symbol table.
 */
struct symbol_table {
    size_t size; ///< Currently allocated number of entries.
    size_t entry_count; ///< Currently used number of entries.

    symbol_table_entry *entries; ///< Array of entries.
};

/**
 * Single entry to the symbol table consisting of a name and opaque pointer to the symbol table record.
 */
struct symbol_table_entry {
    char *name; ///< Name of the symbol.
    void *symbol; ///< Pointer to the actual symbol.
};

// FUNCTIONS

/**
 * Initialize a symbol table with an initial size. Object of symbol_table has to be allocated before being passed
 * to the function. It is assumed table in not NULL.
 *
 * @param table Symbol table to be initialized
 * @param initial_size Initial size of the symbol table (minimum 16)
 */
void symbol_table_init(symbol_table *table, size_t initial_size);

/**
 * Get a record from the symbol table for the given name, or return NULL if there is no matching record. It is assumed
 * neither name nor table are NULL.
 *
 * @param table Symbol table to be searched
 * @param name Name of the symbol
 * @return Pointer to the record or NULL if no record found
 */
void *symbol_table_lookup(symbol_table *table, char *name);

/**
 * Add new record, stored as an opaque pointer, to the symbol table. If the record with a given name already exists
 * the function terminates by calling exit(-1). It is assumed none of the arguments is NULL.
 *
 * @param table Symbol table where the record is inserted
 * @param name  Name of the symbol to be inserted
 * @param symbol Opaque pointer to the record
 */
void symbol_table_check_insert(symbol_table *table, char *name, void *symbol);

/**
 * Add new record, stored as an opaque pointer, to the symbol table. If the record with a given name already exists
 * do nothing. It is assumed none of the arguments is NULL.
 *
 * @param table Symbol table where the record is inserted
 * @param name  Name of the symbol to be inserted
 * @param symbol Opaque pointer to the record
 */
void symbol_table_insert(symbol_table *table, char *name, void *symbol);
