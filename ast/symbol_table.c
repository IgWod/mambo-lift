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

#include <assert.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "symbol_table.h"

/*
 * Simple function to compute a hash for a given null-terminated string. It is, supposedly, based on Java hashing
 * method (https://stackoverflow.com/questions/2624192/good-hash-function-for-strings).
 */
static uint64_t primary_hash(char *string) {
    assert(string != NULL);

    uint64_t hash = 7;
    char c;
    while ((c = *string++) != '\0') {
        hash = hash * 31 + c;
    }
    return hash;
}

void symbol_table_init(symbol_table *table, size_t initial_size) {
    assert(table != NULL);

    if (initial_size < 16) {
        fprintf(stderr, "MAMBO Lift: Initial size of the symbol table has to be at least 16!\n");
        exit(-1);
    }

    table->entries = (symbol_table_entry *) calloc(initial_size, sizeof(symbol_table_entry));
    if (table->entries == NULL) {
        fprintf(stderr, "MAMBO Lift: Failed to allocate the symbol table!\n");
        exit(-1);
    }

    table->size = initial_size;
    table->entry_count = 0;
}

void *symbol_table_lookup(symbol_table *table, char *name) {
    assert(table != NULL && name != NULL);

    uint64_t hash = primary_hash(name) % table->size;

    // TODO: Use secondary hash rather than a simple increment.
    while (table->entries[hash].name != NULL && strcmp(name, table->entries[hash].name) != 0) {
        hash = (hash + 1) % table->size;
    }

    if (table->entries[hash].name != NULL) {
        return table->entries[hash].symbol;
    }

    return NULL;
}

/*
 * Double the size of the given symbol table. This function allocates a new memory region for the entries, rehashes
 * current entries into this new region, and frees the previously used space.
 */
static void resize(symbol_table *table) {
    assert(table != NULL);

    symbol_table_entry *prev_entries = table->entries;
    size_t prev_size = table->size;

    table->size = table->size * 2;

    table->entries = (symbol_table_entry *) calloc(table->size, sizeof(symbol_table_entry));
    if (table->entries == NULL) {
        fprintf(stderr, "MAMBO Lift: Failed to allocate the symbol table!\n");
        exit(-1);
    }

    for (int i = 0; i < prev_size; i++) {
        if (prev_entries[i].name != NULL) {
            symbol_table_check_insert(table, prev_entries[i].name, prev_entries[i].symbol);
        }
    }

    free(prev_entries);
}

/*
 * Implements the actual insertion that either fails if the name already exists or allows it and does nothing.
 */
void symbol_table_insert_internal(symbol_table *table, char *name, void *symbol, bool check) {
    assert(table != NULL && name != NULL && symbol != NULL);

    if ((table->entry_count * 100 / table->size) >= 80) {
        resize(table);
    }

    // NOTE: Technically we could share this code with symbol_table_lookup.
    uint64_t hash = primary_hash(name) % table->size;

    while (table->entries[hash].name != NULL && strcmp(name, table->entries[hash].name) != 0) {
        hash = (hash + 1) % table->size;
    }

    if (table->entries[hash].name != NULL) {
        if(check) {
            fprintf(stderr, "MAMBO Lift: Record with a given name in the symbol table already exists!\n");
            fprintf(stderr, "MAMBO Lift: Found: %s == %s!\n", table->entries[hash].name, name);
            exit(-1);
        } else {
            return;
        }
    }

    table->entries[hash].name = name;
    table->entries[hash].symbol = symbol;

    table->entry_count++;
}

void symbol_table_check_insert(symbol_table *table, char *name, void *symbol) {
    symbol_table_insert_internal(table, name, symbol, true);
}

void symbol_table_insert(symbol_table *table, char *name, void *symbol) {
    symbol_table_insert_internal(table, name, symbol, false);
}
