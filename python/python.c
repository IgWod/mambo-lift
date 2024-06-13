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

#include <Python.h>

#include "hash_table.h"

#include "python/python.h"

PyObject *global_dict;

mambo_ht_t* symbol_cache = NULL;
mambo_ht_t* plt_cache = NULL;

int initialize_python() {
    Py_Initialize();

    const char* env = getenv("LIFT_ROOT");

    char path[1024];

    sprintf(path, "%s/python/parse_elf.py", env);

    FILE* file = fopen(path, "r");
    PyRun_SimpleFile(file, path);

    PyObject* main_module = PyImport_AddModule("__main__");
    global_dict = PyModule_GetDict(main_module);
}

int destroy_python() {
    Py_DECREF(global_dict);
    Py_Finalize();
}

static int get_section(char* function, char* filename, int* section_addr, int* section_size, char** code) {
    PyObject *expression;

    expression = PyDict_GetItemString(global_dict, function);

    PyObject* result = PyObject_CallFunction(expression, "s", filename);

    Py_buffer py_code;

    if(PyTuple_Check(result)) {
        if (!PyArg_ParseTuple(result, "iiy*", section_addr, section_size, &py_code)) {
            PyErr_Print();
        }
    } else {
        PyErr_Print();
    }

    *code = (char*)py_code.buf;

    PyBuffer_Release(&py_code);

    return 0;
} 

int get_text_section(char* filename, int* section_addr, int* section_size, char** code) {
    return get_section("get_text_section", filename, section_addr, section_size, code);
}

int get_plt_section(char* filename, int* section_addr, int* section_size, char** code) {
    return get_section("get_plt_section", filename, section_addr, section_size, code);
}

int get_init_array_section(char* filename, int* section_addr, int* section_size, char** code) {
    return get_section("get_init_array_section", filename, section_addr, section_size, code);
}

static int get_info_by_addr(char* function, char* filename, void* addr, char** symbol) {
    PyObject *expression;

    expression = PyDict_GetItemString(global_dict, function);

    PyObject* result = PyObject_CallFunction(expression, "sL", filename, addr);

    if(PyUnicode_Check(result)) {
        if(*symbol = (char*)PyUnicode_AsUTF8(result)) {
            PyErr_Print();
        }
    } else {
        PyErr_Print();
    }

    if(strcmp(*symbol, "") == 0) {
        *symbol = NULL;
    }
 
    if(*symbol != NULL && strlen(*symbol) == 0) {
        *symbol = NULL;
    }

    return 0;
}

static int cache_symbols_generic(char* filename, mambo_ht_t** cache, char* function) {
    *cache = (mambo_ht_t *) malloc(sizeof(mambo_ht_t));
    if (*cache == NULL) {
        fprintf(stderr, "mclift: Couldn't allocate the hash map!\n");
        return -1;
    }

    int ret = mambo_ht_init(*cache, 1 << 12, 0, 80, true);
    if (ret) {
        fprintf(stderr, "mclift: Couldn't initialize the hash map!\n");
        return -1;
    }

    PyObject *expression;

    expression = PyDict_GetItemString(global_dict, function);

    PyObject* result = PyObject_CallFunction(expression, "s", filename);

    if (PyList_Check(result)) {
        Py_ssize_t size = PyList_Size(result);
        for (Py_ssize_t i = 0; i < size; i++) {
            PyObject *item = PyList_GetItem(result, i);
            if (PyTuple_Check(item)) {
                uintptr_t addr;
                const char* symbol;
                if (!PyArg_ParseTuple(item, "Ks", &addr, &symbol)) {
                    PyErr_Print();
                } else {
                    if(addr != (uintptr_t) NULL) {
                        mambo_ht_add_nolock(*cache, (uintptr_t) addr, (uintptr_t) strdup(symbol));
                    }
                }
            } else {
                PyErr_Print();
            }
        }
    } else {
        PyErr_Print();
    }

    return 0;
}

static int cache_plt(char* filename) {
    return cache_symbols_generic(filename, &plt_cache, "get_plt_symbols");
}

int get_plt_symbol_by_addr(char* filename, void* addr, char** symbol) {
    if(plt_cache == NULL) {
        cache_plt(filename);
    }

    int ret = mambo_ht_get_nolock(plt_cache, (uintptr_t) addr, (void *) symbol);

    if(!ret) {
        return 0;
    }

    return -1;

    // TODO: Disable fallback to improve the performance. It assumes that if the symbol
    // is not in the cache it is not available at all.
    // return get_info_by_addr("get_plt_symbol_by_addr", filename, addr, symbol);
}

static int cache_symbols(char* filename) {
    return cache_symbols_generic(filename, &symbol_cache, "get_symbols");
}

int get_symbol_info_by_addr(char* filename, void* addr, char** symbol) {
    if(symbol_cache == NULL) {
        cache_symbols(filename);
    }

    int ret = mambo_ht_get_nolock(symbol_cache, (uintptr_t) addr, (void *) symbol);

    if(!ret) {
        return 0;
    }

    return -1;

    // TODO: Disable fallback to improve the performance. It assumes that if the symbol
    // is not in the cache it is not available at all.
    // return get_info_by_addr("get_symbol_info_by_addr", filename, addr, symbol);
}
