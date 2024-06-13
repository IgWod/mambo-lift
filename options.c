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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef GIT_HASH
    #define GIT_HASH "dirty"
#endif

#include "options.h"

global_options options = {NULL, "", false, false, false, false, false, false};

static struct option long_options[] = {
    {"help",                 no_argument,       0, 'h'},
    {"version",              no_argument,       0, 'v'},
    {"cmp-opt",              no_argument,       0, 'c'},
    {"vfp-opt",              no_argument,       0, 'f'},
    {"support-longjmp",      no_argument,       0, 'l'},
    {"static",               required_argument, 0, 's'},
    {"add-asserts",          no_argument,       0, 'a'},
    {"reset-trampolines",    required_argument, 0, 't'},
    {0, 0, 0, 0}
};

static void print_usage() {
    printf("Usage: lifter [options] <binary>\n");
    printf("Options:\n");
    printf("  -h, --help                Show this help message\n");
    printf("  -v, --version             Show program version\n");
    printf("  --support-longjmp         Enable support for setjmp/longjmp in the lifted code\n");
    printf("  --static [full|partial]   Enable static lifting with a selected strategy\n");
    printf("  --add-asserts             Add assert(0) to unexplored branches\n");
    printf("Expetimental options:\n");
    printf("  --cmp-opt                 Optimise TCG comparisons\n");
    printf("  --vfp-opt                 Optimise TCG floating-point emulation\n");
    printf("  --reset-trampolines addr  Replace trampolines with RETs\n");
    printf("Positional arguments:\n");
    printf("  <input>                   Binary to lift\n");
}

void parse_options(int argc, char** argv) {
    int opt, option_index = 0;

    while ((opt = getopt_long(argc, argv, "hvcfls:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                printf("Program version %s\n", GIT_HASH);
                exit(EXIT_SUCCESS);
                break;
            case 'c':
                options.cmp_opts = true;
                break;
            case 'f':
                options.vfp_opts = true;
                break;
            case 'l':
                options.longjmps = true;
                break;
            case 's':
                options.static_lifting = true;
                if(strcmp(optarg, "full") == 0) {
                    options.full_static_lifting = true;
                }
                break;
            case 'a':
                options.asserts = true;
                break;
            case 't':
                options.trampolines = optarg;
                break;
            case '?':
                print_usage();
                exit(EXIT_FAILURE);
                break;
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        options.input_file = argv[optind];
    } else {
        fprintf(stderr, "Error: Input binary is required\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
}

