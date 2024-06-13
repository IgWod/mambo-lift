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

#include <stdbool.h>

struct global_options;
typedef struct global_options global_options;

struct global_options {
    char* input_file;
    char* trampolines;

    bool longjmps;
    bool static_lifting;
    bool full_static_lifting;
    bool cmp_opts;
    bool vfp_opts;
    bool asserts;
};

extern global_options options;

void parse_options(int argc, char** argv);
