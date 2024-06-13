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

// MACROS

#define iterate_mambo_hashmap(type, name) \
    for(int index = 0; index < (name)->size; index++) { \
        if((name)->entries[index].key != 0 && (name)->entries[index].key != -1) { \
            type* val  = (type*) (name)->entries[index].value; \

#define iterate_mambo_hashmap_end() \
        } \
    }
