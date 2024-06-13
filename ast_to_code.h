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

#include "ast/ast.h"

/**
 * Convert AST IR into textual C file.
 *
 * @param file File or stream where the C code should be printed to
 * @param translation_unit Translation unit containing AST IR and symbol information
 */
void convert_ast_to_code(FILE* file, ast_translation_unit* translation_unit);

void generate_trampolines(FILE* file, ast_translation_unit* translation_unit);
void generate_linker_trampolines(FILE* file, ast_translation_unit* translation_unit);
