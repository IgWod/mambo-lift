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

.global native_call
#ifdef HAVE_AS_FUNC
.func native_call
#endif
.type native_call, %function

// TODO: May need to handle x8 as well

native_call:
    ldr x8, [sp, #16] // function
    ldr x9, [sp, #8] // env
    ldr x11, [sp, #0] // sp
    mov x10, x9

    # Move emulated fp registers into the concrete ones
    add x9, x9, #3088
    ld1 { v0.16b }, [x9]
    add x9, x9, #256
    ld1 { v1.16b }, [x9]
    add x9, x9, #256
    ld1 { v2.16b }, [x9]
    add x9, x9, #256
    ld1 { v3.16b }, [x9]
    add x9, x9, #256
    ld1 { v4.16b }, [x9]
    add x9, x9, #256
    ld1 { v5.16b }, [x9]
    add x9, x9, #256
    ld1 { v6.16b }, [x9]
    add x9, x9, #256
    ld1 { v7.16b }, [x9]

    mov x9, x10

    # Preserve frame pointer, link register and callee saved registers
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    mov x20, x9

    # Update the concrete sp with the emulated one
    mov x19, sp
    mov sp, x11
    blr x8
    mov sp, x19

    # Restore frame pointer and link register
    mov x9, x20
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16

    # Move concrete result into the emulated register
    add x9, x9, #3088
    st1 { v0.16b }, [x9]
    add x9, x9, #256
    st1 { v1.16b }, [x9]
    add x9, x9, #256
    st1 { v2.16b }, [x9]
    add x9, x9, #256
    st1 { v3.16b }, [x9]

    ret

#ifdef HAVE_AS_FUNC
.endfunc
#endif

.global helper_fcmpd_aarch64
#ifdef HAVE_AS_FUNC
.func helper_fcmpd_aarch64
#endif
.type helper_fcmpd_aarch64, %function

helper_fcmpd_aarch64:
    fmov d0, x0
    fmov d1, x1

    fcmp d0, d1

    mrs x0, nzcv

    ret

#ifdef HAVE_AS_FUNC
.endfunc
#endif

.global helper_fcmps_aarch64
#ifdef HAVE_AS_FUNC
.func helper_fcmps_aarch64
#endif
.type helper_fcmps_aarch64, %function

helper_fcmps_aarch64:
    fmov s0, w0
    fmov s1, w1

    fcmp s0, s1

    mrs x0, nzcv

    ret

#ifdef HAVE_AS_FUNC
.endfunc
#endif
