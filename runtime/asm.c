// Bit manipulations

static int64_t mambo_lift_clz64(int64_t x) {
    int64_t result;
    __asm ("CLZ %[output], %[input]"
    : [output] "=r"(result)
    : [input] "r"(x)
    );
    return result;
}

static int32_t mambo_lift_clz32(int32_t x) {
    int32_t result;
    __asm ("CLZ %w[output], %w[input]"
    : [output] "=r"(result)
    : [input] "r"(x)
    );
    return result;
}

static int64_t mambo_lift_rbit64(int64_t x) {
    int64_t result;
    __asm ("RBIT %[output], %[input]"
    : [output] "=r"(result)
    : [input] "r"(x)
    );
    return result;
}

static int32_t mambo_lift_rbit(int32_t x) {
    int32_t result;
    __asm ("RBIT %w[output], %w[input]"
    : [output] "=r"(result)
    : [input] "r"(x)
    );
    return result;
}

// MRS

static int64_t mambo_lift_mrs_tpidr() {
    int64_t result;
    __asm ("mrs %[output], tpidr_el0"
    : [output] "=r"(result)
    );
    return result;
}

static int64_t mambo_lift_mrs_fpcr() {
    int64_t result;
    __asm ("mrs %[output], fpcr"
    : [output] "=r"(result)
    );
    return result;
}

static int64_t mambo_lift_mrs_fpsr() {
    int64_t result;
    __asm ("mrs %[output], fpsr"
    : [output] "=r"(result)
    );
    return result;
}

static int64_t mambo_lift_mrs_dczid()
{
    int64_t result;
    __asm ("mrs %[output], dczid_el0"
    : [output] "=r"(result)
    );
    return result;
}

static int64_t mambo_lift_mrs_cntvct()
{
    int64_t result;
    __asm ("mrs %[output], cntvct_el0"
    : [output] "=r"(result)
    );
    return result;
}

// MSR

static void mambo_lift_msr_tpidr(int64_t x) {
    __asm ("msr tpidr_el0, %[input]"
    : [input] "=r"(x)
    );
}

static void mambo_lift_msr_fpcr(int64_t x) {
    __asm ("msr fpcr, %[input]"
    : [input] "=r"(x)
    );
}

// System instructions

static void mambo_lift_dc_zva(int64_t x) {
    __asm __volatile__ ("dc zva, %[input]"
    : [input] "+r"(x)
    );
}

// Exclusive loads

static int32_t mambo_ldxr_32(int64_t a) {
    int32_t result;
    __asm ("LDXR w0, [x0]"
    : "=r"(result)
    : "r"(a)
    );
    return result;
}

static int32_t mambo_ldaxr_32(int64_t a) {
    int32_t result;
    __asm ("LDAXR w0, [x0]"
    : "=r"(result)
    : "r"(a)
    );
    return result;
}

static int64_t mambo_ldxr_64(int64_t a) {
    int64_t result;
    __asm ("LDXR x0, [x0]"
    : "=r"(result)
    : "r"(a)
    );
    return result;
}

static int64_t mambo_ldaxr_64(int64_t a) {
    int64_t result;
    __asm ("LDAXR x0, [x0]"
    : "=r"(result)
    : "r"(a)
    );
    return result;
}

// Exclusive stores

static int32_t mambo_stxr_32(int32_t s, int32_t v, int64_t a) {
    int32_t result;
    __asm ("STXR w0, w1, [x2]"
    : "=r"(result)
    : "r"(v), "r"(a)
    );
    return result;
}

static int32_t mambo_stlxr_32(int32_t s, int32_t v, int64_t a) {
    int32_t result;
    __asm ("STLXR w0, w1, [x2]"
    : "=r"(result)
    : "r"(v), "r"(a)
    );
    return result;
}

static int32_t mambo_stxr_64(int32_t s, int64_t v, int64_t a) {
    int32_t result;
    __asm ("STXR w0, x1, [x2]"
    : "=r"(result)
    : "r"(v), "r"(a)
    );
    return result;
}

static int32_t mambo_stlxr_64(int32_t s, int64_t v, int64_t a) {
    int32_t result;
    __asm ("STLXR w0, x1, [x2]"
    : "=r"(result)
    : "r"(v), "r"(a)
    );
    return result;
}

// Long mul

static int64_t __mulh(int64_t a, int64_t b) {
    int64_t result;
    __asm ("SMULH %[x], %[y], %[z]"
    : [x] "=r"(result)
    : [y] "r"(a), [z] "r"(b)
    );
    return result;
}

// BRK

static void helper_aarch64_brk() {
}

