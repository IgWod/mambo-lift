// Declaration of QEMU helpers

int64_t helper_vfp_fcvtds_aarch64(int32_t, int64_t);
int32_t helper_vfp_fcvtsd_aarch64(int64_t, int64_t);
int64_t helper_vfp_addd_aarch64(int64_t, int64_t, int64_t);
int64_t helper_vfp_cmpd_a64_aarch64(int64_t, int64_t, int64_t);
int64_t helper_vfp_absd_aarch64(int64_t);
int32_t helper_vfp_adds_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_divs_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_sqtos_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_divd_aarch64(int64_t, int64_t, int64_t);
int64_t helper_vfp_muld_aarch64(int64_t, int64_t, int64_t);
int64_t helper_vfp_muladdd_aarch64(int64_t, int64_t, int64_t, int64_t);
int64_t helper_vfp_subd_aarch64(int64_t, int64_t, int64_t);
int64_t helper_vfp_negd_aarch64(int64_t);
int64_t helper_vfp_cmps_a64_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_muls_aarch64(int32_t, int32_t, int64_t);
int64_t helper_vfp_tosld_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_cmpes_a64_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_subs_aarch64(int32_t, int32_t, int64_t);
int64_t helper_vfp_cmped_a64_aarch64(int64_t, int64_t, int64_t);
int64_t helper_vfp_sqtod_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_tosqd_aarch64(int64_t, int32_t, int64_t);
int32_t helper_vfp_tosls_aarch64(int32_t, int32_t,int64_t);
int32_t helper_vfp_abss_aarch64(int32_t);
int64_t helper_vfp_uqtod_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_sqrtd_aarch64(int64_t, int64_t);
int32_t helper_vfp_uqtos_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_touqs_aarch64(int32_t, int32_t, int64_t);
int64_t helper_vfp_tosqs_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_muladds_aarch64(int32_t, int32_t, int32_t, int64_t);
int32_t helper_vfp_sitos_aarch64(int32_t, int64_t);
int64_t helper_vfp_touqd_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_tould_aarch64(int64_t, int32_t, int64_t);
int64_t helper_vfp_maxnumd_aarch64(int64_t, int64_t, int64_t);
int32_t helper_vfp_sqrts_aarch64(int32_t, int64_t);
int32_t helper_vfp_negs_aarch64(int32_t);
int32_t helper_vfp_maxnums_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_touls_aarch64(int32_t, int32_t, int64_t);
int64_t helper_vfp_minnumd_aarch64(int64_t, int64_t, int64_t);
int32_t helper_vfp_minnums_aarch64(int32_t, int32_t, int64_t);
int32_t helper_vfp_uitos_aarch64(int32_t, int64_t);

int32_t helper_neon_ceq_u8_aarch64(int32_t, int32_t);
int32_t helper_neon_padd_u8_aarch64(int32_t, int32_t);
int32_t helper_neon_cnt_u8_aarch64(int32_t);
int32_t helper_neon_narrow_u16_aarch64(int64_t);
int32_t helper_neon_narrow_u8_aarch64(int64_t);
int64_t helper_neon_widen_u16_aarch64(int32_t);
int64_t helper_neon_addl_u32_aarch64(int64_t, int64_t);
int32_t helper_neon_abd_s32_aarch64(int32_t, int32_t);
int64_t helper_neon_mull_s16_aarch64(int32_t, int32_t);
int64_t helper_neon_widen_s16_aarch64(int64_t);
int64_t helper_neon_widen_u8_aarch64(int32_t);
int64_t helper_neon_addl_u16_aarch64(int64_t, int64_t);
int32_t helper_neon_mul_u16_aarch64(int32_t, int32_t);
int64_t helper_neon_subl_u32_aarch64(int64_t, int64_t);
int64_t helper_neon_mull_u8_aarch64(int32_t, int32_t);
int64_t helper_neon_subl_u16_aarch64(int64_t, int64_t);
int64_t helper_neon_cgt_s16_aarch64(int32_t, int32_t);
int64_t helper_neon_rhadd_u8_aarch64(int32_t, int32_t);
int64_t helper_neon_cgt_f64_aarch64(int64_t, int64_t, int64_t);
int32_t helper_neon_cge_f32_aarch64(int32_t, int32_t, int64_t);
int32_t helper_neon_cgt_f32_aarch64(int32_t, int32_t, int64_t);
int32_t helper_neon_cgt_s8_aarch64(int32_t, int32_t);
int64_t helper_neon_addlp_u16_aarch64(int64_t);

int32_t helper_set_rmode_aarch64(int32_t, int64_t);
int64_t helper_rintd_aarch64(int64_t, int64_t);
int32_t helper_rints_aarch64(int32_t, int64_t);
int64_t helper_mulsh_i64_aarch64(int64_t, int64_t);
int64_t helper_muluh_i64_aarch64(int64_t,int64_t);
int64_t helper_simd_tbl_aarch64(int64_t, int64_t, int64_t, int32_t, int32_t);

void helper_gvec_dup64_aarch64(int64_t, int32_t, int64_t);

// Native function calls

typedef union int64_var int64_var;

int64_t native_call(int64_t x0, int64_t x1, int64_t x2, int64_t x3, int64_t x4, int64_t x5, int64_t x6, int64_t x7, int64_t sp, int64_t env, void* function);

int64_t native_setjmp(int64_t x0, void* state);
void native_longjmp(int64_t x0, int64_t x1, void* state);

int64_t helper_fcmps_aarch64(int64_t s0, int64_t s1);
int64_t helper_fcmpd_aarch64(int64_t d0, int64_t d1);

// Non-source function (cannot be included but available to link)

int __asprintf_chk (char **result_ptr, int flag, const char *format, ...);
int __printf_chk(int flag, const char * format, ...);
int __fprintf_chk(FILE * stream, int flag, const char * format, ...);
int __vsprintf_chk (char *__restrict __s, int __flag, size_t __slen, const char *__restrict __format, __gnuc_va_list __ap);
char * __strcpy_chk(char * dest, const char * src, size_t destlen);
int __vfprintf_chk (FILE *__restrict __stream, int __flag, const char *__restrict __format, __gnuc_va_list __ap);
int __sprintf_chk(char * str, int flag, size_t strlen, const char * format, ...);
char * __realpath_chk(const char * path, char * resolved_path, size_t resolved_len);
int __snprintf_chk(char * str, size_t maxlen, int flag, size_t strlen, const char * format, ...);
char * __strcat_chk(char * dest, const char * src, size_t destlen);
char * __strncat_chk(char * s1, const char * s2, size_t n, size_t s1len);
void __syslog_chk (int __pri, int __flag, const char *__fmt, ...);
void * __memcpy_chk(void * dest, const void * src, size_t len, size_t destlen);
int __vsnprintf_chk(char * s, size_t maxlen, int flag, size_t slen, const char * format, va_list args);
wchar_t * __wcsncpy_chk(wchar_t * dest, const wchar_t * src, size_t n, size_t destlen);
void * __memset_chk(void * dest, int c, size_t len, size_t destlen);
char * __stpcpy_chk(char * dest, const char * src, size_t destlen);
void __longjmp_chk (void * __env, int __val);
int __vasprintf_chk (char **result_ptr, int flags, const char *format, va_list args);
extern void __strncpy_chk(void); // TOOD: Full signature
extern size_t __fread_chk (void *__restrict __ptr, size_t __ptrlen, size_t __size, size_t __n, FILE *__restrict __stream);

double __powidf2 (double a, int b);
extern void __divtf3(void);
extern void __extenddftf2(void);
extern void __floatunsitf(void);
extern void __gttf2(void);
extern void __multf3(void);
extern void __subtf3(void);
extern void __trunctfdf2(void);
extern void __lttf2(void);
extern void __powisf2(void);

// OpenMP

int64_t GOMP_parallel(int64_t, int64_t, int64_t, int64_t);
void GOMP_barrier(void);

void omp_get_max_threads(void);
void omp_get_max_threads_(void);
void omp_get_thread_num(void);
void omp_get_num_threads(void);


// Fortran

extern void _gfortran_stop_numeric(void);
extern void _gfortran_count_4_l(void);
extern void _gfortran_cshift0_4(void);
extern void _gfortran_get_command_argument_i4(void);
extern void _gfortran_iargc(void);
extern void _gfortran_reshape_4(void);
extern void _gfortran_set_args(void);
extern void _gfortran_set_options(void);
extern void _gfortran_st_close(void);
extern void _gfortran_st_open(void);
extern void _gfortran_st_read(void);
extern void _gfortran_st_read_done(void);
extern void _gfortran_st_write(void);
extern void _gfortran_st_write_done(void);
extern void _gfortran_stop_string(void);
extern void _gfortran_transfer_array(void);
extern void _gfortran_transfer_array_write(void);
extern void _gfortran_transfer_character(void);
extern void _gfortran_transfer_integer(void);
extern void _gfortran_transfer_integer_write(void);
extern void _gfortran_mminloc0_4_i4(void);
extern void _gfortran_transfer_character_write(void);
extern void _gfortran_compare_string(void);
extern void _gfortran_concat_string(void);
extern void _gfortran_st_inquire(void);
extern void _gfortran_st_rewind(void);
extern void _gfortran_string_index(void);
extern void _gfortran_string_len_trim(void);
extern void _gfortran_transfer_real(void);
extern void _gfortran_transfer_real_write(void);
extern void _gfortran_pow_i4_i4(void);
extern void _gfortran_transfer_logical_write(void);
extern void _gfortran_st_set_nml_var(void);
extern void _gfortran_st_set_nml_var_dim(void);
extern void _gfortran_date_and_time(void);
extern void _gfortran_select_string(void);
extern void _gfortran_string_trim(void);
extern void _gfortran_system_clock_4(void);
extern void _gfortran_adjustl(void);
extern void _gfortran_internal_pack(void);
extern void _gfortran_transfer_complex_write(void);
extern void _gfortran_st_backspace(void);
extern void _gfortran_string_scan(void);
extern void _gfortran_string_verify(void);
extern void _gfortran_size0(void);
extern void _gfortran_spread(void);
extern void _gfortran_cpu_time_8(void);
extern void _gfortran_runtime_error_at(void);
extern void _gfortran_os_error(void);
extern void _gfortran_runtime_error(void);
extern void _gfortran_transfer_complex(void);
extern void _gfortran_spread_char_scalar(void);
extern void _gfortran_random_r8(void);
extern void _gfortran_reshape_r8(void);
extern void _gfortran_matmul_r8(void);
extern void _gfortran_matmul_c8(void);
extern void _gfortran_internal_unpack(void);
extern void _gfortran_pack(void);
extern void _gfortran_pack_char(void);

extern void __libc_start_main(void);
extern void __cxa_finalize(void);

extern void _dl_find_dso_for_object(void);
extern void __tunable_get_val(void);

void __stack_chk_fail() { while (1); }

extern char __executable_start;

