#ifndef PONY_DETAIL_ATOMICS_H
#define PONY_DETAIL_ATOMICS_H

#if !defined(__ARM_ARCH_2__) && !defined(__arm__) && !defined(__aarch64__) && \
 !defined(__i386__) && !defined(_M_IX86) && !defined(_X86_) && \
 !defined(__amd64__) && !defined(__x86_64__) && !defined(_M_X64) && \
 !defined(_M_AMD64)
#  error "Unsupported platform"
#endif

#ifndef __cplusplus
#  include <stdalign.h>
#endif

#ifdef _MSC_VER
// MSVC has no support of C11 atomics.
#  include <atomic>
#  define PONY_ATOMIC(T) std::atomic<T>
#  define PONY_ATOMIC_RVALUE(T) std::atomic<T>
#  ifdef PONY_WANT_ATOMIC_DEFS
using std::memory_order_relaxed;
using std::memory_order_consume;
using std::memory_order_acquire;
using std::memory_order_release;
using std::memory_order_acq_rel;
using std::memory_order_seq_cst;

using std::atomic_load_explicit;
using std::atomic_store_explicit;
using std::atomic_exchange_explicit;
using std::atomic_compare_exchange_weak_explicit;
using std::atomic_compare_exchange_strong_explicit;
using std::atomic_fetch_add_explicit;
using std::atomic_fetch_sub_explicit;
using std::atomic_thread_fence;
#  endif
#elif defined(__GNUC__) && !defined(__clang__)
#  if ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((4) << 16) + (9))
#    ifdef __cplusplus
//     g++ doesn't like C11 atomics. We never need atomic ops in C++ files so
//     we only define the atomic types.
#      include <atomic>
#      define PONY_ATOMIC(T) std::atomic<T>
#      define PONY_ATOMIC_RVALUE(T) std::atomic<T>
#    else
#      ifdef PONY_WANT_ATOMIC_DEFS
#        include <stdatomic.h>
#      endif
#      define PONY_ATOMIC(T) T _Atomic
#      define PONY_ATOMIC_RVALUE(T) T _Atomic
#    endif
#  elif ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((4) << 16) + (7))
#    define PONY_ATOMIC(T) alignas(sizeof(T)) T
#    define PONY_ATOMIC_RVALUE(T) T
#    define PONY_ATOMIC_BUILTINS
#  else
#    error "Please use GCC >= 4.7"
#  endif
#elif defined(__clang__)
#  if __clang_major__ >= 4 || (__clang_major__ == 3 && __clang_minor__ >= 6)
#    ifdef PONY_WANT_ATOMIC_DEFS
#      ifdef __DragonFly__

// Include stdatomic.h verbatim
//
//

/*===---- stdatomic.h - Standard header for atomic types and operations -----===
 *
 * Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 * See https://llvm.org/LICENSE.txt for license information.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 *===-----------------------------------------------------------------------===
 */

#ifndef __CLANG_STDATOMIC_H
#define __CLANG_STDATOMIC_H

/* If we're hosted, fall back to the system's stdatomic.h. FreeBSD, for
 * example, already has a Clang-compatible stdatomic.h header.
 */
#if 0 /* __STDC_HOSTED__ && __has_include_next(<stdatomic.h>) */
# include_next <stdatomic.h>
#else

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 7.17.1 Introduction */

#define ATOMIC_BOOL_LOCK_FREE       __CLANG_ATOMIC_BOOL_LOCK_FREE
#define ATOMIC_CHAR_LOCK_FREE       __CLANG_ATOMIC_CHAR_LOCK_FREE
#define ATOMIC_CHAR16_T_LOCK_FREE   __CLANG_ATOMIC_CHAR16_T_LOCK_FREE
#define ATOMIC_CHAR32_T_LOCK_FREE   __CLANG_ATOMIC_CHAR32_T_LOCK_FREE
#define ATOMIC_WCHAR_T_LOCK_FREE    __CLANG_ATOMIC_WCHAR_T_LOCK_FREE
#define ATOMIC_SHORT_LOCK_FREE      __CLANG_ATOMIC_SHORT_LOCK_FREE
#define ATOMIC_INT_LOCK_FREE        __CLANG_ATOMIC_INT_LOCK_FREE
#define ATOMIC_LONG_LOCK_FREE       __CLANG_ATOMIC_LONG_LOCK_FREE
#define ATOMIC_LLONG_LOCK_FREE      __CLANG_ATOMIC_LLONG_LOCK_FREE
#define ATOMIC_POINTER_LOCK_FREE    __CLANG_ATOMIC_POINTER_LOCK_FREE

/* 7.17.2 Initialization */

#define ATOMIC_VAR_INIT(value) (value)
#define atomic_init __c11_atomic_init

/* 7.17.3 Order and consistency */

typedef enum memory_order {
  memory_order_relaxed = __ATOMIC_RELAXED,
  memory_order_consume = __ATOMIC_CONSUME,
  memory_order_acquire = __ATOMIC_ACQUIRE,
  memory_order_release = __ATOMIC_RELEASE,
  memory_order_acq_rel = __ATOMIC_ACQ_REL,
  memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;

#define kill_dependency(y) (y)

/* 7.17.4 Fences */

/* These should be provided by the libc implementation. */
void atomic_thread_fence(memory_order);
void atomic_signal_fence(memory_order);

#define atomic_thread_fence(order) __c11_atomic_thread_fence(order)
#define atomic_signal_fence(order) __c11_atomic_signal_fence(order)

/* 7.17.5 Lock-free property */

#define atomic_is_lock_free(obj) __c11_atomic_is_lock_free(sizeof(*(obj)))

/* 7.17.6 Atomic integer types */

#ifdef __cplusplus
typedef _Atomic(bool)               atomic_bool;
#else
typedef _Atomic(_Bool)              atomic_bool;
#endif
typedef _Atomic(char)               atomic_char;
typedef _Atomic(signed char)        atomic_schar;
typedef _Atomic(unsigned char)      atomic_uchar;
typedef _Atomic(short)              atomic_short;
typedef _Atomic(unsigned short)     atomic_ushort;
typedef _Atomic(int)                atomic_int;
typedef _Atomic(unsigned int)       atomic_uint;
typedef _Atomic(long)               atomic_long;
typedef _Atomic(unsigned long)      atomic_ulong;
typedef _Atomic(long long)          atomic_llong;
typedef _Atomic(unsigned long long) atomic_ullong;
typedef _Atomic(uint_least16_t)     atomic_char16_t;
typedef _Atomic(uint_least32_t)     atomic_char32_t;
typedef _Atomic(wchar_t)            atomic_wchar_t;
typedef _Atomic(int_least8_t)       atomic_int_least8_t;
typedef _Atomic(uint_least8_t)      atomic_uint_least8_t;
typedef _Atomic(int_least16_t)      atomic_int_least16_t;
typedef _Atomic(uint_least16_t)     atomic_uint_least16_t;
typedef _Atomic(int_least32_t)      atomic_int_least32_t;
typedef _Atomic(uint_least32_t)     atomic_uint_least32_t;
typedef _Atomic(int_least64_t)      atomic_int_least64_t;
typedef _Atomic(uint_least64_t)     atomic_uint_least64_t;
typedef _Atomic(int_fast8_t)        atomic_int_fast8_t;
typedef _Atomic(uint_fast8_t)       atomic_uint_fast8_t;
typedef _Atomic(int_fast16_t)       atomic_int_fast16_t;
typedef _Atomic(uint_fast16_t)      atomic_uint_fast16_t;
typedef _Atomic(int_fast32_t)       atomic_int_fast32_t;
typedef _Atomic(uint_fast32_t)      atomic_uint_fast32_t;
typedef _Atomic(int_fast64_t)       atomic_int_fast64_t;
typedef _Atomic(uint_fast64_t)      atomic_uint_fast64_t;
typedef _Atomic(intptr_t)           atomic_intptr_t;
typedef _Atomic(uintptr_t)          atomic_uintptr_t;
typedef _Atomic(size_t)             atomic_size_t;
typedef _Atomic(ptrdiff_t)          atomic_ptrdiff_t;
typedef _Atomic(intmax_t)           atomic_intmax_t;
typedef _Atomic(uintmax_t)          atomic_uintmax_t;

/* 7.17.7 Operations on atomic types */

#define atomic_store(object, desired) __c11_atomic_store(object, desired, __ATOMIC_SEQ_CST)
#define atomic_store_explicit __c11_atomic_store

#define atomic_load(object) __c11_atomic_load(object, __ATOMIC_SEQ_CST)
#define atomic_load_explicit __c11_atomic_load

#define atomic_exchange(object, desired) __c11_atomic_exchange(object, desired, __ATOMIC_SEQ_CST)
#define atomic_exchange_explicit __c11_atomic_exchange

#define atomic_compare_exchange_strong(object, expected, desired) __c11_atomic_compare_exchange_strong(object, expected, desired, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_strong_explicit __c11_atomic_compare_exchange_strong

#define atomic_compare_exchange_weak(object, expected, desired) __c11_atomic_compare_exchange_weak(object, expected, desired, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_weak_explicit __c11_atomic_compare_exchange_weak

#define atomic_fetch_add(object, operand) __c11_atomic_fetch_add(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_add_explicit __c11_atomic_fetch_add

#define atomic_fetch_sub(object, operand) __c11_atomic_fetch_sub(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub_explicit __c11_atomic_fetch_sub

#define atomic_fetch_or(object, operand) __c11_atomic_fetch_or(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_or_explicit __c11_atomic_fetch_or

#define atomic_fetch_xor(object, operand) __c11_atomic_fetch_xor(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor_explicit __c11_atomic_fetch_xor

#define atomic_fetch_and(object, operand) __c11_atomic_fetch_and(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_and_explicit __c11_atomic_fetch_and

/* 7.17.8 Atomic flag type and operations */

typedef struct atomic_flag { atomic_bool _Value; } atomic_flag;

#define ATOMIC_FLAG_INIT { 0 }

/* These should be provided by the libc implementation. */
#ifdef __cplusplus
bool atomic_flag_test_and_set(volatile atomic_flag *);
bool atomic_flag_test_and_set_explicit(volatile atomic_flag *, memory_order);
#else
_Bool atomic_flag_test_and_set(volatile atomic_flag *);
_Bool atomic_flag_test_and_set_explicit(volatile atomic_flag *, memory_order);
#endif
void atomic_flag_clear(volatile atomic_flag *);
void atomic_flag_clear_explicit(volatile atomic_flag *, memory_order);

#define atomic_flag_test_and_set(object) __c11_atomic_exchange(&(object)->_Value, 1, __ATOMIC_SEQ_CST)
#define atomic_flag_test_and_set_explicit(object, order) __c11_atomic_exchange(&(object)->_Value, 1, order)

#define atomic_flag_clear(object) __c11_atomic_store(&(object)->_Value, 0, __ATOMIC_SEQ_CST)
#define atomic_flag_clear_explicit(object, order) __c11_atomic_store(&(object)->_Value, 0, order)

#ifdef __cplusplus
}
#endif

#endif /* __STDC_HOSTED__ */
#endif /* __CLANG_STDATOMIC_H */


#      else
#        include <stdatomic.h>
#      endif
#    endif
#    define PONY_ATOMIC(T) T _Atomic
#    define PONY_ATOMIC_RVALUE(T) T _Atomic
#  elif __clang_major__ >= 3 && __clang_minor__ >= 4
#    define PONY_ATOMIC(T) alignas(sizeof(T)) T
#    define PONY_ATOMIC_RVALUE(T) T
#    define PONY_ATOMIC_BUILTINS
#  else
#    error "Please use Clang >= 3.4"
#  endif
#else
#  error "Unsupported compiler"
#endif

#ifdef _MSC_VER
namespace ponyint_atomics
{
  template <typename T>
  struct aba_protected_ptr_t
  {
    // Nested struct for uniform initialisation with GCC/Clang.
    struct
    {
      T* object;
      uintptr_t counter;
    };
  };
}
#  define PONY_ABA_PROTECTED_PTR_DECLARE(T)
#  define PONY_ABA_PROTECTED_PTR(T) ponyint_atomics::aba_protected_ptr_t<T>
#else
#  if defined(__LP64__) || defined(_WIN64)
#    define PONY_DOUBLEWORD __int128_t
#  else
#    define PONY_DOUBLEWORD int64_t
#  endif
#  define PONY_ABA_PROTECTED_PTR_DECLARE(T) \
    typedef union \
    { \
      struct \
      { \
        T* object; \
        uintptr_t counter; \
      }; \
      PONY_DOUBLEWORD raw; \
    } aba_protected_##T;
#  define PONY_ABA_PROTECTED_PTR(T) aba_protected_##T
#endif

// We provide our own implementation of big atomic objects (larger than machine
// word size) because we need special functionalities that aren't provided by
// standard atomics. In particular, we need to be able to do both atomic and
// non-atomic operations on big objects since big atomic operations (e.g.
// CMPXCHG16B on x86_64) are very expensive.
#define PONY_ATOMIC_ABA_PROTECTED_PTR(T) \
    alignas(sizeof(PONY_ABA_PROTECTED_PTR(T))) PONY_ABA_PROTECTED_PTR(T)

#ifdef PONY_WANT_ATOMIC_DEFS
#  ifdef _MSC_VER
#    pragma warning(push)
#    pragma warning(disable:4164)
#    pragma warning(disable:4800)
#    pragma intrinsic(_InterlockedCompareExchange128)

namespace ponyint_atomics
{
  template <typename T>
  inline PONY_ABA_PROTECTED_PTR(T) big_load(PONY_ABA_PROTECTED_PTR(T)* ptr)
  {
    PONY_ABA_PROTECTED_PTR(T) ret = {NULL, 0};
    _InterlockedCompareExchange128((LONGLONG*)ptr, 0, 0, (LONGLONG*)&ret);
    return ret;
  }

  template <typename T>
  inline void big_store(PONY_ABA_PROTECTED_PTR(T)* ptr,
    PONY_ABA_PROTECTED_PTR(T) val)
  {
    PONY_ABA_PROTECTED_PTR(T) tmp;
    tmp.object = ptr->object;
    tmp.counter = ptr->counter;
    while(!_InterlockedCompareExchange128((LONGLONG*)ptr,
      (LONGLONG)val.counter, (LONGLONG)val.object, (LONGLONG*)&tmp))
    {}
  }

  template <typename T>
  inline bool big_cas(PONY_ABA_PROTECTED_PTR(T)* ptr,
    PONY_ABA_PROTECTED_PTR(T)* exp, PONY_ABA_PROTECTED_PTR(T) des)
  {
    return _InterlockedCompareExchange128((LONGLONG*)ptr, (LONGLONG)des.counter,
      (LONGLONG)des.object, (LONGLONG*)exp);
  }
}

#    define bigatomic_load_explicit(PTR, MO) \
      ponyint_atomics::big_load(PTR)

#    define bigatomic_store_explicit(PTR, VAL, MO) \
      ponyint_atomics::big_store(PTR, VAL)

#    define bigatomic_compare_exchange_weak_explicit(PTR, EXP, DES, SUCC, FAIL) \
      ponyint_atomics::big_cas(PTR, EXP, DES)

#    pragma warning(pop)
#  else
#    define bigatomic_load_explicit(PTR, MO) \
      ({ \
        _Static_assert(sizeof(*(PTR)) == (2 * sizeof(void*)), ""); \
        (__typeof__(*(PTR)))__atomic_load_n(&(PTR)->raw, MO); \
      })

#    define bigatomic_store_explicit(PTR, VAL, MO) \
      ({ \
        _Static_assert(sizeof(*(PTR)) == (2 * sizeof(void*)), ""); \
        __atomic_store_n(&(PTR)->raw, (VAL).raw, MO); \
      })

#    define bigatomic_compare_exchange_weak_explicit(PTR, EXP, DES, SUCC, FAIL) \
      ({ \
        _Static_assert(sizeof(*(PTR)) == (2 * sizeof(void*)), ""); \
        __atomic_compare_exchange_n(&(PTR)->raw, &(EXP)->raw, (DES).raw, true, \
          SUCC, FAIL); \
      })
#  endif

#  ifdef PONY_ATOMIC_BUILTINS
#    define memory_order_relaxed __ATOMIC_RELAXED
#    define memory_order_consume __ATOMIC_CONSUME
#    define memory_order_acquire __ATOMIC_ACQUIRE
#    define memory_order_release __ATOMIC_RELEASE
#    define memory_order_acq_rel __ATOMIC_ACQ_REL
#    define memory_order_seq_cst __ATOMIC_SEQ_CST

#    define atomic_load_explicit(PTR, MO) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_load_n(PTR, MO); \
      })

#    define atomic_store_explicit(PTR, VAL, MO) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_store_n(PTR, VAL, MO); \
      })

#    define atomic_exchange_explicit(PTR, VAL, MO) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_exchange_n(PTR, VAL, MO); \
      })

#    define atomic_compare_exchange_weak_explicit(PTR, EXP, DES, SUCC, FAIL) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_compare_exchange_n(PTR, EXP, DES, true, SUCC, FAIL); \
      })

#    define atomic_compare_exchange_strong_explicit(PTR, EXP, DES, SUCC, FAIL) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_compare_exchange_n(PTR, EXP, DES, false, SUCC, FAIL); \
      })

#    define atomic_fetch_add_explicit(PTR, VAL, MO) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_fetch_add(PTR, VAL, MO); \
      })

#    define atomic_fetch_sub_explicit(PTR, VAL, MO) \
      ({ \
        _Static_assert(sizeof(PTR) <= sizeof(void*), ""); \
        __atomic_fetch_sub(PTR, VAL, MO); \
      })

#    define atomic_thread_fence(MO) \
      __atomic_thread_fence(MO)

#    undef PONY_ATOMIC_BUILTINS
#  endif
#endif

#endif
