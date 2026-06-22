#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(ARENA_SHARED)
#  if defined(ARENA_BUILD)
#    define ARENA_API __declspec(dllexport)
#  else
#    define ARENA_API __declspec(dllimport)
#  endif
#else
#  define ARENA_API
#endif

typedef enum ArenaResolveKind {
    ARENA_RESOLVE_DIRECT_RVA = 0,
    ARENA_RESOLVE_RIP_RELATIVE32 = 1,
    ARENA_RESOLVE_MATCH_ADDRESS = 2,
    ARENA_RESOLVE_ABS32 = 3,
    ARENA_RESOLVE_ABS64 = 4,
    ARENA_RESOLVE_MATCH_RVA_PLUS_OFFSET = 5,
} ArenaResolveKind;

typedef struct ArenaResolveParams {
    uint32_t displacement_offset;
    uint32_t instruction_length;
    intptr_t extra_offset;
} ArenaResolveParams;

/* Validate pages with VirtualQuery, then copy. Use for probing unknown memory. */
ARENA_API bool arena_read_safe(uintptr_t address, void* out, size_t size);

/* Fast unchecked read. Invalid memory may fault. */
ARENA_API void arena_read(uintptr_t address, void* out, size_t size);

ARENA_API bool arena_write_safe(uintptr_t address, const void* data, size_t size);
ARENA_API void arena_write(uintptr_t address, const void* data, size_t size);

/*
 * Build spoof tables from a loaded module image (typically the game exe).
 * Must be called once before arena_call_ret_spoofed.
 */
ARENA_API bool arena_spoof_init(uint8_t* module_base, uint32_t max_fakestack);

/*
 * Call `fn` with args[0..count-1] while spoofing the return stack.
 * Uses Microsoft x64 integer/pointer registers and stack slots.
 * Supports 0..8 integer/pointer arguments and uintptr_t-sized returns only.
 * Floating-point/vector arguments and returns are not supported.
 */
ARENA_API bool arena_call_ret_spoofed_ex(
    void* fn,
    const uintptr_t* args,
    size_t count,
    uintptr_t* out_return);

/* Convenience wrapper. Returns 0 on failure; use arena_call_ret_spoofed_ex to disambiguate. */
ARENA_API uintptr_t arena_call_ret_spoofed(void* fn, const uintptr_t* args, size_t count);

/*
 * Scan [base, base+size) for `pattern` ("48 8B ? ?" style).
 * Returns true and writes `out_result` on success. Meaning depends on resolve_kind:
 *   DIRECT_RVA        - offset from base to match
 *   RIP_RELATIVE32    - absolute address (needs params)
 *   MATCH_ADDRESS     - absolute address of match
 *   ABS32             - base + *(uint32_t*)(match + disp_offset)
 *   ABS64             - *(uint64_t*)(match + disp_offset)
 *   MATCH_RVA_PLUS_OFFSET - offset from base to match, plus params->extra_offset
 */
ARENA_API bool arena_scan_signature_ex(
    const void* base,
    size_t size,
    const char* pattern,
    ArenaResolveKind resolve_kind,
    const ArenaResolveParams* params,
    uintptr_t* out_result);

/* Convenience wrapper. Returns 0 on failure; use arena_scan_signature_ex to allow RVA 0. */
ARENA_API uintptr_t arena_scan_signature(
    const void* base,
    size_t size,
    const char* pattern,
    ArenaResolveKind resolve_kind,
    const ArenaResolveParams* params);

/* Retrieves the last thread-local error code for this thread. */
ARENA_API uint32_t arena_last_error(void);

#ifdef __cplusplus
}

#include <array>
#include <type_traits>

namespace arena {

template <typename T>
inline constexpr bool spoof_arg_supported =
    std::is_integral_v<T> || std::is_enum_v<T> || std::is_pointer_v<T>;

template <typename T>
inline constexpr bool spoof_return_supported =
    std::is_void_v<T> || std::is_integral_v<T> || std::is_enum_v<T> || std::is_pointer_v<T>;

template <typename T>
inline uintptr_t pack_spoof_arg(T value)
{
    static_assert(spoof_arg_supported<T>, "arena spoof args must be integer, enum, or pointer types");
    if constexpr (std::is_pointer_v<T>)
        return reinterpret_cast<uintptr_t>(value);
    else
        return static_cast<uintptr_t>(value);
}

template <typename Ret>
inline Ret unpack_spoof_return(uintptr_t value)
{
    static_assert(spoof_return_supported<Ret>, "arena spoof return must be void, integer, enum, or pointer type");
    if constexpr (std::is_pointer_v<Ret>)
        return reinterpret_cast<Ret>(value);
    else
        return static_cast<Ret>(value);
}

template <typename Ret, typename... Args>
inline bool call_ret_spoofed(void* fn, Ret* out, Args... args)
{
    static_assert(!std::is_void_v<Ret>, "use arena::call_ret_spoofed_void for void returns");
    static_assert(sizeof...(Args) <= 8, "arena spoof calls support at most 8 arguments");
    static_assert((spoof_arg_supported<Args> && ...), "arena spoof args must be integer, enum, or pointer types");
    static_assert(spoof_return_supported<Ret>, "arena spoof return must be integer, enum, or pointer type");

    std::array<uintptr_t, sizeof...(Args)> packed = { pack_spoof_arg(args)... };
    uintptr_t raw = 0;
    if (!arena_call_ret_spoofed_ex(fn, sizeof...(Args) == 0 ? nullptr : packed.data(), sizeof...(Args), &raw))
        return false;

    if (out)
        *out = unpack_spoof_return<Ret>(raw);
    return true;
}

template <typename... Args>
inline bool call_ret_spoofed_void(void* fn, Args... args)
{
    static_assert(sizeof...(Args) <= 8, "arena spoof calls support at most 8 arguments");
    static_assert((spoof_arg_supported<Args> && ...), "arena spoof args must be integer, enum, or pointer types");

    std::array<uintptr_t, sizeof...(Args)> packed = { pack_spoof_arg(args)... };
    uintptr_t ignored = 0;
    return arena_call_ret_spoofed_ex(fn, sizeof...(Args) == 0 ? nullptr : packed.data(), sizeof...(Args), &ignored);
}

} // namespace arena
#endif

#ifdef ARENA_SHORT_NAMES
#  define read_safe         arena_read_safe
#  define read              arena_read
#  define write_safe        arena_write_safe
#  define write             arena_write
#  define call_ret_spoofed_ex arena_call_ret_spoofed_ex
#  define call_ret_spoofed  arena_call_ret_spoofed
#  define scan_signature_ex arena_scan_signature_ex
#  define scan_signature    arena_scan_signature
#endif
