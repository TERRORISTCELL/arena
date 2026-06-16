#include "arena.h"

#include <cstdint>

static uintptr_t add_two(uintptr_t a, uintptr_t b)
{
    return a + b;
}

int main()
{
    const unsigned char bytes[] = { 0x48, 0x8B, 0x15, 0x01, 0x02, 0x03, 0x04 };

    uintptr_t result = 0;
    ArenaResolveParams params{};
    if (!arena_scan_signature_ex(bytes, sizeof(bytes), "48 8B 15 ? ? ? ?", ARENA_RESOLVE_DIRECT_RVA, &params, &result))
        return 1;

    unsigned char copied[sizeof(bytes)]{};
    if (!arena_read_safe(reinterpret_cast<uintptr_t>(bytes), copied, sizeof(copied)))
        return 2;

    unsigned char writable = 0;
    const unsigned char value = 7;
    if (!arena_write_safe(reinterpret_cast<uintptr_t>(&writable), &value, sizeof(value)))
        return 3;

    uintptr_t typed_result = 0;
    (void)arena::call_ret_spoofed<uintptr_t>(
        reinterpret_cast<void*>(&add_two),
        &typed_result,
        static_cast<uintptr_t>(1),
        static_cast<uintptr_t>(2));

    (void)arena_spoof_init;
    (void)arena_call_ret_spoofed_ex;
    (void)arena_call_ret_spoofed;
    (void)arena_last_error;

    return 0;
}
