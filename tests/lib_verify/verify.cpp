#include "arena.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string_view>

namespace {

int g_failures = 0;

void check(bool condition, std::string_view label)
{
    if (condition) {
        std::printf("[ok]   %.*s\n", static_cast<int>(label.size()), label.data());
        return;
    }

    ++g_failures;
    const char* err = arena_last_error();
    std::printf("[fail] %.*s", static_cast<int>(label.size()), label.data());
    if (err && err[0] != '\0')
        std::printf(" (%s)", err);
    std::printf("\n");
}

static uintptr_t add_two(uintptr_t a, uintptr_t b)
{
    return a + b;
}

static uintptr_t mul_three(uintptr_t a, uintptr_t b, uintptr_t c)
{
    return a * b * c;
}

static uintptr_t return_seven()
{
    return 7;
}

static uintptr_t identity_one(uintptr_t value)
{
    return value;
}

static uintptr_t sum_four(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    return a + b + c + d;
}

static uintptr_t sum_five(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e)
{
    return a + b + c + d + e;
}

static uintptr_t sum_six(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f)
{
    return a + b + c + d + e + f;
}

static uintptr_t sum_seven(
    uintptr_t a,
    uintptr_t b,
    uintptr_t c,
    uintptr_t d,
    uintptr_t e,
    uintptr_t f,
    uintptr_t g)
{
    return a + b + c + d + e + f + g;
}

static uintptr_t sum_eight(
    uintptr_t a,
    uintptr_t b,
    uintptr_t c,
    uintptr_t d,
    uintptr_t e,
    uintptr_t f,
    uintptr_t g,
    uintptr_t h)
{
    return a + b + c + d + e + f + g + h;
}

#if defined(_MSC_VER)
#include <intrin.h>

extern "C" size_t proxy_call_fakestack_size;

static HMODULE g_last_spoof_module = nullptr;

static bool spoof_call_ex(void* fn, const uintptr_t* args, size_t count, uintptr_t* out, bool* crashed);

struct StackProbeResult;
static void run_stack_probe_direct(StackProbeResult* out);
static bool run_stack_probe_spoofed(StackProbeResult* out, bool* crashed);
static void test_spoof_stack_walk(uint32_t max_fakestack);
void test_spoof();

static bool module_image_range(HMODULE module, uintptr_t* out_base, uintptr_t* out_end)
{
    if (!module)
        return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    *out_base = reinterpret_cast<uintptr_t>(module);
    *out_end = *out_base + nt->OptionalHeader.SizeOfImage;
    return true;
}

static bool address_in_module(uintptr_t address, HMODULE module)
{
    uintptr_t base = 0;
    uintptr_t end = 0;
    if (!module_image_range(module, &base, &end))
        return false;
    return address >= base && address < end;
}

struct StackProbeResult {
    uintptr_t return_address = 0;
    uintptr_t backtrace[32]{};
    unsigned backtrace_count = 0;
    bool return_in_spoof_module = false;
    bool return_in_self_module = false;
    bool harness_in_backtrace = false;
    unsigned spoof_module_stack_hits = 0;
};

static constexpr uintptr_t kHarnessFunctionBytes = 0x400;

static bool address_in_harness(uintptr_t address)
{
    const uintptr_t markers[] = {
        reinterpret_cast<uintptr_t>(&run_stack_probe_direct),
        reinterpret_cast<uintptr_t>(&run_stack_probe_spoofed),
        reinterpret_cast<uintptr_t>(&spoof_call_ex),
        reinterpret_cast<uintptr_t>(&stack_probe),
        reinterpret_cast<uintptr_t>(&test_spoof_stack_walk),
        reinterpret_cast<uintptr_t>(&test_spoof),
    };

    for (const uintptr_t marker : markers) {
        if (address >= marker && address < marker + kHarnessFunctionBytes)
            return true;
    }

    return false;
}

static bool address_in_test_entry_harness(uintptr_t address)
{
    const uintptr_t markers[] = {
        reinterpret_cast<uintptr_t>(&test_spoof_stack_walk),
        reinterpret_cast<uintptr_t>(&test_spoof),
    };

    for (const uintptr_t marker : markers) {
        if (address >= marker && address < marker + kHarnessFunctionBytes)
            return true;
    }

    return false;
}

static uintptr_t stack_probe(uintptr_t ctx_ptr)
{
    auto* ctx = reinterpret_cast<StackProbeResult*>(ctx_ptr);
    const HMODULE self_module = GetModuleHandleW(nullptr);
    const HMODULE spoof_module = g_last_spoof_module;

    auto* const ret_slot = reinterpret_cast<uintptr_t*>(_AddressOfReturnAddress());
    ctx->return_address = ret_slot[0];
    ctx->return_in_spoof_module = address_in_module(ctx->return_address, spoof_module);
    ctx->return_in_self_module = address_in_module(ctx->return_address, self_module);

    using RtlCaptureStackBackTraceFn = USHORT(WINAPI*)(ULONG, ULONG, PVOID*, PULONG);
    const auto capture = reinterpret_cast<RtlCaptureStackBackTraceFn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "RtlCaptureStackBackTrace"));
    if (capture) {
        ctx->backtrace_count = capture(
            0,
            static_cast<ULONG>(sizeof(ctx->backtrace) / sizeof(ctx->backtrace[0])),
            reinterpret_cast<PVOID*>(ctx->backtrace),
            nullptr);

        for (unsigned i = 1; i < ctx->backtrace_count; ++i) {
            if (address_in_test_entry_harness(ctx->backtrace[i]))
                ctx->harness_in_backtrace = true;
        }
    }

    for (intptr_t offset = 1; offset <= 128; ++offset) {
        if (address_in_module(ret_slot[-offset], spoof_module))
            ++ctx->spoof_module_stack_hits;
    }

    return 1;
}

static void run_stack_probe_direct(StackProbeResult* out)
{
    *out = {};
    (void)stack_probe(reinterpret_cast<uintptr_t>(out));
}

static bool run_stack_probe_spoofed(StackProbeResult* out, bool* crashed)
{
    *out = {};
    const uintptr_t args[] = { reinterpret_cast<uintptr_t>(out) };
    uintptr_t result = 0;
    if (!spoof_call_ex(reinterpret_cast<void*>(&stack_probe), args, 1, &result, crashed))
        return false;
    return result == 1;
}

static bool spoof_call_ex(void* fn, const uintptr_t* args, size_t count, uintptr_t* out, bool* crashed)
{
    *crashed = false;
    __try {
        return arena_call_ret_spoofed_ex(fn, args, count, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *crashed = true;
        return false;
    }
}

static bool spoof_call_two_arg(uintptr_t* out_sum, bool* crashed)
{
    const uintptr_t args[] = { 10, 32 };
    return spoof_call_ex(reinterpret_cast<void*>(&add_two), args, 2, out_sum, crashed);
}

static bool spoof_call_three_arg(uintptr_t* out_product, bool* crashed)
{
    const uintptr_t args[] = { 2, 3, 4 };
    return spoof_call_ex(reinterpret_cast<void*>(&mul_three), args, 3, out_product, crashed);
}

static uintptr_t spoof_call_zero_arg(bool* crashed)
{
    uintptr_t result = 0;
    if (!spoof_call_ex(reinterpret_cast<void*>(&return_seven), nullptr, 0, &result, crashed))
        return 0;
    return result;
}

static bool init_spoof_module_for_arg_count(size_t arg_count, uint32_t max_fakestack)
{
    const uintptr_t probe_args[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    void* fn = nullptr;
    switch (arg_count) {
    case 0:
        fn = reinterpret_cast<void*>(&return_seven);
        break;
    case 1:
        fn = reinterpret_cast<void*>(&identity_one);
        break;
    case 2:
        fn = reinterpret_cast<void*>(&add_two);
        break;
    case 3:
        fn = reinterpret_cast<void*>(&mul_three);
        break;
    case 4:
        fn = reinterpret_cast<void*>(&sum_four);
        break;
    case 5:
        fn = reinterpret_cast<void*>(&sum_five);
        break;
    case 6:
        fn = reinterpret_cast<void*>(&sum_six);
        break;
    case 7:
        fn = reinterpret_cast<void*>(&sum_seven);
        break;
    case 8:
        fn = reinterpret_cast<void*>(&sum_eight);
        break;
    default:
        return false;
    }

    const wchar_t* modules[] = {
        L"kernel32.dll",
        L"ntdll.dll",
        L"user32.dll",
        L"msvcrt.dll",
    };

    for (const wchar_t* name : modules) {
        auto* base = reinterpret_cast<uint8_t*>(GetModuleHandleW(name));
        if (!base || !arena_spoof_init(base, max_fakestack))
            continue;

        bool crashed = false;
        uintptr_t result = 0;
        if (!spoof_call_ex(fn, probe_args, arg_count, &result, &crashed) || crashed)
            continue;

        if (arg_count == 0 && result != 7)
            continue;
        if (arg_count == 1 && result != 1)
            continue;
        if (arg_count == 2 && result != 3)
            continue;
        if (arg_count == 3 && result != 6)
            continue;
        if (arg_count >= 4 && result != ((arg_count * (arg_count + 1)) / 2))
            continue;

        g_last_spoof_module = reinterpret_cast<HMODULE>(base);
        return true;
    }

    return false;
}

static void test_spoof_stack_depth(size_t arg_count, void* fn, const uintptr_t* args, uintptr_t expected)
{
    char label[96]{};
    std::snprintf(label, sizeof(label), "spoof module init supports %zu arg(s)", arg_count);
    check(init_spoof_module_for_arg_count(arg_count, 0), label);

    bool crashed = false;
    uintptr_t result = 0;

    std::snprintf(
        label,
        sizeof(label),
        "spoof call with %zu arg(s) succeeds",
        arg_count);
    check(spoof_call_ex(fn, args, arg_count, &result, &crashed), label);

    std::snprintf(
        label,
        sizeof(label),
        "spoof call with %zu arg(s) did not crash",
        arg_count);
    check(!crashed, label);

    std::snprintf(
        label,
        sizeof(label),
        "spoof call with %zu arg(s) returns expected value",
        arg_count);
    check(result == expected, label);
}

static void test_spoof_fakestack_depth(uint32_t max_fakestack)
{
    char label[128]{};

    std::snprintf(
        label,
        sizeof(label),
        "spoof init with live fakestack depth %u supports two-arg calls",
        max_fakestack);
    check(init_spoof_module_for_arg_count(2, max_fakestack), label);

    const uintptr_t args[] = { 10, 32 };
    bool crashed = false;
    uintptr_t result = 0;
    std::snprintf(
        label,
        sizeof(label),
        "two-arg spoof call with live fakestack depth %u succeeds",
        max_fakestack);
    check(
        spoof_call_ex(reinterpret_cast<void*>(&add_two), args, 2, &result, &crashed),
        label);

    std::snprintf(
        label,
        sizeof(label),
        "two-arg spoof call with live fakestack depth %u did not crash",
        max_fakestack);
    check(!crashed, label);

    std::snprintf(
        label,
        sizeof(label),
        "two-arg spoof call with live fakestack depth %u returns 42",
        max_fakestack);
    check(result == 42, label);
}

static void test_spoof_stack_walk(uint32_t max_fakestack)
{
    char label[128]{};

    std::snprintf(
        label,
        sizeof(label),
        "spoof init for stack-walk test at fakestack depth %u",
        max_fakestack);
    check(init_spoof_module_for_arg_count(0, max_fakestack), label);

    StackProbeResult direct{};
    run_stack_probe_direct(&direct);

    check(direct.return_in_self_module, "direct call return address is in self module");
    check(direct.harness_in_backtrace, "direct call backtrace reaches test harness");

    StackProbeResult spoofed{};
    bool crashed = false;
    std::snprintf(
        label,
        sizeof(label),
        "spoofed stack probe succeeds at fakestack depth %u",
        max_fakestack);
    check(run_stack_probe_spoofed(&spoofed, &crashed), label);
    check(!crashed, "spoofed stack probe did not crash");

    std::snprintf(
        label,
        sizeof(label),
        "spoofed return address is in spoof module (fakestack %u)",
        max_fakestack);
    check(spoofed.return_in_spoof_module, label);

    std::snprintf(
        label,
        sizeof(label),
        "spoofed return address is not in self module (fakestack %u)",
        max_fakestack);
    check(!spoofed.return_in_self_module, label);

    std::snprintf(
        label,
        sizeof(label),
        "spoofed backtrace does not reach test harness (fakestack %u)",
        max_fakestack);
    check(!spoofed.harness_in_backtrace, label);

    if (max_fakestack > 0) {
        std::snprintf(
            label,
            sizeof(label),
            "fakestack depth %u leaves spoof-module addresses on stack",
            max_fakestack);
        check(spoofed.spoof_module_stack_hits > 0, label);
    }
}
#endif

void test_read_write()
{
    const unsigned char source[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    unsigned char copied[sizeof(source)]{};

    check(
        arena_read_safe(reinterpret_cast<uintptr_t>(source), copied, sizeof(copied)),
        "arena_read_safe reads committed memory");

    check(
        std::memcmp(source, copied, sizeof(source)) == 0,
        "arena_read_safe copies expected bytes");

    arena_read(reinterpret_cast<uintptr_t>(source), copied, sizeof(copied));
    check(
        std::memcmp(source, copied, sizeof(source)) == 0,
        "arena_read copies expected bytes");

    unsigned char target = 0;
    const unsigned char value = 42;
    check(
        arena_write_safe(reinterpret_cast<uintptr_t>(&target), &value, sizeof(value)),
        "arena_write_safe writes committed memory");
    check(target == 42, "arena_write_safe wrote expected value");

    target = 0;
    arena_write(reinterpret_cast<uintptr_t>(&target), &value, sizeof(value));
    check(target == 42, "arena_write wrote expected value");

    copied[0] = 0;
    check(
        !arena_read_safe(0, copied, 1),
        "arena_read_safe rejects null address");
    check(
        std::string_view(arena_last_error()).find("user range") != std::string_view::npos,
        "arena_read_safe sets user-range error on null address");
}

void test_scan()
{
    const unsigned char image[] = {
        0x90, 0x90,
        0x48, 0x8B, 0x15, 0x10, 0x20, 0x30, 0x40,
        0x48, 0x89, 0x05, 0xAA, 0xBB, 0xCC, 0xDD,
        0xC3,
    };

    uintptr_t result = 0;

    check(
        arena_scan_signature_ex(
            image,
            sizeof(image),
            "48 8B 15 ? ? ? ?",
            ARENA_RESOLVE_DIRECT_RVA,
            nullptr,
            &result),
        "arena_scan_signature_ex finds pattern (direct rva)");
    check(result == 2, "direct rva points at match offset");

    ArenaResolveParams rip_params{};
    rip_params.displacement_offset = 3;
    rip_params.instruction_length = 7;
    result = 0;
    check(
        arena_scan_signature_ex(
            image,
            sizeof(image),
            "48 8B 15 ? ? ? ?",
            ARENA_RESOLVE_RIP_RELATIVE32,
            &rip_params,
            &result),
        "arena_scan_signature_ex resolves rip-relative32 target");
    check(
        result == reinterpret_cast<uintptr_t>(image) + 0x40302010 + 9,
        "rip-relative32 target matches expected absolute address");

    ArenaResolveParams abs32_params{};
    abs32_params.displacement_offset = 3;
    result = 0;
    check(
        arena_scan_signature_ex(
            image,
            sizeof(image),
            "48 89 05 ? ? ? ?",
            ARENA_RESOLVE_ABS32,
            &abs32_params,
            &result),
        "arena_scan_signature_ex resolves abs32 target");
    check(
        result == reinterpret_cast<uintptr_t>(image) + 0xDDCCBBAA,
        "abs32 target matches expected absolute address");

    check(
        arena_scan_signature(image, sizeof(image), "FF FF FF FF", ARENA_RESOLVE_DIRECT_RVA, nullptr) == 0,
        "arena_scan_signature returns 0 when pattern is missing");
    check(
        std::string_view(arena_last_error()).find("not found") != std::string_view::npos,
        "missing pattern sets not-found error");
}

void test_spoof()
{
    uintptr_t sum = 0;
    check(
        !arena::call_ret_spoofed<uintptr_t>(
            reinterpret_cast<void*>(&add_two),
            &sum,
            static_cast<uintptr_t>(10),
            static_cast<uintptr_t>(32)),
        "spoof call fails before init");
    check(
        std::string_view(arena_last_error()).find("not initialized") != std::string_view::npos,
        "spoof call before init sets not-initialized error");

    auto* module = reinterpret_cast<uint8_t*>(GetModuleHandleW(L"kernel32.dll"));
    check(module != nullptr, "GetModuleHandleW(kernel32.dll) succeeds");
    check(
        arena_spoof_init(module, 0),
        "arena_spoof_init succeeds on kernel32.dll");

#if defined(_MSC_VER)
    sum = 0;
    bool crashed = false;
    check(spoof_call_two_arg(&sum, &crashed), "arena::call_ret_spoofed returns two-arg result");
    check(!crashed, "two-arg spoof call did not crash");
    check(sum == 42, "spoofed call add_two(10, 32) == 42");

    uintptr_t product = 0;
    crashed = false;
    check(spoof_call_three_arg(&product, &crashed), "arena::call_ret_spoofed returns three-arg result");
    check(!crashed, "three-arg spoof call did not crash");
    check(product == 24, "spoofed call mul_three(2, 3, 4) == 24");

    crashed = false;
    const uintptr_t raw = spoof_call_zero_arg(&crashed);
    check(!crashed, "zero-arg spoof call did not crash");
    check(raw == 7, "arena_call_ret_spoofed wrapper returns zero-arg result");

    const uintptr_t one_arg[] = { 11 };
    const uintptr_t four_args[] = { 1, 2, 3, 4 };
    const uintptr_t five_args[] = { 1, 2, 3, 4, 5 };
    const uintptr_t six_args[] = { 1, 2, 3, 4, 5, 6 };
    const uintptr_t seven_args[] = { 1, 2, 3, 4, 5, 6, 7 };
    const uintptr_t eight_args[] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    test_spoof_stack_depth(1, reinterpret_cast<void*>(&identity_one), one_arg, 11);
    test_spoof_stack_depth(4, reinterpret_cast<void*>(&sum_four), four_args, 10);
    test_spoof_stack_depth(5, reinterpret_cast<void*>(&sum_five), five_args, 15);
    test_spoof_stack_depth(6, reinterpret_cast<void*>(&sum_six), six_args, 21);
    test_spoof_stack_depth(7, reinterpret_cast<void*>(&sum_seven), seven_args, 28);
    test_spoof_stack_depth(8, reinterpret_cast<void*>(&sum_eight), eight_args, 36);

    test_spoof_fakestack_depth(0);
    test_spoof_fakestack_depth(16);
    test_spoof_fakestack_depth(64);
    test_spoof_fakestack_depth(256);

    check(init_spoof_module_for_arg_count(6, 64), "spoof init with live fakestack depth 64 supports six-arg calls");
    {
        const uintptr_t args[] = { 1, 2, 3, 4, 5, 6 };
        bool crashed = false;
        uintptr_t result = 0;
        check(
            spoof_call_ex(reinterpret_cast<void*>(&sum_six), args, 6, &result, &crashed),
            "six-arg spoof call with live fakestack depth 64 succeeds");
        check(!crashed, "six-arg spoof call with live fakestack depth 64 did not crash");
        check(result == 21, "six-arg spoof call with live fakestack depth 64 returns 21");
    }

    test_spoof_stack_walk(0);
    test_spoof_stack_walk(64);
#else
    check(false, "spoof call live tests require MSVC SEH wrapper on Windows");
#endif
}

} // namespace

int main()
{
    std::printf("arena.lib verification\n");
    std::printf("----------------------\n");

    test_read_write();
    test_scan();
    test_spoof();

    std::printf("----------------------\n");
    if (g_failures == 0) {
        std::printf("all checks passed\n");
        return 0;
    }

    std::printf("%d check(s) failed\n", g_failures);
    return 1;
}
