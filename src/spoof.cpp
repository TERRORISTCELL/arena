#include "arena.h"
#include "error.hpp"
#include "errors.h"
#include <string>

#ifdef _WIN32
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

extern "C" void spoofcall_stub();

extern "C" uintptr_t proxy_call_returns[];
extern "C" size_t proxy_call_fakestack_size;
extern "C" uintptr_t* proxy_call_fakestack;

namespace {

constexpr uintptr_t kSpoofSentinel = 0x46C4660ULL;
constexpr std::size_t kReturnSlotCount = 32;
constexpr LONG kMaxPeHeaderOffset = 0x100000;

std::array<bool, kReturnSlotCount> g_return_slot_ready{};
bool g_spoof_ready = false;

unsigned custom_rand(int start, int end)
{
    if (start == end)
        return static_cast<unsigned>(start);

    static unsigned state = 0xACE1U;
    state += 0x3AD;
    state %= static_cast<unsigned>(end - start + 1);

    while (state < static_cast<unsigned>(start))
        state += static_cast<unsigned>(end - start + 1);

    return state;
}

using Spoof0 = uintptr_t(__fastcall*)(uintptr_t, void*);
using Spoof1 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, void*);
using Spoof2 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, void*);
using Spoof3 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, void*);
using Spoof4 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, void*);
using Spoof5 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, void*);
using Spoof6 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, void*);
using Spoof7 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, void*);
using Spoof8 = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, void*);

bool protection_allows_read(DWORD protect)
{
    const DWORD access = protect & 0xFF;
    return access == PAGE_READONLY ||
           access == PAGE_READWRITE ||
           access == PAGE_WRITECOPY ||
           access == PAGE_EXECUTE_READ ||
           access == PAGE_EXECUTE_READWRITE ||
           access == PAGE_EXECUTE_WRITECOPY;
}

bool readable_range(const void* address, std::size_t size)
{
    if (!address && size != 0)
        return false;

    const auto start = reinterpret_cast<uintptr_t>(address);
    if (size == 0)
        return true;
    if (size > UINTPTR_MAX - start)
        return false;

    const uintptr_t end = start + size;
    uintptr_t cursor = start;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT)
            return false;
        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
            return false;
        if (!protection_allows_read(mbi.Protect))
            return false;

        const auto region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        if (mbi.RegionSize > UINTPTR_MAX - region_base)
            return false;

        const uintptr_t region_end = region_base + mbi.RegionSize;
        if (region_end <= cursor)
            return false;
        cursor = region_end;
    }

    return true;
}

void reset_spoof_state()
{
    std::fill(g_return_slot_ready.begin(), g_return_slot_ready.end(), false);
    std::memset(proxy_call_returns, 0, kReturnSlotCount * sizeof(proxy_call_returns[0]));
    proxy_call_fakestack_size = 0;
    delete[] proxy_call_fakestack;
    proxy_call_fakestack = nullptr;
    g_spoof_ready = false;
}

bool validate_pe_image(uint8_t* module_base, IMAGE_NT_HEADERS** out_nt)
{
    if (!module_base) {
        arena::set_error(ARENA_E_SPOOF_BASE_NULL);
        return false;
    }

    if (!readable_range(module_base, sizeof(IMAGE_DOS_HEADER))) {
        arena::set_error(ARENA_E_SPOOF_DOS_READ);
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        arena::set_error(ARENA_E_SPOOF_DOS_SIG);
        return false;
    }

    const auto module_address = reinterpret_cast<uintptr_t>(module_base);
    const auto pe_offset = static_cast<uintptr_t>(dos->e_lfanew);
    if (dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        dos->e_lfanew > kMaxPeHeaderOffset ||
        module_address > UINTPTR_MAX - pe_offset ||
        module_address + pe_offset > UINTPTR_MAX - sizeof(IMAGE_NT_HEADERS)) {
        arena::set_error(ARENA_E_SPOOF_PE_OFFSET);
        return false;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
    if (!readable_range(nt, sizeof(IMAGE_NT_HEADERS))) {
        arena::set_error(ARENA_E_SPOOF_NT_READ);
        return false;
    }

    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        arena::set_error(ARENA_E_SPOOF_NT_SIG);
        return false;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        arena::set_error(ARENA_E_SPOOF_NOT_X64);
        return false;
    }

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        arena::set_error(ARENA_E_SPOOF_NOT_PE32);
        return false;
    }

    if (nt->OptionalHeader.SizeOfImage == 0) {
        arena::set_error(ARENA_E_SPOOF_IMAGE_SIZE);
        return false;
    }

    if (nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.NumberOfSections > 96) {
        arena::set_error(ARENA_E_SPOOF_SECTION_COUNT);
        return false;
    }

    const std::size_t section_bytes =
        static_cast<std::size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    const auto* section = IMAGE_FIRST_SECTION(nt);
    if (!readable_range(section, section_bytes)) {
        arena::set_error(ARENA_E_SPOOF_SECTION_READ);
        return false;
    }

    *out_nt = nt;
    return true;
}

bool add_size(uintptr_t value, std::size_t size, uintptr_t* out)
{
    if (size > UINTPTR_MAX - value)
        return false;
    *out = value + size;
    return true;
}

bool required_return_slot(size_t count, std::size_t* out_slot)
{
    if (count <= 5) {
        *out_slot = 5;
        return true;
    }
    if (count <= 7) {
        *out_slot = 7;
        return true;
    }
    if (count == 8) {
        *out_slot = 9;
        return true;
    }
    return false;
}

} // namespace

extern "C" bool arena_spoof_init(uint8_t* module_base, uint32_t max_fakestack)
{
    arena::clear_error();
    reset_spoof_state();

    try {
        IMAGE_NT_HEADERS* nt = nullptr;
        if (!validate_pe_image(module_base, &nt))
            return false;

        const auto image_size = nt->OptionalHeader.SizeOfImage;
        const auto module_address = reinterpret_cast<uintptr_t>(module_base);
        uintptr_t module_end{};
        if (!add_size(module_address, image_size, &module_end)) {
            arena::set_error(ARENA_E_SPOOF_RANGE_OVERFLOW);
            return false;
        }

        std::map<int8_t, std::vector<uintptr_t>> proxy_clean_returns;
        auto* section = IMAGE_FIRST_SECTION(nt);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
                ++section;
                continue;
            }

            if (section->VirtualAddress >= image_size) {
                ++section;
                continue;
            }

            const auto section_size = section->Misc.VirtualSize;
            if (section_size == 0) {
                ++section;
                continue;
            }

            uintptr_t section_start{};
            uintptr_t section_end{};
            if (!add_size(module_address, section->VirtualAddress, &section_start) ||
                !add_size(section_start, section_size, &section_end)) {
                ++section;
                continue;
            }
            section_end = std::min(section_end, module_end);

            auto* address = reinterpret_cast<uint8_t*>(section_start);
            while (reinterpret_cast<uintptr_t>(address) < section_end) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(address, &mbi, sizeof(mbi)))
                    break;

                auto* base_page = static_cast<uint8_t*>(mbi.BaseAddress);
                const auto page_start = reinterpret_cast<uintptr_t>(base_page);
                uintptr_t page_end{};
                if (!add_size(page_start, mbi.RegionSize, &page_end) || page_end <= reinterpret_cast<uintptr_t>(address))
                    break;

                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
                    protection_allows_read(mbi.Protect)) {
                    const uintptr_t scan_start = std::max(page_start, section_start);
                    const uintptr_t scan_end = std::min(page_end, section_end);
                    if (scan_end > scan_start) {
                        const auto first = static_cast<std::size_t>(scan_start - page_start);
                        const auto last = static_cast<std::size_t>(scan_end - page_start);
                        for (std::size_t j = first; j + 0x10 < last; ++j) {
                            if (j >= 6 &&
                                base_page[j - 6] == 0xFF &&
                                base_page[j - 5] == 0x15 &&
                                base_page[j] == 0x48 &&
                                base_page[j + 1] == 0x83 &&
                                base_page[j + 2] == 0xC4 &&
                                base_page[j + 4] == 0xC3) {
                                proxy_clean_returns[static_cast<int8_t>(base_page[j + 3])].push_back(
                                    reinterpret_cast<uintptr_t>(base_page + j));
                            }
                        }
                    }
                }

                address = reinterpret_cast<uint8_t*>(page_end);
            }

            ++section;
        }

        std::vector<int8_t> proxy_clean_returns_keys;
        proxy_clean_returns_keys.reserve(proxy_clean_returns.size());

        std::vector<uintptr_t> fakestack;
        fakestack.reserve(static_cast<std::size_t>(max_fakestack) * 2);

        for (auto& entry : proxy_clean_returns) {
            if (entry.first <= 0 || entry.first % static_cast<int8_t>(sizeof(uintptr_t)) != 0)
                continue;

            const auto index = static_cast<std::size_t>(entry.first / static_cast<int8_t>(sizeof(uintptr_t)));
            if (index >= kReturnSlotCount || entry.second.empty())
                continue;

            proxy_call_returns[index] = entry.second.at(custom_rand(10, 30) % entry.second.size());
            g_return_slot_ready[index] = true;

            if (index < 10 && index % 2 == 1)
                proxy_clean_returns_keys.push_back(entry.first);
        }

        std::size_t minimum_slot{};
        if (!required_return_slot(0, &minimum_slot) || !g_return_slot_ready[minimum_slot]) {
            arena::set_error(ARENA_E_SPOOF_RETURN_SLOT_NOT_FOUND);
            reset_spoof_state();
            return false;
        }

        while (fakestack.size() < max_fakestack && !proxy_clean_returns_keys.empty()) {
            const auto pseudo_random = custom_rand(10, 30);
            const auto return_length = proxy_clean_returns_keys.at(pseudo_random % proxy_clean_returns_keys.size());
            const auto params = return_length / static_cast<int8_t>(sizeof(uintptr_t));
            const auto& address_array = proxy_clean_returns[return_length];
            const auto random_address = address_array.at(pseudo_random % address_array.size());
            const auto entry_slots = 1u + static_cast<std::size_t>(params);

            if (fakestack.size() + entry_slots > max_fakestack)
                break;

            fakestack.push_back(random_address);
            for (auto p = 0; p < params; ++p)
                fakestack.push_back(module_address + (custom_rand(10, 30) % image_size));
        }

        if (!fakestack.empty()) {
            proxy_call_fakestack = new uintptr_t[fakestack.size()];
            std::memcpy(proxy_call_fakestack, fakestack.data(), fakestack.size() * sizeof(uintptr_t));
        }
        proxy_call_fakestack_size = fakestack.size();
        g_spoof_ready = true;
        arena::clear_error();
        return true;
    } catch (...) {
        reset_spoof_state();
        arena::set_error(ARENA_E_SPOOF_INIT_FAILED);
        return false;
    }
}

extern "C" bool arena_call_ret_spoofed_ex(void* fn, const uintptr_t* args, size_t count, uintptr_t* out_return)
{
    arena::clear_error();

    if (!out_return) {
        arena::set_error(ARENA_E_SPOOF_MISSING_OUTPUT);
        return false;
    }

    *out_return = 0;

    if (!fn) {
        arena::set_error(ARENA_E_SPOOF_TARGET_NULL);
        return false;
    }

    if (count > 0 && !args) {
        arena::set_error(ARENA_E_SPOOF_ARGS_NULL);
        return false;
    }

    std::size_t slot{};
    if (!required_return_slot(count, &slot)) {
        arena::set_error(ARENA_E_SPOOF_TOO_MANY_ARGS);
        return false;
    }

    if (!g_spoof_ready || !g_return_slot_ready[slot] || proxy_call_returns[slot] == 0) {
        arena::set_error(ARENA_E_SPOOF_SLOT_NOT_INIT);
        return false;
    }

    auto* stub = reinterpret_cast<void*>(spoofcall_stub);

    switch (count) {
    case 0:
        *out_return = reinterpret_cast<Spoof0>(stub)(kSpoofSentinel, fn);
        break;
    case 1:
        *out_return = reinterpret_cast<Spoof1>(stub)(args[0], kSpoofSentinel, fn);
        break;
    case 2:
        *out_return = reinterpret_cast<Spoof2>(stub)(args[0], args[1], kSpoofSentinel, fn);
        break;
    case 3:
        *out_return = reinterpret_cast<Spoof3>(stub)(args[0], args[1], args[2], kSpoofSentinel, fn);
        break;
    case 4:
        *out_return = reinterpret_cast<Spoof4>(stub)(args[0], args[1], args[2], args[3], kSpoofSentinel, fn);
        break;
    case 5:
        *out_return = reinterpret_cast<Spoof5>(stub)(args[0], args[1], args[2], args[3], args[4], kSpoofSentinel, fn);
        break;
    case 6:
        *out_return = reinterpret_cast<Spoof6>(stub)(args[0], args[1], args[2], args[3], args[4], args[5], kSpoofSentinel, fn);
        break;
    case 7:
        *out_return = reinterpret_cast<Spoof7>(stub)(args[0], args[1], args[2], args[3], args[4], args[5], args[6], kSpoofSentinel, fn);
        break;
    case 8:
        *out_return = reinterpret_cast<Spoof8>(stub)(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], kSpoofSentinel, fn);
        break;
    default:
        arena::set_error(ARENA_E_SPOOF_TOO_MANY_ARGS);
        return false;
    }

    arena::clear_error();
    return true;
}
#else
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <vector>

// Forward declare the System V assembly spoof stub
extern "C" uintptr_t arena_call_sysv_spoof(
    void* fn,
    const uintptr_t* args,
    size_t count,
    uintptr_t gadget_jmp,
    uintptr_t gadget_ret
);

namespace {

uintptr_t g_gadget_jmp = 0;
uintptr_t g_gadget_ret = 0;
bool g_linux_spoof_ready = false;

// Scan loaded ELF segment regions for gadgets:
// gadget_jmp: a direct jump: "jmp r10" -> "41 FF E2" or "jmp *%r10"
// gadget_ret: a standard return instruction: "ret" -> "C3"
int find_elf_gadgets_callback(struct dl_phdr_info* info, size_t size, void* data)
{
    (void)size;
    (void)data;

    // Avoid scanning self main binary if possible, search inside shared libs (like libc.so)
    std::string name = info->dlpi_name;
    if (name.find("libc.so") == std::string::npos) {
        return 0; // Keep searching until we hit libc
    }

    for (int i = 0; i < info->dlpi_phnum; i++) {
        // Only scan executable program segments
        if (info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags & PF_X)) {
            uint8_t* start = reinterpret_cast<uint8_t*>(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            size_t len = info->dlpi_phdr[i].p_memsz;

            // Search for:
            // 1. "jmp r10" -> \x41\xFF\xE2
            // 2. "ret" -> \xC3
            for (size_t j = 0; j < len - 3; j++) {
                if (!g_gadget_jmp && start[j] == 0x41 && start[j+1] == 0xFF && start[j+2] == 0xE2) {
                    g_gadget_jmp = reinterpret_cast<uintptr_t>(start + j);
                }
                if (!g_gadget_ret && start[j] == 0xC3) {
                    g_gadget_ret = reinterpret_cast<uintptr_t>(start + j);
                }
                if (g_gadget_jmp && g_gadget_ret) {
                    return 1; // Done searching!
                }
            }
        }
    }
    return 0;
}

} // namespace

extern "C" bool arena_spoof_init(uint8_t* module_base, uint32_t max_fakestack)
{
    (void)module_base;
    (void)max_fakestack;
    
    arena::clear_error();
    g_gadget_jmp = 0;
    g_gadget_ret = 0;
    g_linux_spoof_ready = false;

    // Scan shared library memory images (e.g. libc) to resolve gadgets
    dl_iterate_phdr(find_elf_gadgets_callback, nullptr);

    if (!g_gadget_jmp || !g_gadget_ret) {
        arena::set_error(ARENA_E_SPOOF_GADGETS_NOT_FOUND);
        return false;
    }

    g_linux_spoof_ready = true;
    return true;
}

extern "C" bool arena_call_ret_spoofed_ex(void* fn, const uintptr_t* args, size_t count, uintptr_t* out_return)
{
    arena::clear_error();

    if (!out_return) {
        arena::set_error(ARENA_E_SPOOF_MISSING_OUTPUT);
        return false;
    }

    *out_return = 0;

    if (!fn) {
        arena::set_error(ARENA_E_SPOOF_TARGET_NULL);
        return false;
    }

    if (count > 0 && !args) {
        arena::set_error(ARENA_E_SPOOF_ARGS_NULL);
        return false;
    }

    if (count > 8) {
        arena::set_error(ARENA_E_SPOOF_TOO_MANY_ARGS);
        return false;
    }

    if (!g_linux_spoof_ready) {
        arena::set_error(ARENA_E_SPOOF_NOT_INIT);
        return false;
    }

    // Call System V ABI return spoof stub
    *out_return = arena_call_sysv_spoof(fn, args, count, g_gadget_jmp, g_gadget_ret);
    return true;
}
#endif

extern "C" uintptr_t arena_call_ret_spoofed(void* fn, const uintptr_t* args, size_t count)
{
    uintptr_t result{};
    if (!arena_call_ret_spoofed_ex(fn, args, count, &result))
        return 0;
    return result;
}
