#include "arena.h"

#include "error.hpp"
#include "errors.h"

#include <windows.h>

#include <cstring>

namespace {

constexpr uintptr_t kMinUserAddress = 0x1000;
constexpr uintptr_t kMaxUserAddress = 0x00007FFFFFFFFFFFULL;

bool valid_user_address(uintptr_t address)
{
    return address >= kMinUserAddress && address <= kMaxUserAddress;
}

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

bool protection_allows_write(DWORD protect)
{
    const DWORD access = protect & 0xFF;
    return access == PAGE_READWRITE ||
           access == PAGE_WRITECOPY ||
           access == PAGE_EXECUTE_READWRITE ||
           access == PAGE_EXECUTE_WRITECOPY;
}

bool region_allows_access(uintptr_t address, size_t size, bool require_write)
{
    if (!valid_user_address(address)) {
        arena::set_error(ARENA_E_MEM_OUTSIDE_USER_RANGE);
        return false;
    }

    if (size == 0)
        return true;

    if (size > kMaxUserAddress - address + 1) {
        arena::set_error(ARENA_E_MEM_OVERFLOW_USER_RANGE);
        return false;
    }

    const uintptr_t end = address + size;
    uintptr_t cursor = address;

    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi))) {
            arena::set_error(ARENA_E_MEM_VQUERY_FAILED);
            return false;
        }

        if (mbi.State != MEM_COMMIT) {
            arena::set_error(ARENA_E_MEM_NOT_COMMITTED);
            return false;
        }

        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) {
            arena::set_error(ARENA_E_MEM_GUARDED);
            return false;
        }

        if (!protection_allows_read(mbi.Protect)) {
            arena::set_error(ARENA_E_MEM_NOT_READABLE);
            return false;
        }

        if (require_write) {
            if (!protection_allows_write(mbi.Protect)) {
                arena::set_error(ARENA_E_MEM_NOT_WRITABLE);
                return false;
            }
        }

        const uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        if (mbi.RegionSize > kMaxUserAddress - region_base + 1) {
            arena::set_error(ARENA_E_MEM_OVERFLOW_USER_RANGE);
            return false;
        }

        const uintptr_t region_end = region_base + mbi.RegionSize;
        if (region_end <= cursor) {
            arena::set_error(ARENA_E_MEM_NOT_ADVANCED);
            return false;
        }

        cursor = region_end;
    }

    return true;
}

} // namespace

extern "C" bool arena_read_safe(uintptr_t address, void* out, size_t size)
{
    arena::clear_error();

    if (!out && size != 0) {
        arena::set_error(ARENA_E_MEM_READ_OUT_INVALID);
        return false;
    }

    if (!region_allows_access(address, size, false))
        return false;

    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(address),
            out,
            size,
            &bytes_read) ||
        bytes_read != size) {
        arena::set_error(ARENA_E_MEM_READ_PROC_FAILED);
        return false;
    }

    return true;
}

extern "C" void arena_read(uintptr_t address, void* out, size_t size)
{
    std::memcpy(out, reinterpret_cast<const void*>(address), size);
}

extern "C" bool arena_write_safe(uintptr_t address, const void* data, size_t size)
{
    arena::clear_error();

    if (!data && size != 0) {
        arena::set_error(ARENA_E_MEM_WRITE_IN_INVALID);
        return false;
    }

    if (!region_allows_access(address, size, true))
        return false;

    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPVOID>(address),
            data,
            size,
            &bytes_written) ||
        bytes_written != size) {
        arena::set_error(ARENA_E_MEM_WRITE_PROC_FAILED);
        return false;
    }

    return true;
}

extern "C" void arena_write(uintptr_t address, const void* data, size_t size)
{
    std::memcpy(reinterpret_cast<void*>(address), data, size);
}
