#include "arena.h"
#include "error.hpp"
#include "errors.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

namespace {

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    bool readable;
    bool writable;
};

// Reads /proc/self/maps to build a snapshot of committed memory regions
bool get_memory_regions(std::vector<MemoryRegion>& regions)
{
    regions.clear();
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    std::string contents;
    char buffer[4096];
    ssize_t bytes;
    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        contents.append(buffer, bytes);
    }
    close(fd);

    size_t line_start = 0;
    while (line_start < contents.size()) {
        size_t line_end = contents.find('\n', line_start);
        if (line_end == std::string::npos) {
            line_end = contents.size();
        }

        std::string line = contents.substr(line_start, line_end - line_start);
        line_start = line_end + 1;

        if (line.empty()) continue;

        // Parse format: "555555554000-555555558000 r--p 00000000 08:02 123456 /usr/bin/cat"
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;

        size_t space1 = line.find(' ', dash);
        if (space1 == std::string::npos) continue;

        size_t space2 = line.find(' ', space1 + 1);
        if (space2 == std::string::npos) continue;

        std::string start_hex = line.substr(0, dash);
        std::string end_hex = line.substr(dash + 1, space1 - (dash + 1));
        std::string perms = line.substr(space1 + 1, space2 - (space1 + 1));

        try {
            uintptr_t start = std::stoull(start_hex, nullptr, 16);
            uintptr_t end = std::stoull(end_hex, nullptr, 16);
            bool r = (perms.find('r') != std::string::npos);
            bool w = (perms.find('w') != std::string::npos);
            regions.push_back({start, end, r, w});
        } catch (...) {
            continue;
        }
    }

    return true;
}

bool region_allows_access(uintptr_t address, size_t size, bool require_write)
{
    if (size == 0) return true;

    // Check overflow
    if (size > UINTPTR_MAX - address) {
        arena::set_error(ARENA_E_MEM_OVERFLOW);
        return false;
    }

    std::vector<MemoryRegion> regions;
    if (!get_memory_regions(regions)) {
        arena::set_error(ARENA_E_MEM_PROC_MAPS);
        return false;
    }

    uintptr_t target_start = address;
    uintptr_t target_end = address + size;

    uintptr_t cursor = target_start;
    while (cursor < target_end) {
        bool found = false;
        for (const auto& r : regions) {
            if (cursor >= r.start && cursor < r.end) {
                if (!r.readable) {
                    arena::set_error(ARENA_E_MEM_NOT_READABLE);
                    return false;
                }
                if (require_write && !r.writable) {
                    arena::set_error(ARENA_E_MEM_NOT_WRITABLE);
                    return false;
                }
                cursor = r.end;
                found = true;
                break;
            }
        }
        if (!found) {
            arena::set_error(ARENA_E_MEM_NOT_COMMITTED);
            return false;
        }
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

    std::memcpy(out, reinterpret_cast<const void*>(address), size);
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

    std::memcpy(reinterpret_cast<void*>(address), data, size);
    return true;
}

extern "C" void arena_write(uintptr_t address, const void* data, size_t size)
{
    std::memcpy(reinterpret_cast<void*>(address), data, size);
}
