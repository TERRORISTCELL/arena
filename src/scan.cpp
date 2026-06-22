#include "arena.h"

#include "error.hpp"
#include "errors.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace {

struct CompiledPattern {
    std::vector<int> bytes;
    std::vector<std::uint8_t> anchor;
    std::size_t anchor_offset{};
};

bool is_wildcard(std::string_view token)
{
    return token == "?" || token == "??";
}

int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool parse_byte(std::string_view token, std::uint8_t* out)
{
    if (token.empty() || token.size() > 2)
        return false;

    unsigned value = 0;
    for (char c : token) {
        const int digit = hex_value(c);
        if (digit < 0)
            return false;
        value = (value << 4) | static_cast<unsigned>(digit);
    }

    *out = static_cast<std::uint8_t>(value);
    return true;
}

bool compile_pattern(std::string_view pattern, CompiledPattern* out)
{
    *out = {};

    std::size_t pos = 0;
    while (pos < pattern.size()) {
        while (pos < pattern.size() && pattern[pos] == ' ')
            ++pos;
        if (pos == pattern.size())
            break;

        const std::size_t token_start = pos;
        while (pos < pattern.size() && pattern[pos] != ' ')
            ++pos;

        const std::string_view token = pattern.substr(token_start, pos - token_start);
        if (is_wildcard(token)) {
            out->bytes.push_back(-1);
            continue;
        }

        std::uint8_t value{};
        if (!parse_byte(token, &value)) {
            arena::set_error(ARENA_E_SCAN_INVALID_TOKEN);
            return false;
        }
        out->bytes.push_back(static_cast<int>(value));
    }

    if (out->bytes.empty()) {
        arena::set_error(ARENA_E_SCAN_EMPTY_PATTERN);
        return false;
    }

    std::size_t best_offset = 0;
    std::size_t best_length = 0;
    std::size_t current_offset = 0;
    std::size_t current_length = 0;
    bool in_run = false;

    for (std::size_t i = 0; i < out->bytes.size(); ++i) {
        if (out->bytes[i] >= 0) {
            if (!in_run) {
                current_offset = i;
                current_length = 0;
                in_run = true;
            }

            ++current_length;
            if (current_length > best_length) {
                best_length = current_length;
                best_offset = current_offset;
            }
        } else {
            in_run = false;
        }
    }

    if (best_length == 0) {
        arena::set_error(ARENA_E_SCAN_ALL_WILDCARDS);
        return false;
    }

    out->anchor_offset = best_offset;
    out->anchor.reserve(best_length);
    for (std::size_t i = best_offset; i < best_offset + best_length; ++i)
        out->anchor.push_back(static_cast<std::uint8_t>(out->bytes[i]));

    return true;
}

std::vector<std::size_t> find_matches(const std::uint8_t* base, std::size_t size, const CompiledPattern& pattern)
{
    std::vector<std::size_t> matches;

    if (size < pattern.bytes.size())
        return matches;

    const auto* start = base;
    const auto* end = base + size;

    while (start < end) {
        const auto anchor = std::search(start, end, pattern.anchor.begin(), pattern.anchor.end());
        if (anchor == end)
            break;

        const std::size_t anchor_index = static_cast<std::size_t>(anchor - base);
        if (anchor_index < pattern.anchor_offset) {
            start = anchor + 1;
            continue;
        }

        const std::size_t match_offset = anchor_index - pattern.anchor_offset;
        if (match_offset > size - pattern.bytes.size())
            break;

        bool ok = true;
        for (std::size_t i = 0; i < pattern.bytes.size(); ++i) {
            const int expected = pattern.bytes[i];
            if (expected >= 0 && base[match_offset + i] != static_cast<std::uint8_t>(expected)) {
                ok = false;
                break;
            }
        }

        if (ok)
            matches.push_back(match_offset);

        start = anchor + 1;
    }

    return matches;
}

bool add_signed_offset(uintptr_t value, intptr_t offset, uintptr_t* out)
{
    if (offset >= 0) {
        const auto amount = static_cast<uintptr_t>(offset);
        if (value > UINTPTR_MAX - amount)
            return false;
        *out = value + amount;
        return true;
    }

    const auto amount = static_cast<uintptr_t>(-(offset + 1)) + 1;
    if (value < amount)
        return false;
    *out = value - amount;
    return true;
}

bool has_bytes(std::size_t offset, std::size_t size, std::size_t image_size)
{
    return offset <= image_size && size <= image_size - offset;
}

bool has_displaced_bytes(std::size_t offset, std::size_t displacement, std::size_t size, std::size_t image_size)
{
    if (!has_bytes(offset, displacement, image_size))
        return false;
    return has_bytes(offset + displacement, size, image_size);
}

bool resolve_match(
    uintptr_t base,
    std::size_t match_offset,
    ArenaResolveKind kind,
    const ArenaResolveParams* params,
    const std::uint8_t* image,
    std::size_t image_size,
    uintptr_t* out)
{
    if (match_offset > UINTPTR_MAX - base) {
        arena::set_error(ARENA_E_SCAN_ADDR_OVERFLOW);
        return false;
    }

    const uintptr_t match_address = base + match_offset;

    switch (kind) {
    case ARENA_RESOLVE_DIRECT_RVA:
        *out = match_offset;
        return true;

    case ARENA_RESOLVE_MATCH_ADDRESS:
        *out = match_address;
        return true;

    case ARENA_RESOLVE_MATCH_RVA_PLUS_OFFSET:
        if (!params) {
            arena::set_error(ARENA_E_SCAN_RVA_PARAMS);
            return false;
        }
        if (!add_signed_offset(match_offset, params->extra_offset, out)) {
            arena::set_error(ARENA_E_SCAN_RVA_OVERFLOW);
            return false;
        }
        return true;

    case ARENA_RESOLVE_RIP_RELATIVE32: {
        if (!params) {
            arena::set_error(ARENA_E_SCAN_RIP_PARAMS);
            return false;
        }

        if (!has_displaced_bytes(match_offset, params->displacement_offset, sizeof(std::int32_t), image_size)) {
            arena::set_error(ARENA_E_SCAN_RIP_DISPLACEMENT);
            return false;
        }

        std::int32_t displacement{};
        std::memcpy(&displacement, image + match_offset + params->displacement_offset, sizeof(displacement));

        uintptr_t next{};
        if (match_address > UINTPTR_MAX - params->instruction_length) {
            arena::set_error(ARENA_E_SCAN_RIP_NEXT_OVERFLOW);
            return false;
        }

        next = match_address + params->instruction_length;
        if (!add_signed_offset(next, displacement, out)) {
            arena::set_error(ARENA_E_SCAN_RIP_TARGET_INVALID);
            return false;
        }
        return true;
    }

    case ARENA_RESOLVE_ABS32: {
        if (!params) {
            arena::set_error(ARENA_E_SCAN_ABS32_PARAMS);
            return false;
        }

        if (!has_displaced_bytes(match_offset, params->displacement_offset, sizeof(std::uint32_t), image_size)) {
            arena::set_error(ARENA_E_SCAN_ABS32_DISPLACEMENT);
            return false;
        }

        std::uint32_t value{};
        std::memcpy(&value, image + match_offset + params->displacement_offset, sizeof(value));
        if (base > UINTPTR_MAX - value) {
            arena::set_error(ARENA_E_SCAN_ABS32_OVERFLOW);
            return false;
        }
        *out = base + value;
        return true;
    }

    case ARENA_RESOLVE_ABS64: {
        if (!params) {
            arena::set_error(ARENA_E_SCAN_ABS64_PARAMS);
            return false;
        }

        if (!has_displaced_bytes(match_offset, params->displacement_offset, sizeof(std::uint64_t), image_size)) {
            arena::set_error(ARENA_E_SCAN_ABS64_DISPLACEMENT);
            return false;
        }

        std::uint64_t value{};
        std::memcpy(&value, image + match_offset + params->displacement_offset, sizeof(value));
        if (value > UINTPTR_MAX) {
            arena::set_error(ARENA_E_SCAN_ABS64_OVERFLOW);
            return false;
        }
        *out = static_cast<uintptr_t>(value);
        return true;
    }
    }

    arena::set_error(ARENA_E_SCAN_UNKNOWN_KIND);
    return false;
}

} // namespace

extern "C" bool arena_scan_signature_ex(
    const void* base,
    size_t size,
    const char* pattern,
    ArenaResolveKind resolve_kind,
    const ArenaResolveParams* params,
    uintptr_t* out_result)
{
    arena::clear_error();

    if (!base || !pattern || !out_result || size == 0) {
        arena::set_error(ARENA_E_SCAN_INVALID_INPUT);
        return false;
    }

    try {
        const auto base_address = reinterpret_cast<uintptr_t>(base);
        if (size > UINTPTR_MAX - base_address) {
            arena::set_error(ARENA_E_SCAN_RANGE_OVERFLOW);
            return false;
        }

        const auto* image = static_cast<const std::uint8_t*>(base);
        CompiledPattern compiled{};
        if (!compile_pattern(pattern, &compiled))
            return false;

        const auto matches = find_matches(image, size, compiled);

        if (matches.empty()) {
            arena::set_error(ARENA_E_SCAN_NOT_FOUND);
            return false;
        }

        std::vector<uintptr_t> resolved;
        resolved.reserve(matches.size());

        for (const auto match_offset : matches) {
            uintptr_t value{};
            if (!resolve_match(
                base_address,
                match_offset,
                resolve_kind,
                params,
                image,
                size,
                &value)) {
                return false;
            }
            resolved.push_back(value);
        }

        const uintptr_t first = resolved.front();
        const bool all_same = std::all_of(resolved.begin(), resolved.end(), [&](uintptr_t value) {
            return value == first;
        });

        if (!all_same) {
            arena::set_error(ARENA_E_SCAN_MULTIPLE_MATCHES);
            return false;
        }

        *out_result = first;
        arena::clear_error();
        return true;
    } catch (...) {
        arena::set_error(ARENA_E_SCAN_FAILED);
        return false;
    }
}

extern "C" uintptr_t arena_scan_signature(
    const void* base,
    size_t size,
    const char* pattern,
    ArenaResolveKind resolve_kind,
    const ArenaResolveParams* params)
{
    uintptr_t result{};
    if (!arena_scan_signature_ex(base, size, pattern, resolve_kind, params, &result))
        return 0;
    return result;
}
