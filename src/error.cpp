#include "error.hpp"

#include "arena.h"

#include <string>

namespace arena {
namespace {

thread_local std::string g_last_error;

} // namespace

void clear_error()
{
    g_last_error.clear();
}

void set_error(std::string_view message)
{
    g_last_error.assign(message.begin(), message.end());
}

const char* last_error()
{
    return g_last_error.c_str();
}

} // namespace arena

extern "C" const char* arena_last_error(void)
{
    return arena::last_error();
}
