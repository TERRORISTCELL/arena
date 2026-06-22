#include "error.hpp"

#include "arena.h"



namespace arena {
namespace {

thread_local uint32_t g_last_error = 0;

} // namespace

void clear_error()
{
    g_last_error = 0;
}

void set_error(uint32_t code)
{
    g_last_error = code;
}

uint32_t last_error()
{
    return g_last_error;
}

} // namespace arena

extern "C" uint32_t arena_last_error(void)
{
    return arena::last_error();
}
