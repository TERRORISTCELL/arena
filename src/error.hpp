#pragma once

#include <stdint.h>

namespace arena {

void clear_error();
void set_error(uint32_t code);
uint32_t last_error();

} // namespace arena
