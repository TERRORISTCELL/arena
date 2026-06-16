#pragma once

#include <string_view>

namespace arena {

void clear_error();
void set_error(std::string_view message);
const char* last_error();

} // namespace arena
