#pragma once

#include <string_view>

namespace http
{
    std::string_view get_mime_type(std::string_view path);
}