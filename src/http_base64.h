#pragma once

#include <string>
#include <string_view>

namespace http
{
    std::string to_base64(std::string_view v);
    std::string from_base64(std::string_view v);
}