#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string     buf(reinterpret_cast<const char*>(data), size);
    http::request   req{};
    std::error_code ec{};
    http::parser<http::request> parser;
    parser.parse(req, buf, ec);
    return 0;
}