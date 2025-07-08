#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string      buf(reinterpret_cast<const char*>(data), size);
    http::response   resp{};
    std::error_code  ec{};
    http::parser<http::response> parser;
    parser.parse(resp, buf, ec);
    buf.clear();
    ec = {};
    http::serialize_header(resp, buf, ec);
    return 0;
}