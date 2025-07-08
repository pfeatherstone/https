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
    resp.clear();
    resp.keep_alive(true);
    bool is_websocket = resp.is_websocket_response();
    return 0;
}