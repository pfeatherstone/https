#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string      buf(reinterpret_cast<const char*>(data), size);
    http::response   resp{};
    std::error_code  ec{};
    http::parser_response parser;
    parser.parse(resp, buf, ec);
    buf.clear();
    std::string ec_msg = ec ? ec.message() : "";
    ec = {};
    http::serialize_header(resp, buf, ec);
    resp.keep_alive(true);
    bool is_websocket = resp.is_websocket_response();
    resp.clear();
    ec_msg = ec ? ec.message() : "";
    return 0;
}