#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string buf(reinterpret_cast<const char*>(data), size);

    http::request   req{};
    std::error_code ec{};
    http::parser<http::request> parser;
    parser.parse(req, buf, ec);
    bool is_websocket_req = req.is_websocket_req();

    std::vector<char> msg;
    http::dynamic_buffer view(msg);
    http::websocket_parser ws_parser;
    ws_parser.parse(view, buf, ec);
    const auto opcode       = ws_parser.get_opcode();
    const auto is_server    = ws_parser.is_server();
    const auto current_size = view.size();
    const auto current_data = view.data();
    const auto current_buf  = view.buffer();
    view.resize(10);
    view.clear();
    msg.assign(data, data+size);
    buf.clear();
    http::serialize_websocket_message(boost::asio::buffer(msg), http::WS_OPCODE_DATA_BINARY, true, buf);
    return 0;
}