#pragma once

namespace http
{
    enum error
    {
        http_read_header_fail = 1,
        http_read_body_fail,
        ws_accept_missing_seq_key,
        ws_invalid_opcode,
        ws_closed
    };

    std::error_code make_error_code(error ec);
}

namespace std
{
    template <>
    struct is_error_code_enum<http::error> : std::true_type {};
}