#pragma once

namespace http
{
    enum http_error
    {
        HTTP_READ_HEADER_FAIL = 1,
        HTTP_READ_BODY_FAIL,
        WS_ACCEPT_MISSING_SEQ_KEY,
    };

    std::error_code make_error_code(http_error ec);
}

namespace std
{
    template <>
    struct is_error_code_enum<http::http_error> : std::true_type {};
}