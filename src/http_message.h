#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <boost/asio/buffer.hpp>
#include "http_field.h"
#include "http_status.h"

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    struct header
    {
        std::string name;
        std::string values;
        field   get_field() const;
        bool    contains_value(std::string_view v) const;
    };

//----------------------------------------------------------------------------------------------------------------

    struct request
    {
        std::string         method;
        std::string         uri;
        int                 http_version_major{};
        int                 http_version_minor{};
        std::vector<header> headers;
        std::string         content;
        void    clear();
        auto    find(field f) const -> std::vector<header>::const_iterator;
        bool    keep_alive() const;
        bool    is_websocket_req() const;
    };

//----------------------------------------------------------------------------------------------------------------

    struct response
    {
        status_type         status{unknown};
        std::vector<header> headers;
        std::string         content_str;
        std::ifstream       content_file;

        std::string                             status_buf;
        std::vector<boost::asio::const_buffer>  buffers;
        void clear();
        void add_header(field f, std::string_view value);
        auto find(field f)       -> std::vector<header>::iterator;
        auto find(field f) const -> std::vector<header>::const_iterator;
        bool contains(field f) const;
        void prepare(bool keep_alive, int http_major, int http_minor);
    };

//----------------------------------------------------------------------------------------------------------------

}