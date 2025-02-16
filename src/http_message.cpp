#include <algorithm>
#include <boost/asio/version.hpp>
#include "http_message.h"

using namespace boost::asio::buffer_literals;

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    const auto BOOST_ASIO_VERSION_STRING = []() -> std::string {
        char buf[16]= {0};
        snprintf(buf, sizeof(buf), "%d.%d.%d", BOOST_ASIO_VERSION / 100000, 
                                               BOOST_ASIO_VERSION / 100 % 1000, 
                                               BOOST_ASIO_VERSION % 100);
        return buf;
    }();

//----------------------------------------------------------------------------------------------------------------

    field header::get_field() const
    {
        return field_enum(name);
    }

    bool header::contains_value(std::string_view v) const
    {
        return values.find(v) != std::string_view::npos;
    }

//----------------------------------------------------------------------------------------------------------------

    void request::clear()
    {
        method.clear();
        uri.clear();
        headers.clear();
        content.clear();
        http_version_major = 0;
        http_version_minor = 0;
    }

    auto request::find(field f) const -> std::vector<header>::const_iterator
    {
        return std::find_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.name == field_name(f);});
    }

    bool request::keep_alive() const
    {
        auto it = find(field::connection);

        if (it != end(headers))
        {
            if (it->contains_value("keep-alive") || it->contains_value("Keep-Alive"))
                return true;

            else if (it->contains_value("Close") || it->contains_value("close"))
                return false;
        }

        // HTTP 1.0 - default is to close
        if (http_version_major == 1 && http_version_minor == 0)
            return false;

        // HTTP 1.1 - default is to close
        else if (http_version_major == 1 && http_version_minor == 1)
            return true;
        
        // Default - just close
        return false;
    }

    bool request::is_websocket_req() const
    {
        auto conn_field     = find(field::connection);
        auto upgrade_field  = find(field::upgrade);

        return conn_field           != end(headers)     &&
               upgrade_field        != end(headers)     &&
               conn_field->contains_value("Upgrade")    &&
               upgrade_field->contains_value("websocket");
    }

//----------------------------------------------------------------------------------------------------------------

    void response::clear()
    {
        status = unknown;
        headers.clear();
        content_str.clear();
        content_file.reset();
        status_buf.clear();
        buffers.clear();
    }  

    void response::add_header(field f, std::string_view value)
    {
        header hdr;
        hdr.name    = field_name(f);
        hdr.values  = value;
        headers.push_back(std::move(hdr));
    }

    auto response::find(field f) -> std::vector<header>::iterator
    {
        return std::find_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.name == field_name(f);});
    }

    auto response::find(field f) const -> std::vector<header>::const_iterator
    {
        return std::find_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.name == field_name(f);});
    }

    void response::prepare(bool keep_alive, int http_major, int http_minor)
    {
        // Clear buffers
        buffers.clear();

        // Set status string
        char buf[64] = {0};
        snprintf(buf, sizeof(buf), "HTTP/%i.%i %i %s\r\n", http_major, http_minor, status, status_string(status));
        status_buf = buf;

        // Add a couple headers
        if (find(field::server) == end(headers))
            add_header(field::server, BOOST_ASIO_VERSION_STRING);

        if (find(field::connection) == end(headers))
            add_header(field::connection, keep_alive ? "keep-alive" : "close");

        // Check body
        if (content_str.empty() && content_file == nullptr)
        {
            headers.erase(std::remove_if(begin(headers), end(headers), [](const auto& hdr) {return hdr.name == field_name(field::content_type);}), end(headers));
            headers.erase(std::remove_if(begin(headers), end(headers), [](const auto& hdr) {return hdr.name == field_name(field::content_length);}), end(headers));
        }

        // Content - str
        else if (!content_str.empty())
        {
            // Content type
            if (find(field::content_type) == end(headers))
                add_header(field::content_type, "text/plain");
            
            // Content length
            auto it = find(field::content_length);
            if (it == end(headers))
                add_header(field::content_length, std::to_string(content_str.size()));
            else
                it->values = std::to_string(content_str.size());                
        }

        // Content - file
        else if (content_file)
        {
            // Content type - assume it's already set
            if (find(field::content_type) == end(headers))
                fprintf(stderr, "Content-Type is not set for file\n");
            
            // Content length
            fseek(content_file.get(), 0, SEEK_END);
            const size_t file_size = ftell(content_file.get());
            fseek(content_file.get(), 0, SEEK_SET);

            auto it = find(field::content_length);
            if (it == end(headers))
                add_header(field::content_length, std::to_string(file_size));
            else
               it->values = std::to_string(file_size);
        }

        // Add buffers
        buffers.push_back(boost::asio::buffer(status_buf));

        for (std::size_t i = 0; i < headers.size(); ++i)
        {
            header& h = headers[i];
            buffers.push_back(boost::asio::buffer(h.name));
            buffers.push_back(": "_buf);
            buffers.push_back(boost::asio::buffer(h.values));
            buffers.push_back("\r\n"_buf);
        }
        buffers.push_back("\r\n"_buf);
    }

//----------------------------------------------------------------------------------------------------------------

    struct request_parser
    {
        enum result_type 
        { 
            good, 
            bad, 
            indeterminate 
        };

        struct result
        {
            result_type type{indeterminate};
            std::size_t bytes_consumed{0};
        };

        enum
        {
            method_start,
            method,
            uri,
            http_version_h,
            http_version_t_1,
            http_version_t_2,
            http_version_p,
            http_version_slash,
            http_version_major_start,
            http_version_major,
            http_version_minor_start,
            http_version_minor,
            expecting_newline_1,
            header_line_start,
            header_lws,
            header_name,
            space_before_header_value,
            header_value,
            expecting_newline_2,
            expecting_newline_3
        } state_{method_start};

        result      parse(request& req, size_t ndata, const char* data);
        result_type consume(request& req, char input);
        void        reset();
    };

//----------------------------------------------------------------------------------------------------------------

    constexpr bool is_char(int c)     { return c >= 0 && c <= 127; }
    constexpr bool is_ctl(int c)      { return (c >= 0 && c <= 31) || (c == 127); }
    constexpr bool is_digit(int c)    { return c >= '0' && c <= '9'; }
    constexpr bool is_tspecial(int c)
    {
        switch (c)
        {
            case '(': case ')': case '<': case '>': case '@':
            case ',': case ';': case ':': case '\\': case '"':
            case '/': case '[': case ']': case '?': case '=':
            case '{': case '}': case ' ': case '\t':
                return true;
            default:
                return false;
        }
    }

    void request_parser::reset()
    { 
        state_ = method_start; 
    }

    request_parser::result request_parser::parse(request& req, size_t ndata, const char* data)
    {
        for (size_t i = 0 ; i < ndata ; ++i)
        {
            result_type result = consume(req, data[i]);
            if (result == good || result == bad)
                return {result, i+1};
        }
        
        return {indeterminate, ndata};
    }

    request_parser::result_type request_parser::consume(request& req, char input)
    {
        switch (state_)
        {
        case method_start:
            if (!is_char(input) || is_ctl(input) || is_tspecial(input))
            {
                return bad;
            }
            else
            {
                state_ = method;
                req.method.push_back(input);
                return indeterminate;
            }
        case method:
            if (input == ' ')
            {
                state_ = uri;
                return indeterminate;
            }
            else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
            {
                return bad;
            }
            else
            {
                req.method.push_back(input);
                return indeterminate;
            }
        case uri:
            if (input == ' ')
            {
                state_ = http_version_h;
                return indeterminate;
            }
            else if (is_ctl(input))
            {
                return bad;
            }
            else
            {
                req.uri.push_back(input);
                return indeterminate;
            }
        case http_version_h:
            if (input == 'H')
            {
                state_ = http_version_t_1;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_t_1:
            if (input == 'T')
            {
                state_ = http_version_t_2;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_t_2:
            if (input == 'T')
            {
                state_ = http_version_p;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_p:
            if (input == 'P')
            {
                state_ = http_version_slash;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_slash:
            if (input == '/')
            {
                req.http_version_major = 0;
                req.http_version_minor = 0;
                state_ = http_version_major_start;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_major_start:
            if (is_digit(input))
            {
                req.http_version_major = req.http_version_major * 10 + input - '0';
                state_ = http_version_major;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_major:
            if (input == '.')
            {
                state_ = http_version_minor_start;
                return indeterminate;
            }
            else if (is_digit(input))
            {
                req.http_version_major = req.http_version_major * 10 + input - '0';
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_minor_start:
            if (is_digit(input))
            {
                req.http_version_minor = req.http_version_minor * 10 + input - '0';
                state_ = http_version_minor;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case http_version_minor:
            if (input == '\r')
            {
                state_ = expecting_newline_1;
                return indeterminate;
            }
            else if (is_digit(input))
            {
                req.http_version_minor = req.http_version_minor * 10 + input - '0';
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case expecting_newline_1:
            if (input == '\n')
            {
                state_ = header_line_start;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case header_line_start:
            if (input == '\r')
            {
                state_ = expecting_newline_3;
                return indeterminate;
            }
            else if (!req.headers.empty() && (input == ' ' || input == '\t'))
            {
                state_ = header_lws;
                return indeterminate;
            }
            else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
            {
                return bad;
            }
            else
            {
                req.headers.push_back(header());
                req.headers.back().name.push_back(input);
                state_ = header_name;
                return indeterminate;
            }
        case header_lws:
            if (input == '\r')
            {
                state_ = expecting_newline_2;
                return indeterminate;
            }
            else if (input == ' ' || input == '\t')
            {
                return indeterminate;
            }
            else if (is_ctl(input))
            {
                return bad;
            }
            else
            {
                state_ = header_value;
                req.headers.back().values.push_back(input);
                return indeterminate;
            }
        case header_name:
            if (input == ':')
            {
                state_ = space_before_header_value;
                return indeterminate;
            }
            else if (!is_char(input) || is_ctl(input) || is_tspecial(input))
            {
                return bad;
            }
            else
            {
                req.headers.back().name.push_back(input);
                return indeterminate;
            }
        case space_before_header_value:
            if (input == ' ')
            {
                state_ = header_value;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case header_value:
            if (input == '\r')
            {
                state_ = expecting_newline_2;
                return indeterminate;
            }
            else if (is_ctl(input))
            {
                return bad;
            }
            else
            {
                req.headers.back().values.push_back(input);
                return indeterminate;
            }
        case expecting_newline_2:
            if (input == '\n')
            {
                state_ = header_line_start;
                return indeterminate;
            }
            else
            {
                return bad;
            }
        case expecting_newline_3:
            return (input == '\n') ? good : bad;
        default:
            return bad;
        }
    }

//----------------------------------------------------------------------------------------------------------------

    int parse_request(request& req, int ndata, const char* data)
    {
        request_parser parser;
        auto res = parser.parse(req, ndata, data);
        return res.type == request_parser::good ? res.bytes_consumed : -1;
    }

//----------------------------------------------------------------------------------------------------------------

}
