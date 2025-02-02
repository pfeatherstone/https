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
        content_file.close();
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

    bool response::contains(field f) const
    {
        return find(f) != end(headers);
    }

    void response::prepare(bool keep_alive, int http_major, int http_minor) 
    {
        // Clear buffers
        buffers.clear();

        // Set status string
        char buf[64] = {0};
        snprintf(buf, sizeof(buf), "HTTP/%i.%i %i %s\r\n", http_major, http_minor, status, status_string(status).data());
        status_buf = buf;

        // Add a couple headers
        if (!contains(field::server))
            add_header(field::server, BOOST_ASIO_VERSION_STRING);

        if (!contains(field::connection))
            add_header(field::connection, keep_alive ? "keep-alive" : "close");

        // Check body
        if (content_str.empty() && !content_file.is_open())
        {
            headers.erase(std::remove_if(begin(headers), end(headers), [](const auto& hdr) {return hdr.name == field_name(field::content_type);}), end(headers));
            headers.erase(std::remove_if(begin(headers), end(headers), [](const auto& hdr) {return hdr.name == field_name(field::content_length);}), end(headers));
        }

        // Content - str
        else if (!content_str.empty())
        {
            // Content type
            auto it = find(field::content_type);
            if (it == end(headers))
                add_header(field::content_type, "text/plain");
            
            // Content length
            it = find(field::content_length);
            if (it != end(headers))
                it->values = std::to_string(content_str.size());
            else
                add_header(field::content_length, std::to_string(content_str.size()));
        }

        // Content - file
        else if (content_file.is_open())
        {
            // Content type - assume it's already set
            auto it = find(field::content_type);
            if (it == end(headers))
                fprintf(stderr, "Content-Type is not set for file\n");
            
            // Content length
            content_file.seekg(0, std::ios::end);
            const size_t file_size = content_file.tellg();
            content_file.seekg(0, std::ios::beg);

            it = find(field::content_length);
            if (it != end(headers))
                it->values = std::to_string(file_size);
            else
                add_header(field::content_length, std::to_string(file_size));
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

}