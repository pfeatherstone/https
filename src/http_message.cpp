#include <cstring>
#include <algorithm>
#include <filesystem>
#include <boost/asio/version.hpp>
#include "http_message.h"

namespace fs = std::filesystem;

namespace http
{

//---------------------------------------------------push_back-------------------------------------------------------------

    const auto BOOST_ASIO_VERSION_STRING = []() -> std::string 
    {
        char buf[16]= {0};
        snprintf(buf, sizeof(buf), "%d.%d.%d", BOOST_ASIO_VERSION / 100000, 
                                               BOOST_ASIO_VERSION / 100 % 1000, 
                                               BOOST_ASIO_VERSION % 100);
        return buf;
    }();

//----------------------------------------------------------------------------------------------------------------

    constexpr std::string_view FIELDS[] = {
        "<unknown-field>",
        "A-IM",
        "Accept",
        "Accept-Additions",
        "Accept-Charset",
        "Accept-Datetime",
        "Accept-Encoding",
        "Accept-Features",
        "Accept-Language",
        "Accept-Patch",
        "Accept-Post",
        "Accept-Ranges",
        "Access-Control",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Origin",
        "Access-Control-Expose-Headers",
        "Access-Control-Max-Age",
        "Access-Control-Request-Headers",
        "Access-Control-Request-Method",
        "Age",
        "Allow",
        "ALPN",
        "Also-Control",
        "Alt-Svc",
        "Alt-Used",
        "Alternate-Recipient",
        "Alternates",
        "Apparently-To",
        "Apply-To-Redirect-Ref",
        "Approved",
        "Archive",
        "Archived-At",
        "Article-Names",
        "Article-Updates",
        "Authentication-Control",
        "Authentication-Info",
        "Authentication-Results",
        "Authorization",
        "Auto-Submitted",
        "Autoforwarded",
        "Autosubmitted",
        "Base",
        "Bcc",
        "Body",
        "C-Ext",
        "C-Man",
        "C-Opt",
        "C-PEP",
        "C-PEP-Info",
        "Cache-Control",
        "CalDAV-Timezones",
        "Cancel-Key",
        "Cancel-Lock",
        "Cc",
        "Close",
        "Comments",
        "Compliance",
        "Connection",
        "Content-Alternative",
        "Content-Base",
        "Content-Description",
        "Content-Disposition",
        "Content-Duration",
        "Content-Encoding",
        "Content-features",
        "Content-ID",
        "Content-Identifier",
        "Content-Language",
        "Content-Length",
        "Content-Location",
        "Content-MD5",
        "Content-Range",
        "Content-Return",
        "Content-Script-Type",
        "Content-Style-Type",
        "Content-Transfer-Encoding",
        "Content-Type",
        "Content-Version",
        "Control",
        "Conversion",
        "Conversion-With-Loss",
        "Cookie",
        "Cookie2",
        "Cost",
        "DASL",
        "Date",
        "Date-Received",
        "DAV",
        "Default-Style",
        "Deferred-Delivery",
        "Delivery-Date",
        "Delta-Base",
        "Depth",
        "Derived-From",
        "Destination",
        "Differential-ID",
        "Digest",
        "Discarded-X400-IPMS-Extensions",
        "Discarded-X400-MTS-Extensions",
        "Disclose-Recipients",
        "Disposition-Notification-Options",
        "Disposition-Notification-To",
        "Distribution",
        "DKIM-Signature",
        "DL-Expansion-History",
        "Downgraded-Bcc",
        "Downgraded-Cc",
        "Downgraded-Disposition-Notification-To",
        "Downgraded-Final-Recipient",
        "Downgraded-From",
        "Downgraded-In-Reply-To",
        "Downgraded-Mail-From",
        "Downgraded-Message-Id",
        "Downgraded-Original-Recipient",
        "Downgraded-Rcpt-To",
        "Downgraded-References",
        "Downgraded-Reply-To",
        "Downgraded-Resent-Bcc",
        "Downgraded-Resent-Cc",
        "Downgraded-Resent-From",
        "Downgraded-Resent-Reply-To",
        "Downgraded-Resent-Sender",
        "Downgraded-Resent-To",
        "Downgraded-Return-Path",
        "Downgraded-Sender",
        "Downgraded-To",
        "EDIINT-Features",
        "Eesst-Version",
        "Encoding",
        "Encrypted",
        "Errors-To",
        "ETag",
        "Expect",
        "Expires",
        "Expiry-Date",
        "Ext",
        "Followup-To",
        "Forwarded",
        "From",
        "Generate-Delivery-Report",
        "GetProfile",
        "Hobareg",
        "Host",
        "HTTP2-Settings",
        "If",
        "If-Match",
        "If-Modified-Since",
        "If-None-Match",
        "If-Range",
        "If-Schedule-Tag-Match",
        "If-Unmodified-Since",
        "IM",
        "Importance",
        "In-Reply-To",
        "Incomplete-Copy",
        "Injection-Date",
        "Injection-Info",
        "Jabber-ID",
        "Keep-Alive",
        "Keywords",
        "Label",
        "Language",
        "Last-Modified",
        "Latest-Delivery-Time",
        "Lines",
        "Link",
        "List-Archive",
        "List-Help",
        "List-ID",
        "List-Owner",
        "List-Post",
        "List-Subscribe",
        "List-Unsubscribe",
        "List-Unsubscribe-Post",
        "Location",
        "Lock-Token",
        "Man",
        "Max-Forwards",
        "Memento-Datetime",
        "Message-Context",
        "Message-ID",
        "Message-Type",
        "Meter",
        "Method-Check",
        "Method-Check-Expires",
        "MIME-Version",
        "MMHS-Acp127-Message-Identifier",
        "MMHS-Authorizing-Users",
        "MMHS-Codress-Message-Indicator",
        "MMHS-Copy-Precedence",
        "MMHS-Exempted-Address",
        "MMHS-Extended-Authorisation-Info",
        "MMHS-Handling-Instructions",
        "MMHS-Message-Instructions",
        "MMHS-Message-Type",
        "MMHS-Originator-PLAD",
        "MMHS-Originator-Reference",
        "MMHS-Other-Recipients-Indicator-CC",
        "MMHS-Other-Recipients-Indicator-To",
        "MMHS-Primary-Precedence",
        "MMHS-Subject-Indicator-Codes",
        "MT-Priority",
        "Negotiate",
        "Newsgroups",
        "NNTP-Posting-Date",
        "NNTP-Posting-Host",
        "Non-Compliance",
        "Obsoletes",
        "Opt",
        "Optional",
        "Optional-WWW-Authenticate",
        "Ordering-Type",
        "Organization",
        "Origin",
        "Original-Encoded-Information-Types",
        "Original-From",
        "Original-Message-ID",
        "Original-Recipient",
        "Original-Sender",
        "Original-Subject",
        "Originator-Return-Address",
        "Overwrite",
        "P3P",
        "Path",
        "PEP",
        "Pep-Info",
        "PICS-Label",
        "Position",
        "Posting-Version",
        "Pragma",
        "Prefer",
        "Preference-Applied",
        "Prevent-NonDelivery-Report",
        "Priority",
        "Privicon",
        "ProfileObject",
        "Protocol",
        "Protocol-Info",
        "Protocol-Query",
        "Protocol-Request",
        "Proxy-Authenticate",
        "Proxy-Authentication-Info",
        "Proxy-Authorization",
        "Proxy-Connection",
        "Proxy-Features",
        "Proxy-Instruction",
        "Public",
        "Public-Key-Pins",
        "Public-Key-Pins-Report-Only",
        "Range",
        "Received",
        "Received-SPF",
        "Redirect-Ref",
        "References",
        "Referer",
        "Referer-Root",
        "Relay-Version",
        "Reply-By",
        "Reply-To",
        "Require-Recipient-Valid-Since",
        "Resent-Bcc",
        "Resent-Cc",
        "Resent-Date",
        "Resent-From",
        "Resent-Message-ID",
        "Resent-Reply-To",
        "Resent-Sender",
        "Resent-To",
        "Resolution-Hint",
        "Resolver-Location",
        "Retry-After",
        "Return-Path",
        "Safe",
        "Schedule-Reply",
        "Schedule-Tag",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "Sec-WebSocket-Accept",
        "Sec-WebSocket-Extensions",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Protocol",
        "Sec-WebSocket-Version",
        "Security-Scheme",
        "See-Also",
        "Sender",
        "Sensitivity",
        "Server",
        "Set-Cookie",
        "Set-Cookie2",
        "SetProfile",
        "SIO-Label",
        "SIO-Label-History",
        "SLUG",
        "SoapAction",
        "Solicitation",
        "Status-URI",
        "Strict-Transport-Security",
        "Subject",
        "SubOK",
        "Subst",
        "Summary",
        "Supersedes",
        "Surrogate-Capability",
        "Surrogate-Control",
        "TCN",
        "TE",
        "Timeout",
        "Title",
        "To",
        "Topic",
        "Trailer",
        "Transfer-Encoding",
        "TTL",
        "UA-Color",
        "UA-Media",
        "UA-Pixels",
        "UA-Resolution",
        "UA-Windowpixels",
        "Upgrade",
        "Upgrade-Insecure-Requests",
        "Urgency",
        "URI",
        "User-Agent",
        "Variant-Vary",
        "Vary",
        "VBR-Info",
        "Version",
        "Via",
        "Want-Digest",
        "Warning",
        "WWW-Authenticate",
        "X-Archived-At",
        "X-Device-Accept",
        "X-Device-Accept-Charset",
        "X-Device-Accept-Encoding",
        "X-Device-Accept-Language",
        "X-Device-User-Agent",
        "X-Frame-Options",
        "X-Mittente",
        "X-PGP-Sig",
        "X-Ricevuta",
        "X-Riferimento-Message-ID",
        "X-TipoRicevuta",
        "X-Trasporto",
        "X-VerificaSicurezza",
        "X400-Content-Identifier",
        "X400-Content-Return",
        "X400-Content-Type",
        "X400-MTS-Identifier",
        "X400-Originator",
        "X400-Received",
        "X400-Recipients",
        "X400-Trace",
        "Xref"
    };

    static_assert(std::size(FIELDS) == 358, "bad mapping");

//----------------------------------------------------------------------------------------------------------------

    std::string_view field_label(field f)
    {
        return FIELDS[f];
    }

    field field_enum(std::string_view f)
    {
        for (unsigned int i = 0 ; i < std::size(FIELDS) ; ++i)
            if (FIELDS[i] == f)
                return (field)i;
        fprintf(stderr, "Could not find field enum for %.*s\n", (int)f.size(), f.data());
        return unknown_field;
    }

//----------------------------------------------------------------------------------------------------------------

    std::string_view status_label(const status_type v)
    {
        switch(v)
        {
        // 1xx
        case status_type::continue_:                             return "Continue";
        case status_type::switching_protocols:                   return "Switching Protocols";
        case status_type::processing:                            return "Processing";
        case status_type::early_hints:                           return "Early Hints";

        // 2xx
        case status_type::ok:                                    return "OK";
        case status_type::created:                               return "Created";
        case status_type::accepted:                              return "Accepted";
        case status_type::non_authoritative_information:         return "Non-Authoritative Information";
        case status_type::no_content:                            return "No Content";
        case status_type::reset_content:                         return "Reset Content";
        case status_type::partial_content:                       return "Partial Content";
        case status_type::multi_status:                          return "Multi-Status";
        case status_type::already_reported:                      return "Already Reported";
        case status_type::im_used:                               return "IM Used";

        // 3xx
        case status_type::multiple_choices:                      return "Multiple Choices";
        case status_type::moved_permanently:                     return "Moved Permanently";
        case status_type::found:                                 return "Found";
        case status_type::see_other:                             return "See Other";
        case status_type::not_modified:                          return "Not Modified";
        case status_type::use_proxy:                             return "Use Proxy";
        case status_type::temporary_redirect:                    return "Temporary Redirect";
        case status_type::permanent_redirect:                    return "Permanent Redirect";

        // 4xx
        case status_type::bad_request:                           return "Bad Request";
        case status_type::unauthorized:                          return "Unauthorized";
        case status_type::payment_required:                      return "Payment Required";
        case status_type::forbidden:                             return "Forbidden";
        case status_type::not_found:                             return "Not Found";
        case status_type::method_not_allowed:                    return "Method Not Allowed";
        case status_type::not_acceptable:                        return "Not Acceptable";
        case status_type::proxy_authentication_required:         return "Proxy Authentication Required";
        case status_type::request_timeout:                       return "Request Timeout";
        case status_type::conflict:                              return "Conflict";
        case status_type::gone:                                  return "Gone";
        case status_type::length_required:                       return "Length Required";
        case status_type::precondition_failed:                   return "Precondition Failed";
        case status_type::payload_too_large:                     return "Payload Too Large";
        case status_type::uri_too_long:                          return "URI Too Long";
        case status_type::unsupported_media_type:                return "Unsupported Media Type";
        case status_type::range_not_satisfiable:                 return "Range Not Satisfiable";
        case status_type::expectation_failed:                    return "Expectation Failed";
        case status_type::i_am_a_teapot:                         return "I'm a teapot";
        case status_type::misdirected_request:                   return "Misdirected Request";
        case status_type::unprocessable_entity:                  return "Unprocessable Entity";
        case status_type::locked:                                return "Locked";
        case status_type::failed_dependency:                     return "Failed Dependency";
        case status_type::too_early:                             return "Too Early";
        case status_type::upgrade_required:                      return "Upgrade Required";
        case status_type::precondition_required:                 return "Precondition Required";
        case status_type::too_many_requests:                     return "Too Many Requests";
        case status_type::request_header_fields_too_large:       return "Request Header Fields Too Large";
        case status_type::unavailable_for_legal_reasons:         return "Unavailable For Legal Reasons";
        // 5xx
        case status_type::internal_server_error:                 return "Internal Server Error";
        case status_type::not_implemented:                       return "Not Implemented";
        case status_type::bad_gateway:                           return "Bad Gateway";
        case status_type::service_unavailable:                   return "Service Unavailable";
        case status_type::gateway_timeout:                       return "Gateway Timeout";
        case status_type::http_version_not_supported:            return "HTTP Version Not Supported";
        case status_type::variant_also_negotiates:               return "Variant Also Negotiates";
        case status_type::insufficient_storage:                  return "Insufficient Storage";
        case status_type::loop_detected:                         return "Loop Detected";
        case status_type::not_extended:                          return "Not Extended";
        case status_type::network_authentication_required:       return "Network Authentication Required";
        //10xx - websocket
        case status_type::normal_closure:                        return "Normal closure";
        case status_type::going_away:                            return "Going away";
        case status_type::protocol_error:                        return "Protocol error";
        case status_type::unsupported_data:                      return "Unsupported data";
        case status_type::no_code_received:                      return "No code received";
        case status_type::connection_closed_abnormally:          return "Connection closed abnormally";
        case status_type::invalid_payload_data:                  return "Invalid payload data";
        case status_type::policy_violated:                       return "Policy violated";
        case status_type::message_too_big:                       return "Message too big";
        case status_type::unsupported_extension:                 return "Unsupported extension. The client should write the extensions it expected the server to support in the payload";
        case status_type::internal_server_error_ws:              return "nternal server error";
        case status_type::tls_handshake_failure:                 return "TLS handshake failure";
        default: break;
        }
        return "<unknown-status>";
    }

//----------------------------------------------------------------------------------------------------------------

    struct mime_details
    {
        std::string_view extension;
        std::string_view mime_type;
    };

    constexpr mime_details MIME_TYPES[] = {
        {".htm",    "text/html"},
        {".html",   "text/html"},
        {".php",    "text/html"},
        {".css",    "text/css"},
        {".txt",    "text/plain"},
        {".js",     "application/javascript"},
        {".json",   "application/json"},
        {".xml",    "application/xml"},
        {".swf",    "application/x-shockwave-flash"},
        {".woff2",  "font/woff2"},
        {".png",    "image/png"},
        {".jpe",    "image/jpeg"},
        {".jpeg",   "image/jpeg"},
        {".jpg",    "image/jpeg"},
        {".gif",    "image/gif"},
        {".bmp",    "image/bmp"},
        {".ico",    "image/vnd.microsoft.icon"},
        {".tiff",   "image/tiff"},
        {".tif",    "image/tiff"},
        {".svg",    "image/svg+xml"},
        {".svgz",   "image/svg+xml"},
        {".flv",    "video/x-flv"},
    };

    std::string_view get_mime_type(std::string_view path)
    {
        const std::string ext2 = fs::path(path).extension();
        for (const auto& [ext1, mime] : MIME_TYPES)
            if (ext1 == ext2)
                return mime;
        return "application/text";
    }

//----------------------------------------------------------------------------------------------------------------

    bool header::contains_value(std::string_view v) const
    {
        return value.find(v) != std::string_view::npos;
    }

//----------------------------------------------------------------------------------------------------------------
    
    template<class Headers>
    auto find_field(Headers&& headers, const field f)
    {
        return std::find_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.key == f;});
    }

    void remove_field(std::vector<header>& headers, const field f)
    {
        headers.erase(std::remove_if(begin(headers), end(headers), [=](const auto& hdr) {return hdr.key == f;}), end(headers));
    }

    template<class Headers>
    bool contains(Headers&& headers, const field f)
    {
        return find_field(headers, f) != end(headers);
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
        return find_field(headers, f);
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

        // HTTP 1.1 - default is to keep open
        else if (http_version_major == 1 && http_version_minor == 1)
            return true;
        
        // Default - just close
        return false;
    }

    bool request::is_websocket_req() const
    {
        auto conn_field     = find(field::connection);
        auto upgrade_field  = find(field::upgrade);

        return conn_field       != end(headers)         && 
               upgrade_field    != end(headers)         &&
               conn_field->contains_value("Upgrade")    &&
               upgrade_field->contains_value("websocket");
    }

//----------------------------------------------------------------------------------------------------------------

    void response::clear()
    {
        status              = unknown;
        http_version_major  = 0;
        http_version_minor  = 0;
        headers.clear();
        content_str.clear();
        content_file.reset();
    }   
    
    void response::add_header(field f, std::string_view value)
    {
        headers.push_back({f, std::string(value)});
    }

    void response::keep_alive(bool keep_alive_)
    {
        add_header(field::connection, keep_alive_ ? "keep-alive" : "close");
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {

//----------------------------------------------------------------------------------------------------------------

        int parse_header(request& req, const size_t ndata, char* data)
        {
            bool    first_line{true};
            bool    end_of_header{false};
            char*   pos{data};

            while (pos < data+ndata && !end_of_header)
            {
                // Find EOL
                char* end = strstr(pos, "\r\n");
                if (end == nullptr)
                    return -1; // error
                
                // null-terminate line
                *end = '\0';   
                
                // Handle start line
                if (first_line)
                {
                    first_line = false;
                    req.method.resize(8, '\0');
                    req.uri.resize(strlen(pos));
                    const int ret = sscanf(pos, "%s %s HTTP/%i.%i", &req.method[0], &req.uri[0], &req.http_version_major, &req.http_version_minor);
                    if (ret != 4)
                        return -1;
                    req.method.resize(strlen(req.method.c_str()));
                    req.uri.resize(strlen(req.uri.c_str()));
                }

                // Handle header line
                else if (strlen(pos) > 0)
                {
                    char* kend = strstr(pos, ": ");
                    if (kend == nullptr)
                        return -1;
                    
                    header hdr;
                    hdr.key   = field_enum(std::string_view(pos, kend-pos));
                    hdr.value = std::string(kend+2, end-kend-2);
                    req.headers.push_back(std::move(hdr));
                }

                // Handle end of header
                else
                    end_of_header = true;

                // advance pos
                pos = end + 2; 
            }

            return std::distance(data, pos);
        }

//----------------------------------------------------------------------------------------------------------------

        void serialize_header(response& resp, std::string& buf)
        {
            // Set status string
            char status_str[64] = {0};
            snprintf(status_str, sizeof(status_str), "HTTP/%i.%i %i %s\r\n", resp.http_version_major, resp.http_version_minor, resp.status, status_label(resp.status).data());

            // Add default server string if empty
            if (!contains(resp.headers, field::server))
                resp.add_header(field::server, BOOST_ASIO_VERSION_STRING);

            // Add default connection string if empty
            if (!contains(resp.headers, field::connection))
                resp.add_header(field::connection, "close");

            // Handle empty body
            if (resp.content_str.empty() && resp.content_file == nullptr)
            {
                remove_field(resp.headers, field::content_type);
                remove_field(resp.headers, field::content_length);
            }

            // Handle string body
            else if (!resp.content_str.empty())
            {
                // Add default Content type if empty
                if (!contains(resp.headers, field::content_type))
                    resp.add_header(field::content_type, "text/plain");
                
                // Set Content length
                auto it = find_field(resp.headers, field::content_length);
                if (it == end(resp.headers))
                    resp.add_header(field::content_length, std::to_string(resp.content_str.size()));
                else
                    it->value = std::to_string(resp.content_str.size());                
            }

            // Handle file body
            else if (resp.content_file)
            {
                // Content type - assume it's already set
                if (!contains(resp.headers, field::content_type))
                    fprintf(stderr, "Content-Type is not set for file\n");
                
                // Content length
                fseek(resp.content_file.get(), 0, SEEK_END);
                const size_t file_size = ftell(resp.content_file.get());
                fseek(resp.content_file.get(), 0, SEEK_SET);

                auto it = find_field(resp.headers, field::content_length);
                if (it == end(resp.headers))
                    resp.add_header(field::content_length, std::to_string(file_size));
                else
                    it->value = std::to_string(file_size);
            }

            // Serialize
            buf.append(status_str);

            for (const auto& [k, v] : resp.headers)
            {
                buf.append(field_label(k));
                buf.append(": ");
                buf.append(v);
                buf.append("\r\n");
            }
            buf.append("\r\n");
        }

//----------------------------------------------------------------------------------------------------------------

    }
}
