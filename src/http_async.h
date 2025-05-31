#pragma once

#include <boost/asio/version.hpp>
#include <boost/asio/compose.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include "http.h"

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncReadStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncReadStream::executor_type>
    >
    auto async_http_read (
        AsyncReadStream&    sock,
        request&            req,
        std::string&        buf,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncReadStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncReadStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncReadStream::executor_type>
    >
    auto async_http_read (
        AsyncReadStream&    sock,
        response&           resp,
        std::string&        buf,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncReadStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>
    >
    auto async_write_file (
        AsyncWriteStream&   sock,
        FILE*               file,
        std::string&        buf,
        std::size_t         chunk_size,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>
    >
    auto async_http_write (
        AsyncWriteStream&   sock,
        response&           resp,
        std::string&        buf,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>
    >
    auto async_http_write (
        AsyncWriteStream&   sock,
        request&            req,
        std::string&        buf,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncStream::executor_type>
    >
    auto async_ws_handshake (
        AsyncStream&        sock,
        std::string_view    host,
        std::string_view    uri,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>
    >
    auto async_ws_accept (
        AsyncWriteStream&   sock,
        request             req,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncReadStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, bool)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncReadStream::executor_type>
    >
    auto async_ws_read (
        AsyncReadStream&    sock,
        std::vector<char>&  buf,
        bool                is_server,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncReadStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>
    >
    auto async_ws_write (
        AsyncWriteStream&   sock,
        std::vector<char>&  buf,
        bool                is_text,
        bool                is_server,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncWriteStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken = boost::asio::default_completion_token_t<typename AsyncStream::executor_type>
    >
    auto async_ws_close (
        AsyncStream&        sock,
        ws_code             reason,
        bool                is_server,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename AsyncStream::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// DEFINITIONS
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        std::string& get_content(request& req)      {return req.content;}
        std::string& get_content(response& resp)    {return resp.content_str;}
        FILE*        get_file(request& req)         {return nullptr;}
        FILE*        get_file(response& resp)       {return resp.content_file.get();}

        template<class AsyncReadStream, class Message>
        struct async_http_read_impl
        {
            AsyncReadStream&            sock;
            Message&                    msg;
            std::string&                buf;
            size_t                      total_read{0};
            size_t                      body_read{0};
            enum {header, parse, body}  state{header};

            async_http_read_impl(AsyncReadStream& sock_, Message& msg_, std::string& buf_)
            : sock{sock_}, msg{msg_}, buf{buf_}
            {
                buf.clear();
                msg.clear();
            }
            
            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nread = 0)
            {
                // Error
                if (error)
                    self.complete(error, total_read);

                // Header
                else if (state == header) 
                {
                    state = parse;
                    boost::asio::async_read_until(sock, boost::asio::dynamic_buffer(buf), "\r\n\r\n", std::move(self));
                }

                // Parse
                else if (state == parse)
                {
                    const int header_size = details::parse_header(msg, nread, buf.data());
                    assert(header_size == nread);

                    // Header fail
                    if (header_size < 0)
                        self.complete(make_error_code(http_read_header_fail), total_read);

                    // Header ok
                    else
                    {
                        state = body;
                        total_read += buf.size();

                        const auto it = msg.find(field::content_length);

                        // Read body
                        if (it != end(msg.headers))
                        {
                            const size_t content_size   = std::stoul(it->value);
                            body_read                   = buf.size() - header_size;
                            const size_t remaining      = content_size - body_read;
                            assert(body_read <= content_size || "Reading into the next HTTP message or other bug. Either way, bug!");
                            
                            get_content(msg).resize(content_size);
                            std::copy(begin(buf) + header_size, end(buf), begin(get_content(msg)));
                            
                            // Body already read
                            if (remaining == 0)
                                self.complete(boost::system::error_code{}, total_read);

                            // Read body
                            if (remaining > 0)
                                boost::asio::async_read(sock, boost::asio::buffer(&get_content(msg)[body_read], remaining), std::move(self));
                        }

                        // Handle empty body
                        else
                        {
                            self.complete(boost::system::error_code{}, total_read);
                        }
                    }
                }

                // Handle body
                else
                {
                    total_read += nread;
                    body_read  += nread;

                    // Failed to read complete body
                    if (body_read != get_content(msg).size())
                        self.complete(make_error_code(http_read_body_fail), total_read);
                    
                    // Read complete body
                    else
                        self.complete(boost::system::error_code{}, total_read);
                }
            }
        };
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncReadStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_read (
        AsyncReadStream&    sock,
        request&            req,
        std::string&        buf,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_read_impl{sock, req, buf},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncReadStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_read (
        AsyncReadStream&    sock,
        response&           resp,
        std::string&        buf,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_read_impl{sock, resp, buf},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        template<class AsyncWriteStream>
        struct async_write_file_impl
        {
            AsyncWriteStream&   sock;
            FILE*               file;
            std::string&        buf;
            size_t              size{};
            size_t              offset{0};

            async_write_file_impl(AsyncWriteStream& sock_, FILE* file_, std::string& buf_, std::size_t chunksize_)
            : sock{sock_}, file{file_}, buf{buf_}
            {
                fseek(file, 0, SEEK_END);
                size = ftell(file);
                fseek(file, 0, SEEK_SET);
                buf.resize(chunksize_);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nwritten = 0)
            {
                // Error
                if (error)
                    self.complete(error, offset);
                
                // End of file
                else if (offset == size)
                    self.complete(boost::system::error_code{}, offset);

                // Bad file
                else if (ferror(file) || feof(file))
                    self.complete(boost::asio::error::make_error_code(boost::asio::error::broken_pipe), offset);

                // Keep writing
                else 
                {
                    const size_t nread = fread(buf.data(), 1, buf.size(), file);
                    offset += nread;
                    boost::asio::async_write(sock, boost::asio::buffer(buf, nread), std::move(self));
                }
            }
        };
    }

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_write_file (
        AsyncWriteStream&   sock,
        FILE*               file,
        std::string&        buf,
        std::size_t         chunk_size,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_write_file_impl{sock, file, buf, chunk_size},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        template<class AsyncWriteStream, class Message>
        struct async_http_write_impl
        {
            AsyncWriteStream&           sock;
            Message&                    msg;
            std::string&                buf;
            size_t                      total_written{0};
            enum {headers, body, done}  state{headers};

            async_http_write_impl(AsyncWriteStream& sock_, Message& msg_, std::string& buf_) 
            : sock{sock_}, msg{msg_}, buf{buf_}
            {
                buf.clear();
                details::serialize_header(msg, buf);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nwritten = 0)
            {
                // Error
                if (error)
                    self.complete(error, total_written);

                // Headers
                else if (state == headers)
                {
                    state = body;
                    boost::asio::async_write(sock, boost::asio::buffer(buf), std::move(self)); 
                }

                // Body
                else if (state == body)
                {
                    state = done;
                    total_written += nwritten;

                    // Write string
                    if (!get_content(msg).empty())
                        boost::asio::async_write(sock, boost::asio::buffer(get_content(msg)), std::move(self));

                    // Write file
                    else if (get_file(msg))
                        async_write_file(sock, get_file(msg), buf, 1024, std::move(self));
                
                    // Done
                    else
                        self.complete(boost::system::error_code{}, total_written);
                }

                // Done
                else
                {
                    total_written += nwritten;
                    self.complete(boost::system::error_code{}, total_written);
                }
            }
        };
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_write (
        AsyncWriteStream&   sock,
        response&           resp,
        std::string&        buf,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_write_impl{sock, resp, buf},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_write (
        AsyncWriteStream&   sock,
        request&            req,
        std::string&        buf,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_write_impl{sock, req, buf},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details 
    {
        inline std::string compute_sec_ws_accept(std::string_view sec_ws_key)
        {
            constexpr std::string_view magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            const auto hash = sha1{}.push(sec_ws_key.size(), (const uint8_t*)sec_ws_key.data())
                                    .push(magic.size(),      (const uint8_t*)magic.data())
                                    .finish();
            return base64_encode(hash.size(), &hash[0]);
        }

        template<class AsyncStream>
        struct async_ws_handshake_impl
        {
            AsyncStream&                    sock;
            std::string                     uri;
            std::string                     host;
            uint8_t                         nonce[16]   = {0};
            std::unique_ptr<std::string>    buf         = std::make_unique<std::string>();
            std::unique_ptr<request>        req         = std::make_unique<request>();
            std::unique_ptr<response>       reply       = std::make_unique<response>();
            enum {send_request, read_response, parse_response} state{send_request};

            async_ws_handshake_impl (
                AsyncStream&        sock_, 
                std::string_view    uri_, 
                std::string_view    host_
            ) : sock{sock_}, 
                uri{uri_},
                host{host_}
            {
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t ntransferred = 0)
            {
                // Error
                if (error)
                    self.complete(error);

                // Send request
                else if (state == send_request)
                {
                    state = read_response;

                    for (size_t i{0} ; i < 16 ; ++i)
                        nonce[i] = std::rand() % 0xff;

                    req->verb = GET;
                    req->uri  = uri;
                    req->http_version_major = req->http_version_minor = 1;
                    req->add_header(field::host,                  host);
                    req->add_header(field::user_agent,            "Boost::asio " + std::to_string(BOOST_ASIO_VERSION));
                    req->add_header(field::connection,            "upgrade");
                    req->add_header(field::upgrade,               "websocket");
                    req->add_header(field::sec_websocket_version, "13");
                    req->add_header(field::sec_websocket_key,     base64_encode(16, nonce));

                    async_http_write(sock, *req, *buf, std::move(self));
                }

                // Read respone
                else if (state == read_response)
                {
                    state = parse_response;
                    async_http_read(sock, *reply, *buf, std::move(self));
                }

                // Parse response
                else
                {
                    // Check valid response status code
                    if (reply->status != status_type::switching_protocols)
                        self.complete(make_error_code(ws_handshake_bad_status));

                    // Check connection and upgrade fields
                    else if (!reply->is_websocket_response())
                        self.complete(make_error_code(ws_handshake_bad_headers));

                    // Check Sec-WebSocket-Accept
                    else
                    {
                        auto sec_ws_accept = reply->find(field::sec_websocket_accept);

                        if (sec_ws_accept == end(reply->headers))
                            self.complete(make_error_code(ws_handshake_missing_seq_accept));
                        else if (sec_ws_accept->value != compute_sec_ws_accept(base64_encode(16, nonce)))
                            self.complete(make_error_code(ws_handshake_bad_sec_accept));
                        else
                            self.complete({});
                    }
                }
            }
        };
    }

    template <
      class AsyncStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken
    >
    inline auto async_ws_handshake (
        AsyncStream&        sock,
        std::string_view    host,
        std::string_view    uri,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)> (
            details::async_ws_handshake_impl{sock, host, uri},
            token, sock
        ); 
    }

//----------------------------------------------------------------------------------------------------------------


    namespace details 
    {
        template<class AsyncWriteStream>
        struct async_ws_accept_impl
        {
            AsyncWriteStream&               sock;
            request                         req;
            std::unique_ptr<std::string>    buf{std::make_unique<std::string>()};
            std::unique_ptr<response>       reply{std::make_unique<response>()};
            enum {starting, writing}        state{starting};

            async_ws_accept_impl (
                AsyncWriteStream& sock_,
                request           req_
            ) : sock{sock_},
                req{std::move(req_)}
            {
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t ntransferred = 0)
            {
                // Error
                if (error)
                    self.complete(error, ntransferred);

                // Build reply
                else if (state == starting)
                {
                    state = writing;

                    // Get key
                    auto sec_ws_key = req.find(field::sec_websocket_key);

                    // Missing key
                    if (sec_ws_key == end(req.headers))
                    {
                        self.complete(make_error_code(ws_accept_missing_seq_key), 0);
                    }

                    // Got key
                    else
                    {
                        // Send response
                        reply->status               = status_type::switching_protocols;
                        reply->http_version_major   = req.http_version_major;
                        reply->http_version_minor   = req.http_version_minor;
                        reply->add_header(field::server,        "Boost::asio " + std::to_string(BOOST_ASIO_VERSION));
                        reply->add_header(field::upgrade,       "websocket");
                        reply->add_header(field::connection,    "Upgrade");
                        reply->add_header(field::sec_websocket_accept, compute_sec_ws_accept(sec_ws_key->value));
                        async_http_write(sock, *reply, *buf, std::move(self));
                    }
                }

                // Response sent - complete
                else if (state == writing)
                {
                    self.complete({}, ntransferred);
                }
            }
        };
    }

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_ws_accept (
        AsyncWriteStream&   sock,
        request             req,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_ws_accept_impl{sock, std::move(req)},
            token, sock
        );     
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details 
    {

//----------------------------------------------------------------------------------------------------------------

        enum websocket_opcode : int
        {
            WS_OPCODE_CONTINUATION  = 0,
            WS_OPCODE_DATA_TEXT     = 1,
            WS_OPCODE_DATA_BINARY   = 2,
            WS_OPCODE_CLOSE         = 8,
            WS_OPCODE_PING          = 9,
            WS_OPCODE_PONG          = 10
        };
    
//----------------------------------------------------------------------------------------------------------------

        struct websocket_frame
        {
            unsigned char opcode : 4;
            unsigned char rsv3   : 1;
            unsigned char rsv2   : 1;
            unsigned char rsv1   : 1;
            unsigned char fin    : 1;
            unsigned char paylen : 7;
            unsigned char masked : 1;
        };

        static_assert(sizeof(websocket_frame) == 2, "bad");
    
//----------------------------------------------------------------------------------------------------------------

        template <
          class AsyncWriteStream, 
          BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
        >
        inline auto async_ws_write (
            AsyncWriteStream&   sock,
            std::vector<char>&  buf,
            websocket_opcode    opcode,
            bool                do_mask,
            CompletionToken&&   token
        )
        {
            // Header
            websocket_frame hdr{};
            memset(&hdr, 0, sizeof(websocket_frame));
            size_t hdr_len = sizeof(websocket_frame);
            hdr.fin     = 1;
            hdr.masked  = do_mask;
            hdr.opcode  = opcode;

            // Payload size
            const size_t pay_len = buf.size();

            if (pay_len < 126)
            {
                hdr.paylen = pay_len;
            }     
            else if (pay_len <= 65535)
            {
                hdr.paylen = 126;
                hdr_len += 2;
            }
            else
            {
                hdr.paylen = 127;
                hdr_len += 8;
            }

            if (do_mask)
            {
                hdr_len += 4;
            }
            
            // Copy into buffer
            buf.insert(begin(buf), hdr_len, 0);
            size_t off{0};

            memcpy(&buf[off], &hdr, sizeof(websocket_frame));
            off += sizeof(websocket_frame);

            if (hdr.paylen == 126)
            {
                uint16_t len = htobe16((uint16_t)pay_len);
                memcpy(&buf[off], &len, 2);
                off += 2;
            }

            else if (hdr.paylen == 127)
            {
                uint64_t len = htobe64((uint64_t)pay_len);
                memcpy(&buf[off], &len, 8);
                off += 8;
            }

            if (do_mask)
            {
                // Create mask key
                uint8_t mask_key[4];
                mask_key[0] = std::rand() % 0xff;
                mask_key[1] = std::rand() % 0xff;
                mask_key[2] = std::rand() % 0xff;
                mask_key[3] = std::rand() % 0xff;

                // Write mask key
                memcpy(&buf[off], mask_key, 4);
                off += 4;

                // Mask
                for (size_t i = 0 ; i < pay_len ; ++i)
                    buf[i+off] ^= mask_key[i%4];
            }

            return boost::asio::async_write(sock, boost::asio::buffer(buf), std::forward<CompletionToken>(token));
        }

//----------------------------------------------------------------------------------------------------------------

    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncWriteStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_ws_write (
        AsyncWriteStream&   sock,
        std::vector<char>&  buf,
        bool                is_text,
        bool                is_server,
        CompletionToken&&   token
    )
    {
        using namespace details;
        const websocket_opcode code     = is_text ? WS_OPCODE_DATA_TEXT : WS_OPCODE_DATA_BINARY;
        const bool             do_mask  = !is_server;
        return async_ws_write(sock, buf, code, do_mask, std::forward<CompletionToken>(token));
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details 
    {

//----------------------------------------------------------------------------------------------------------------

        template<class AsyncReadStream>
        struct async_ws_read_one_impl
        {
            AsyncReadStream&    sock;
            std::vector<char>&  buf;
            size_t              offset{0};
            websocket_opcode    opcode{WS_OPCODE_CONTINUATION};
            bool                is_masked{false};
            bool                is_last{false};
            uint8_t             mask_key[4];
            uint64_t            paylen{0};
            enum {header0_read,
                  header0_parse,
                  header1_parse,
                  body} state{header0_read};
        
            async_ws_read_one_impl(AsyncReadStream& sock_, std::vector<char>& buf_)
            : sock{sock_}, buf{buf_}
            {
                buf.clear();
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t ntransferred = 0)
            {
                // Error
                if (error)
                    self.complete(error, {});

                // Header 0 read
                else if (state == header0_read)
                {
                    state = header0_parse;
                    buf.resize(offset + sizeof(websocket_frame));
                    boost::asio::async_read(sock, boost::asio::buffer(&buf[offset], sizeof(websocket_frame)), std::move(self)); 
                }

                // Header 0 parse
                else if (state == header0_parse)
                {
                    assert(ntransferred == sizeof(websocket_frame));
                    websocket_frame hdr;
                    memcpy(&hdr, &buf[offset], sizeof(websocket_frame));
                    buf.erase(begin(buf) + offset, begin(buf) + offset + sizeof(websocket_frame));

                    // Update state
                    is_masked = hdr.masked;
                    is_last   = hdr.fin;
                    paylen    = hdr.paylen;
                    if (hdr.opcode > 0)
                        opcode = (websocket_opcode)hdr.opcode;
                    
                    // Calculate size of next header bit
                    size_t nextsize{0};
                    if (hdr.paylen == 126)
                        nextsize += 2;
                    else if (hdr.paylen == 127)
                        nextsize += 8;
                    if (hdr.masked)
                        nextsize += 4;

                    // Next state transition
                    if (nextsize > 0)
                    {
                        state = header1_parse;
                        buf.resize(offset + nextsize);
                        boost::asio::async_read(sock, boost::asio::buffer(&buf[offset], nextsize), std::move(self)); 
                    }
                    else if (nextsize == 0)
                    {
                        state = body;
                        buf.resize(offset + paylen);
                        boost::asio::async_read(sock, boost::asio::buffer(&buf[offset], paylen), std::move(self));
                    }
                }

                // Header 2 parse
                else if (state == header1_parse)
                {
                    assert(ntransferred == (buf.size()-offset));

                    size_t off{0};

                    // Read 16-bit paylen
                    if (paylen == 126)
                    {
                        uint16_t len{0};
                        memcpy(&len, &buf[offset+off], 2);
                        paylen = be16toh(len);
                        off += 2;
                    }
                
                    // Read 64-bit paylen
                    else if (paylen == 127)
                    {
                        uint64_t len{0};
                        memcpy(&len, &buf[offset+off], 8);
                        paylen = be64toh(len);
                        off += 8;
                    }

                    // Read mask
                    if (is_masked)
                    {
                        memcpy(mask_key, &buf[offset+off], 4);
                        off += 4;
                    }
                    
                    // Remove header
                    buf.erase(begin(buf) + offset, begin(buf) + offset + off);
                    assert(buf.size() == offset);

                    // State transition
                    state = body;
                    buf.resize(offset + paylen);
                    boost::asio::async_read(sock, boost::asio::buffer(&buf[offset], paylen), std::move(self));
                }

                // Body
                else if (state == body)
                {
                    assert(ntransferred == (buf.size()-offset));

                    // Un-mask if necessary
                    if (is_masked)
                    {
                        for (size_t i = 0 ; i < paylen ; ++i)
                            buf[i+offset] ^= mask_key[i%4];
                    }

                    // Move offset forward
                    offset += ntransferred;

                    // Check if this is the end
                    if (is_last)
                    {
                        self.complete(boost::system::error_code{}, opcode);
                    }
                    else
                    {
                        state = header0_parse;
                        buf.resize(offset + sizeof(websocket_frame));
                        boost::asio::async_read(sock, boost::asio::buffer(&buf[offset], sizeof(websocket_frame)), std::move(self)); 
                    }
                }
            }
        };

        template <
          class AsyncReadStream, 
          BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, websocket_opcode)) CompletionToken
        >
        inline auto async_ws_read_one (
            AsyncReadStream&    sock,
            std::vector<char>&  buf,
            CompletionToken&&   token
        )
        {
            return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, websocket_opcode)> (
                async_ws_read_one_impl{sock, buf},
                token, sock
            );
        }

//----------------------------------------------------------------------------------------------------------------

        ws_code parse_ws_code(std::vector<char>& buf)
        {
            assert(buf.size() >= 2);
            uint16_t code{};
            memcpy(&code, &buf[0], 2);
            code = ntohs(code);
            return static_cast<ws_code>(code);
        }

        void serialize_ws_code(std::vector<char>& buf, ws_code code)
        {
            buf.resize(2);
            const uint16_t tmp = htons(code);
            memcpy(&buf[0], &tmp, 2);
        }

        template<class AsyncStream>
        struct async_ws_close_impl
        {
            AsyncStream&                        sock;
            ws_code                             reason;
            bool                                read_response;
            bool                                is_server;
            std::unique_ptr<std::vector<char>>  buf{std::make_unique<std::vector<char>>()};
            enum {writing, reading, parsing, done} state{writing};

            async_ws_close_impl (
                AsyncStream&    sock_,
                ws_code         reason_,
                bool            read_response_,
                bool            is_server_
            ) : sock{sock_},
                reason{reason_},
                read_response{read_response_},
                is_server{is_server_}
            {
            }

            template<class Self>
            void run(Self& self, boost::system::error_code error, size_t bytes_transferred, websocket_opcode code)
            {
                // Error
                if (error)
                    self.complete(error);

                // Write first CLOSE frame
                if (state == writing)
                {
                    state = read_response ? reading : done;
                    serialize_ws_code(*buf, reason);
                    async_ws_write(sock, *buf, WS_OPCODE_CLOSE, !is_server, std::move(self));
                }

                // Read echoed CLOSE frame
                else if (state == reading)
                {
                    state = parsing;
                    async_ws_read_one(sock, *buf, std::move(self));
                }

                // Check echoed CLOSE frame
                else if (state == parsing)
                {
                    if (code != WS_OPCODE_CLOSE)
                        self.complete(make_error_code(ws_closing_handshake_non_matching_opcode));
                    
                    else
                    {
                        const ws_code reason_echoed = parse_ws_code(*buf);

                        if (reason != reason_echoed)
                            self.complete(make_error_code(ws_closing_handshake_non_matching_reason));
                        else
                            self.complete({});
                    }
                }

                // We are done
                else
                {
                    self.complete({});
                }
            }

            template<class Self>
            void operator()(Self& self)
            {
                run(self, {}, 0, WS_OPCODE_CONTINUATION);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error, size_t bytes_transferred)
            {
                run(self, error, bytes_transferred, WS_OPCODE_CONTINUATION);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error, websocket_opcode code)
            {
                run(self, error, 0, code);
            }
        };

//----------------------------------------------------------------------------------------------------------------

        template <
          class AsyncStream, 
          BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken
        >
        inline auto async_ws_close_one (
            AsyncStream&        sock,
            ws_code             reason,
            bool                is_server,
            CompletionToken&&   token
        )
        {
            return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)> (
                async_ws_close_impl{sock, reason, false, is_server},
                token, sock
            );
        }

//----------------------------------------------------------------------------------------------------------------

    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken
    >
    inline auto async_ws_close (
        AsyncStream&        sock,
        ws_code             reason,
        bool                is_server,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)> (
            details::async_ws_close_impl{sock, reason, true, is_server},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        template<class AsyncReadStream>
        struct async_ws_read_impl
        {
            AsyncReadStream&    sock;
            std::vector<char>&  buf;
            bool                is_server;
            ws_code             closing_code;
            enum {reading, parse, closing} state{reading};

            async_ws_read_impl(AsyncReadStream& sock_, std::vector<char>& buf_, bool is_server_)
            : sock{sock_}, buf{buf_}, is_server{is_server_}
            {
                buf.clear();
            }

            template<class Self>
            void run(Self& self, boost::system::error_code error, size_t bytes_transferred, websocket_opcode code)
            {
                // Error
                if (error)
                    self.complete(error, {});

                // Read
                else if (state == reading)
                {
                    state = parse;
                    async_ws_read_one(sock, buf, std::move(self));
                }

                // Parse
                else if (state == parse)
                {
                    uint16_t reason{};
                    switch(code)
                    {
                    case WS_OPCODE_DATA_TEXT:
                        self.complete({}, true);
                        break;
                    case WS_OPCODE_DATA_BINARY:
                        self.complete({}, false);
                        break;
                    case WS_OPCODE_CLOSE:
                        state = closing;
                        closing_code = parse_ws_code(buf);
                        async_ws_close_one(sock, closing_code, is_server, std::move(self));
                        break;
                    case WS_OPCODE_PING:
                        state = reading;
                        async_ws_write(sock, buf, WS_OPCODE_PONG, !is_server, std::move(self));
                        break;
                    case WS_OPCODE_PONG:
                        state = parse;
                        async_ws_read_one(sock, buf, std::move(self));
                        break;
                    default:
                        self.complete(make_error_code(ws_invalid_opcode), {});
                        break;
                    }
                }

                // Closing
                else if (state == closing)
                {
                    self.complete(make_error_code(closing_code), {});
                }
            }

            template<class Self>
            void operator()(Self& self)
            {
                run(self, {}, 0, WS_OPCODE_CONTINUATION);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error)
            {
                run(self, error, 0, WS_OPCODE_CONTINUATION);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error, size_t bytes_transferred)
            {
                run(self, error, bytes_transferred, WS_OPCODE_CONTINUATION);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error, websocket_opcode code)
            {
                run(self, error, 0, code);
            }
        };
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class AsyncReadStream, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, bool)) CompletionToken
    >
    inline auto async_ws_read (
        AsyncReadStream&    sock,
        std::vector<char>&  buf,
        bool                is_server,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, bool)> (
            details::async_ws_read_impl{sock, buf, is_server},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

}
