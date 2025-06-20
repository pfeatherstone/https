#pragma once

#include <boost/asio/version.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/compose.hpp>
#include "http.h"

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    template<class Socket>
    struct stream
    {
        Socket      sock;
        bool        is_server{};
        std::string buf_read;
        std::string buf_write;

        template<class Executor>
        struct rebind_executor { using other = stream<typename Socket::template rebind_executor<Executor>::other>; };
        using executor_type     = typename Socket::executor_type;
        using next_layer_type   = Socket;

        stream(Socket sock_, bool is_server_) : sock{std::move(sock_)}, is_server{is_server_} {}

        const auto& next_layer()                const noexcept {return sock;}
        auto&       next_layer()                      noexcept {return sock;}
        auto&       lowest_layer()                    noexcept {return sock.lowest_layer();}
        auto        get_executor()                    noexcept {return sock.get_executor();}
        auto        get_cancellation_state()          noexcept {return boost::asio::get_associated_cancellation_slot(sock);}
        auto        get_allocator()             const noexcept {return boost::asio::get_associated_allocator(sock);}
    };

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_http_read (
        stream<Sock>&       sock,
        request&            req,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_http_read (
        stream<Sock>&       sock,
        response&           resp,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_write_file (
        stream<Sock>&       sock,
        FILE*               file,
        std::size_t         chunk_size,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_http_write (
        stream<Sock>&       sock,
        response&           resp,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_http_write (
        stream<Sock>&       sock,
        request&            req,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_ws_handshake (
        stream<Sock>&       sock,
        std::string_view    host,
        std::string_view    uri,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_ws_accept (
        stream<Sock>&       sock,
        request             req,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, bool)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_ws_read (
        stream<Sock>&       sock,
        std::vector<char>&  msg,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_ws_write (
        stream<Sock>&               sock,
        boost::asio::const_buffer   msg,
        bool                        is_text,
        CompletionToken&&           token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken = boost::asio::default_completion_token_t<typename Sock::executor_type>
    >
    auto async_ws_close (
        stream<Sock>&       sock,
        ws_code             reason,
        CompletionToken&&   token = boost::asio::default_completion_token_t<typename Sock::executor_type>()
    );

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// DEFINITIONS
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

    namespace details
    {

//----------------------------------------------------------------------------------------------------------------
   
        template<class Sock, class Message>
        struct async_http_read_impl
        {
            stream<Sock>&   sock;
            Message&        msg;
            parser<Message> parser_;
            size_t          total_read{0};
            size_t          buf_off{0};

            async_http_read_impl(stream<Sock>& sock_, Message& msg_)
            : sock{sock_}, msg{msg_}
            {
                msg.clear();
                buf_off = sock.buf_read.size();
            }
            
            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nread = 0)
            {
                // IO error
                if (error)
                    self.complete(error, total_read);

                else
                {
                    total_read  += nread;
                    buf_off     += nread;
                    sock.buf_read.resize(buf_off);

                    auto finished = parser_.parse(msg, sock.buf_read, error);

                    // Parsing error
                    if (error)
                        self.complete(error, total_read);

                    // Incomplete
                    else if (!finished)
                    {
                        buf_off = sock.buf_read.size();
                        sock.buf_read.resize(buf_off + 128);
                        sock.sock.async_read_some(boost::asio::buffer(&sock.buf_read[buf_off], 128), std::move(self));
                    }
                            
                    // Done
                    else
                        self.complete({}, total_read);
                }
            }
        };
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_read (
        stream<Sock>&       sock,
        request&            req,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_read_impl{sock, req},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_read (
        stream<Sock>&       sock,
        response&           resp,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_read_impl{sock, resp},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        template<class Sock>
        struct async_write_file_impl
        {
            stream<Sock>&   sock;
            FILE*           file;
            size_t          size{};
            size_t          offset{0};

            async_write_file_impl(stream<Sock>& sock_, FILE* file_, std::size_t chunksize_)
            : sock{sock_}, file{file_}
            {
                fseek(file, 0, SEEK_END);
                size = ftell(file);
                fseek(file, 0, SEEK_SET);
                sock.buf_write.resize(chunksize_);
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nwritten = 0)
            {
                // Error
                if (error)
                    self.complete(error, offset);
                
                // End of file
                else if (offset == size)
                    self.complete({}, offset);

                // Bad file
                else if (ferror(file) || feof(file))
                    self.complete(boost::asio::error::broken_pipe, offset);

                // Keep writing
                else 
                {
                    const size_t nread = fread(sock.buf_write.data(), 1, sock.buf_write.size(), file);
                    offset += nread;
                    // sock.sock.async_write_some(boost::asio::buffer(sock.buf_write, nread), std::move(self));
                    boost::asio::async_write(sock.sock, boost::asio::buffer(sock.buf_write, nread), std::move(self));
                }
            }
        };
    }

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_write_file (
        stream<Sock>&       sock,
        FILE*               file,
        std::size_t         chunk_size,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_write_file_impl{sock, file, chunk_size},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        template<class Sock, class Message>
        struct async_http_write_impl
        {
            stream<Sock>&               sock;
            Message&                    msg;
            size_t                      total_written{0};
            enum {headers, body, done}  state{headers};

            async_http_write_impl(stream<Sock>& sock_, Message& msg_) 
            : sock{sock_}, msg{msg_}
            {
                sock.buf_write.clear();
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nwritten = 0)
            {
                // IO error
                if (error)
                {
                    sock.buf_write.clear();
                    self.complete(error, total_written);
                }
                    
                // Headers
                else if (state == headers)
                {
                    state = body;
                    serialize_header(msg, sock.buf_write, error);

                    // Serializer error
                    if (error)
                    {
                        sock.buf_write.clear();
                        self.complete(error, total_written);
                    }
                        
                    else
                        boost::asio::async_write(sock.sock, boost::asio::buffer(sock.buf_write), std::move(self)); 
                }

                // Body
                else if (state == body)
                {
                    state = done;
                    total_written += nwritten;

                    // Write string
                    if (!get_content(msg).empty())
                        boost::asio::async_write(sock.sock, boost::asio::buffer(get_content(msg)), std::move(self));

                    // Write file
                    else if (get_file(msg))
                        async_write_file(sock, get_file(msg), 1024, std::move(self));
                
                    // Done
                    else
                    {
                        sock.buf_write.clear();
                        self.complete({}, total_written);
                    }
                }

                // Done
                else
                {
                    total_written += nwritten;
                    sock.buf_write.clear();
                    self.complete({}, total_written);
                }
            }
        };
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_write (
        stream<Sock>&       sock,
        response&           resp,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_write_impl{sock, resp},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_http_write (
        stream<Sock>&       sock,
        request&            req,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            details::async_http_write_impl{sock, req},
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

        template<class Sock>
        struct async_ws_handshake_impl
        {
            stream<Sock>&               sock;
            std::string                 host;
            std::string                 uri;
            uint8_t                     nonce[16]   = {0};
            std::unique_ptr<request>    req         = std::make_unique<request>();
            std::unique_ptr<response>   reply       = std::make_unique<response>();
            enum {send_request, read_response, parse_response} state{send_request};

            async_ws_handshake_impl (
                stream<Sock>&       sock_,
                std::string_view    host_, 
                std::string_view    uri_
            ) : sock{sock_},  host{host_}, uri{uri_}
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

                    req->verb = METHOD_GET;
                    req->uri  = uri;
                    req->add_header(field::host,                  host);
                    req->add_header(field::user_agent,            "Boost::asio " + std::to_string(BOOST_ASIO_VERSION));
                    req->add_header(field::connection,            "upgrade");
                    req->add_header(field::upgrade,               "websocket");
                    req->add_header(field::sec_websocket_version, "13");
                    req->add_header(field::sec_websocket_key,     base64_encode(16, nonce));
                    async_http_write(sock, *req, std::move(self));
                }

                // Read respone
                else if (state == read_response)
                {
                    state = parse_response;
                    async_http_read(sock, *reply, std::move(self));
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
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken
    >
    inline auto async_ws_handshake (
        stream<Sock>&       sock,
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
        template<class Sock>
        struct async_ws_accept_impl
        {
            stream<Sock>&                   sock;
            request                         req;
            std::unique_ptr<response>       reply{std::make_unique<response>()};
            enum {starting, writing}        state{starting};

            async_ws_accept_impl (
                stream<Sock>&   sock_,
                request         req_
            ) : sock{sock_}, req{std::move(req_)}
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
                        reply->status   = status_type::switching_protocols;
                        reply->version  = req.version;
                        reply->add_header(field::server,        "Boost::asio " + std::to_string(BOOST_ASIO_VERSION));
                        reply->add_header(field::upgrade,       "websocket");
                        reply->add_header(field::connection,    "Upgrade");
                        reply->add_header(field::sec_websocket_accept, compute_sec_ws_accept(sec_ws_key->value));
                        async_http_write(sock, *reply, std::move(self));
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
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_ws_accept (
        stream<Sock>&       sock,
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

        template <
          class Sock, 
          BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
        >
        inline auto async_ws_write (
            stream<Sock>&               sock,
            boost::asio::const_buffer   buf,
            websocket_opcode            opcode,
            CompletionToken&&           token
        )
        {
            const bool do_mask = !sock.is_server;
            serialize_websocket_message(buf, opcode, do_mask, sock.buf_write);
            return boost::asio::async_write(sock.sock, boost::asio::buffer(sock.buf_write), std::forward<CompletionToken>(token));
        }

//----------------------------------------------------------------------------------------------------------------

    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, std::size_t)) CompletionToken
    >
    inline auto async_ws_write (
        stream<Sock>&               sock,
        boost::asio::const_buffer   buf,
        bool                        is_text,
        CompletionToken&&           token
    )
    {
        using namespace details;
        const websocket_opcode code = is_text ? WS_OPCODE_DATA_TEXT : WS_OPCODE_DATA_BINARY;
        return async_ws_write(sock, buf, code, std::forward<CompletionToken>(token));
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details 
    {

//----------------------------------------------------------------------------------------------------------------

        template<class Sock>
        struct async_ws_read_one_impl
        {
            stream<Sock>&       sock;
            std::vector<char>&  msg;
            websocket_parser    parser;
            size_t              buf_off{0};

            async_ws_read_one_impl(stream<Sock>& sock_, std::vector<char>& msg_)
            : sock{sock_}, msg{msg_}
            {
                msg.clear();
                buf_off = sock.buf_read.size();
            }

            template<class Self>
            void operator()(Self& self, boost::system::error_code error = {}, std::size_t nread = 0)
            {
                // Error
                if (error)
                    self.complete(error, {});

                else
                {
                    buf_off += nread;
                    sock.buf_read.resize(buf_off);

                    auto finished = parser.parse(msg, sock.buf_read, error);

                    // Parsing error
                    if (error)
                        self.complete(error, parser.get_opcode());

                    // Incomplete
                    else if (!finished)
                    {
                        buf_off = sock.buf_read.size();
                        sock.buf_read.resize(buf_off + 128);
                        sock.sock.async_read_some(boost::asio::buffer(&sock.buf_read[buf_off], 128), std::move(self));
                    }
                            
                    // Done
                    else
                        self.complete({}, parser.get_opcode());
                }
            }
        };

        template <
          class Sock, 
          BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, websocket_opcode)) CompletionToken
        >
        inline auto async_ws_read_one (
            stream<Sock>&       sock,
            std::vector<char>&  msg,
            CompletionToken&&   token
        )
        {
            return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, websocket_opcode)> (
                async_ws_read_one_impl{sock, msg},
                token, sock
            );
        }

//----------------------------------------------------------------------------------------------------------------

        inline ws_code parse_ws_code(std::vector<char>& buf)
        {
            assert(buf.size() >= 2);
            uint16_t code{};
            memcpy(&code, &buf[0], 2);
            code = ntohs(code);
            return static_cast<ws_code>(code);
        }

        inline void serialize_ws_code(std::vector<char>& buf, ws_code code)
        {
            buf.resize(2);
            const uint16_t tmp = htons(code);
            memcpy(&buf[0], &tmp, 2);
        }

        template<class Sock>
        struct async_ws_close_impl
        {
            stream<Sock>&                       sock;   
            ws_code                             reason;
            bool                                read_response;
            std::unique_ptr<std::vector<char>>  msg{std::make_unique<std::vector<char>>()};
            enum {writing, reading, parsing, done} state{writing};

            async_ws_close_impl (
                stream<Sock>&   sock_,
                ws_code         reason_,
                bool            read_response_
            ) : sock{sock_},
                reason{reason_},
                read_response{read_response_}
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
                    serialize_ws_code(*msg, reason);
                    async_ws_write(sock, boost::asio::buffer(*msg), WS_OPCODE_CLOSE, std::move(self));
                }

                // Read echoed CLOSE frame
                else if (state == reading)
                {
                    state = parsing;
                    async_ws_read_one(sock, *msg, std::move(self));
                }

                // Check echoed CLOSE frame
                else if (state == parsing)
                {
                    if (code != WS_OPCODE_CLOSE)
                        self.complete(make_error_code(ws_closing_handshake_non_matching_opcode));
                    
                    else
                    {
                        const ws_code reason_echoed = parse_ws_code(*msg);

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
          class Sock, 
          BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken
        >
        inline auto async_ws_close_one (
            stream<Sock>&       sock,
            ws_code             reason,
            CompletionToken&&   token
        )
        {
            return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)> (
                async_ws_close_impl{sock, reason, false},
                token, sock
            );
        }

//----------------------------------------------------------------------------------------------------------------

    }

//----------------------------------------------------------------------------------------------------------------

    template <
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code)) CompletionToken
    >
    inline auto async_ws_close (
        stream<Sock>&       sock,
        ws_code             reason,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)> (
            details::async_ws_close_impl{sock, reason, true},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    namespace details
    {
        template<class Sock>
        struct async_ws_read_impl
        {
            stream<Sock>&       sock;
            std::vector<char>&  msg;
            ws_code             closing_code;
            enum {reading, parse, closing} state{reading};

            async_ws_read_impl(stream<Sock>& sock_, std::vector<char>& msg_)
            : sock{sock_}, msg{msg_}
            {
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
                    async_ws_read_one(sock, msg, std::move(self));
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
                        closing_code = parse_ws_code(msg);
                        async_ws_close_one(sock, closing_code, std::move(self));
                        break;
                    case WS_OPCODE_PING:
                        state = reading;
                        async_ws_write(sock, boost::asio::buffer(msg), WS_OPCODE_PONG, std::move(self));
                        break;
                    case WS_OPCODE_PONG:
                        async_ws_read_one(sock, msg, std::move(self));
                        break;
                    default:
                        self.complete(ws_invalid_opcode, {});
                        break;
                    }
                }

                // Closing
                else if (state == closing)
                {
                    self.complete(closing_code, {});
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
      class Sock, 
      BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code, bool)) CompletionToken
    >
    inline auto async_ws_read (
        stream<Sock>&       sock,
        std::vector<char>&  msg,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, bool)> (
            details::async_ws_read_impl{sock, msg},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

}
