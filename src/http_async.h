#pragma once

#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/compose.hpp>
#include "http_error.h"
#include "http_message.h"
#include "picohttpparser.h"

namespace http
{

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncReadStream, class CompletionToken>
    auto async_http_read (
        AsyncReadStream&    sock,
        request&            req,
        std::string&        buf,
        CompletionToken&&   token
    );

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncWriteStream, class CompletionToken>
    auto async_write_file (
        AsyncWriteStream&   sock,
        std::istream&       file,
        std::size_t         chunk_size,
        CompletionToken&&   token
    );

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncWriteStream, class CompletionToken>
    auto async_http_write (
        AsyncWriteStream&   sock,
        response&           resp,
        CompletionToken&&   token
    );

//----------------------------------------------------------------------------------------------------------------

    enum websocket_opcode : int
    {
        WS_OPCODE_ERROR         = -1,
        WS_OPCODE_CONTINUATION  = 0,
        WS_OPCODE_DATA_TEXT     = 1,
        WS_OPCODE_DATA_BINARY   = 2,
        WS_OPCODE_CLOSE         = 8,
        WS_OPCODE_PING          = 9,
        WS_OPCODE_PONG          = 10
    };

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

    template<class AsyncReadStream, class CompletionToken>
    auto async_ws_read (
        AsyncReadStream&    sock,
        std::vector<char>&  buf_tmp,
        std::vector<char>&  buf_pay,
        CompletionToken&&   token
    );

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncWriteStream, class Byte, class CompletionToken>
    auto async_ws_write (
        AsyncWriteStream&   sock,
        std::vector<char>&  buf_tmp,
        std::vector<Byte>&  buf_pay,
        websocket_opcode    opcode,
        bool                do_mask,
        CompletionToken&&   token
    );

//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------
// DEFINITIONS
//----------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------

    template<class AsyncReadStream>
    struct async_http_read_impl
    {
        AsyncReadStream&            sock;
        request&                    req;
        std::string&                buf;
        size_t                      total_read{0};
        size_t                      body_read{0};
        enum {header, parse, body}  state{header};

        async_http_read_impl(AsyncReadStream& sock_, request& req_, std::string& buf_)
        : sock{sock_}, req{req_}, buf{buf_}
        {
            buf.clear();
            req.clear();
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
                const char* method{nullptr};
                size_t      method_len{0};
                const char* path{nullptr};
                size_t      path_len{0};
                int         version_minor{-1};
                phr_header  headers[100];
                size_t      headers_len{0};

                int res = phr_parse_request(
                    buf.c_str(),  nread, 
                    &method,      &method_len, 
                    &path,        &path_len,
                    &version_minor,
                    headers, &headers_len,
                    0
                );

                // Header fail
                if (res < 0)
                    self.complete(make_error_code(HTTP_READ_HEADER_FAIL), total_read);

                // Header ok
                else
                {
                    buf.erase(begin(buf), begin(buf) + res);
                    total_read += res;

                    // Set fields
                    req.method              = method;
                    req.uri                 = path;
                    req.http_version_major  = 1;
                    req.http_version_minor  = version_minor;
                    req.headers.resize(headers_len);
                    for (int h = 0 ; h < headers_len ; ++h)
                    {
                        req.headers[h].name   = headers[h].name;
                        req.headers[h].values = headers[h].value;
                    }

                    // Next state
                    state = body;
                    const auto it = req.find(field::content_length);

                    // Read body
                    if (it != end(req.headers))
                    {
                        const size_t content_size   = std::stoul(it->values);
                        body_read                   = std::min(buf.size(), content_size);
                        const size_t remaining      = content_size - body_read;
                        req.content.resize(content_size);
                        std::copy(begin(buf), begin(buf) + body_read, begin(req.content));
                        buf.erase(begin(buf), begin(buf) + body_read);
                        total_read += body_read;
                        
                        // Body already read
                        if (remaining == 0)
                            self.complete(boost::system::error_code{}, total_read);

                        // Read body
                        if (remaining > 0)
                            boost::asio::async_read(sock, boost::asio::buffer(&req.content[body_read], remaining), std::move(self));
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
                if (body_read != req.content.size())
                    self.complete(make_error_code(HTTP_READ_BODY_FAIL), total_read);
                
                // Read complete body
                else
                    self.complete(boost::system::error_code{}, total_read);
            }
        }
    };

    template<class AsyncReadStream, class CompletionToken>
    inline auto async_http_read (
        AsyncReadStream&    sock,
        request&            req,
        std::string&        buf,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            async_http_read_impl{sock, req, buf},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncWriteStream>
    struct async_write_file_impl
    {
        AsyncWriteStream&   sock;
        std::istream&       file;
        std::vector<char>   buf;
        size_t              size{};
        size_t              offset{0};

        async_write_file_impl(AsyncWriteStream& sock_, std::istream& file_, std::size_t chunksize_)
        : sock{sock_}, file{file_}, buf(chunksize_)
        {
            file.seekg(0, std::ios::end);
            size = file.tellg();
            file.seekg(0, std::ios::beg);
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
            else if (!file || file.eof())
                self.complete(boost::asio::error::make_error_code(boost::asio::error::broken_pipe), offset);

            // Keep writing
            else 
            {
                file.read(buf.data(), buf.size());
                const size_t nread = file.gcount();
                offset += nread;
                boost::asio::async_write(sock, boost::asio::buffer(buf, nread), std::move(self));
            }
        }
    };

    template<class AsyncWriteStream, class CompletionToken>
    inline auto async_write_file (
        AsyncWriteStream&   sock,
        std::istream&       file,
        std::size_t         chunk_size,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            async_write_file_impl{sock, file, chunk_size},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncWriteStream>
    struct async_http_write_impl
    {
        AsyncWriteStream&           sock;
        response&                   resp;
        size_t                      total_written{0};
        enum {headers, body, done}  state{headers};

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
                boost::asio::async_write(sock, resp.buffers, std::move(self)); 
            }

            // Body
            else if (state == body)
            {
                state = done;
                total_written += nwritten;

                // Write string
                if (!resp.content_str.empty())
                    boost::asio::async_write(sock, boost::asio::buffer(resp.content_str), std::move(self));

                // Write file
                else if (resp.content_file.is_open())
                    async_write_file(sock, resp.content_file, 1024, std::move(self));
            
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

    template<class AsyncWriteStream, class CompletionToken>
    inline auto async_http_write (
        AsyncWriteStream&   sock,
        response&           resp,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)> (
            async_http_write_impl<AsyncWriteStream>{sock, resp},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncReadStream>
    struct async_ws_read_impl
    {
        AsyncReadStream&    sock;
        std::vector<char>&  buf_tmp;
        std::vector<char>&  buf_pay;
        websocket_opcode    opcode{WS_OPCODE_CONTINUATION};
        bool                is_masked{false};
        bool                is_last{false};
        uint8_t             mask_key[4];
        uint64_t            paylen{0};
        enum {header0_read,
              header0_parse,
              header1_parse,
              body} state{header0_read};
    
        async_ws_read_impl(AsyncReadStream& sock_, std::vector<char>& buf_tmp_, std::vector<char>& buf_pay_)
        : sock{sock_}, buf_tmp{buf_tmp_}, buf_pay{buf_pay_}
        {
            buf_tmp.clear();
            buf_pay.clear();
        }

        template<class Self>
        void operator()(Self& self, boost::system::error_code error = {}, std::size_t ntransferred = 0)
        {
            // Error
            if (error)
                self.complete(error, WS_OPCODE_ERROR);

            // Header 0 read
            else if (state == header0_read)
            {
                state = header0_parse;
                buf_tmp.resize(sizeof(websocket_frame));
                boost::asio::async_read(sock, boost::asio::buffer(buf_tmp), std::move(self)); 
            }

            // Header 0 parse
            else if (state == header0_parse)
            {
                assert(ntransferred == sizeof(websocket_frame));
                websocket_frame hdr;
                memcpy(&hdr, buf_tmp.data(), sizeof(websocket_frame));

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
                    buf_tmp.resize(nextsize);
                    boost::asio::async_read(sock, boost::asio::buffer(buf_tmp), std::move(self)); 
                }
                else if (nextsize == 0)
                {
                    state = body;
                    buf_tmp.resize(paylen);
                    boost::asio::async_read(sock, boost::asio::buffer(buf_tmp), std::move(self));
                }
            }

            // Header 2 parse
            else if (state == header1_parse)
            {
                assert(ntransferred == buf_tmp.size());

                size_t off{0};

                // Read 16-bit paylen
                if (paylen == 126)
                {
                    uint16_t len{0};
                    memcpy(&len, &buf_tmp[off], 2);
                    paylen = be16toh(len);
                    off += 2;
                }
            
                // Read 64-bit paylen
                else if (paylen == 127)
                {
                    uint64_t len{0};
                    memcpy(&len, &buf_tmp[off], 8);
                    paylen = be64toh(len);
                    off += 8;
                }

                // Read mask
                if (is_masked)
                    memcpy(mask_key, &buf_tmp[off], 4);

                // State transition
                state = body;
                buf_tmp.resize(paylen);
                boost::asio::async_read(sock, boost::asio::buffer(buf_tmp), std::move(self));
            }

            // Body
            else if (state == body)
            {
                assert(ntransferred == buf_tmp.size());

                // Un-mask if necessary
                if (is_masked)
                {
                    for (size_t i = 0 ; i < buf_tmp.size() ; ++i)
                        buf_tmp[i] ^= mask_key[i%4];
                }

                // Append data
                buf_pay.insert(end(buf_pay), begin(buf_tmp), end(buf_tmp));

                // Check if this is the end
                if (is_last)
                {
                    self.complete(boost::system::error_code{}, opcode);
                }
                else
                {
                    state = header0_parse;
                    buf_tmp.resize(sizeof(websocket_frame));
                    boost::asio::async_read(sock, boost::asio::buffer(buf_tmp), std::move(self)); 
                }
            }
        }
    };

    template<class AsyncReadStream, class CompletionToken>
    inline auto async_ws_read (
        AsyncReadStream&    sock,
        std::vector<char>&  buf_tmp,
        std::vector<char>&  buf_pay,
        CompletionToken&&   token
    )
    {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, websocket_opcode)> (
            async_ws_read_impl{sock, buf_tmp, buf_pay},
            token, sock
        );
    }

//----------------------------------------------------------------------------------------------------------------

    template<class AsyncWriteStream, class CompletionToken, class Byte>
    inline auto async_ws_write (
        AsyncWriteStream&   sock,
        std::vector<char>&  buf_tmp,
        std::vector<Byte>&  buf_pay,
        websocket_opcode    opcode,
        bool                do_mask,
        CompletionToken&&   token
    )
    {
        static_assert(sizeof(Byte) == 1, "must be byte type");

        // Header
        websocket_frame hdr;
        size_t hdr_len = sizeof(websocket_frame);

        hdr.fin     = 1;
        hdr.masked  = do_mask;
        hdr.opcode  = opcode;

        if (buf_pay.size() < 126)
        {
            hdr.paylen = buf_pay.size();
        }     
        else if (buf_pay.size() <= 65535)
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
        buf_tmp.resize(hdr_len);
        size_t off{0};

        memcpy(&buf_tmp[off], &hdr, sizeof(websocket_frame));
        off += sizeof(websocket_frame);

        if (hdr.paylen == 126)
        {
            uint16_t len = htobe16((uint16_t)buf_pay.size());
            memcpy(&buf_tmp[off], &len, 2);
            off += 2;
        }

        else if (hdr.paylen == 127)
        {
            uint64_t len = htobe64((uint64_t)buf_pay.size());
            memcpy(&buf_tmp[off], &len, 8);
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

            // Mask
            for (size_t i = 0 ; i < buf_pay.size() ; ++i)
                buf_pay[i] ^= mask_key[i%4];
            
            // Write mask key
            memcpy(mask_key, &buf_tmp[off], 4);
            off += 4;
        }

        std::array buffers = {boost::asio::buffer(buf_tmp), boost::asio::buffer(buf_pay)};

        return boost::asio::async_write(sock, buffers, std::forward<CompletionToken>(token));
    }

//----------------------------------------------------------------------------------------------------------------

}