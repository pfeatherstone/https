#include <random>
#include <algorithm>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <http.h>
#include "doctest.h"

static std::string openssl_base64_encode(const size_t ndata, const uint8_t* data)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data, ndata);
    BIO_flush(bio);

    BUF_MEM* buffer_ptr{nullptr};
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string encoded(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return encoded;
}

static std::vector<uint8_t> openssl_base64_decode(std::string_view data)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(data.data(), data.size());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<uint8_t> output(data.size(), 0); // Base64 expands by 4/3, so input is always >= output
    int decoded_len = BIO_read(bio, output.data(), output.size());
    if (decoded_len < 0)
        fprintf(stderr, "Failed to base64 decode data\n");

    output.resize(std::max(decoded_len, 0));
    BIO_free_all(bio);
    return output;
}

TEST_SUITE("[BASE64]")
{
    TEST_CASE("matches openssl")
    {
        std::mt19937 eng(std::random_device{}());
        std::uniform_int_distribution<uint8_t> d{};
        std::vector<uint8_t> buf;
        buf.reserve(4096);

        for (size_t i = 0 ; i < 10000 ; ++i)
        {
            // Fill with random
            buf.resize(i);
            std::generate(begin(buf), end(buf), [&]{return d(eng);});

            // Encode
            auto encoded_ssl    = openssl_base64_encode(buf.size(), buf.data());
            auto encoded_custom = http::base64_encode(buf.size(), buf.data());
            
            // Check
            REQUIRE(encoded_ssl == encoded_custom);

            // Decode with padding
            auto decoded = http::base64_decode(encoded_custom);
            REQUIRE(buf.size() == decoded.size());
            REQUIRE(std::equal(begin(buf), end(buf), begin(decoded)));

            // Decode without padding
            encoded_custom.erase(std::remove(begin(encoded_custom), end(encoded_custom), '='), end(encoded_custom));
            decoded = http::base64_decode(encoded_custom);
            REQUIRE(buf.size() == decoded.size());
            REQUIRE(std::equal(begin(buf), end(buf), begin(decoded)));
        }
    }
}