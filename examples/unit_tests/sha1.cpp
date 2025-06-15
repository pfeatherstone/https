#include <random>
#include <algorithm>
#include <openssl/evp.h>
#include <http.h>
#include "doctest.h"

TEST_SUITE("[SHA1]")
{
    TEST_CASE("matches openssl")
    {
        std::mt19937 eng(std::random_device{}());
        std::uniform_int_distribution<unsigned int> d{0, 255};
        std::vector<uint8_t> buf;
        buf.reserve(4096);

        for (size_t i = 0 ; i < 3000 ; ++i)
        {
            // Fill with random
            buf.resize(i);
            std::generate(begin(buf), end(buf), [&]{return static_cast<uint8_t>(d(eng));});

            // Encode using libssl
            uint8_t         hash[EVP_MAX_MD_SIZE];
            unsigned int    hash_len{0};
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_DigestUpdate(mdctx, buf.data(), buf.size());
            EVP_DigestUpdate(mdctx, buf.data(), buf.size());
            EVP_DigestUpdate(mdctx, buf.data(), buf.size());
            EVP_DigestFinal_ex(mdctx, hash, &hash_len);
            EVP_MD_CTX_free(mdctx);

            // Encode using custom function
            auto hash2 = http::sha1{}.push(buf.size(), buf.data())
                                     .push(buf.size(), buf.data())
                                     .push(buf.size(), buf.data())
                                     .finish();
            
            // Check
            REQUIRE(hash_len == hash2.size());
            for (size_t j = 0 ; j < hash2.size() ; ++j)
                REQUIRE(hash[j] == hash2[j]);
        }
    }
}