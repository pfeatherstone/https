#include <random>
#include <http.h>
#include "doctest.h"

const auto random_string = [](auto& eng, size_t len)
{
    std::uniform_int_distribution<int> d(48, 126);
    std::string str(len, '\0');
    for (auto& c : str) c = static_cast<char>(d(eng));
    return str;
};

TEST_SUITE("[HEADERS]")
{
    TEST_CASE("headers")
    {
        std::mt19937 eng(std::random_device{}());
        http::headers_container headers;

        // Check empty
        REQUIRE(headers.size() == 0);
        for (unsigned int f = http::unknown_field ; f <= http::xref ; ++f)
            REQUIRE(!headers.find(static_cast<http::field>(f)));

        // Add headers
        std::vector<std::string> strs;
        std::vector<http::field> fields;

        bool use_modify{false};

        SUBCASE("using add_header()")
        {
            use_modify = false;
        }

        // Modifying a header that isn't present should just add it
        SUBCASE("using modify()")
        {
            use_modify = true;
        }

        for (unsigned int f = http::unknown_field+1 ; f <= http::xref ; ++f)
        {
            const size_t      len = std::uniform_int_distribution<size_t>{0, 128}(eng);
            const std::string str = random_string(eng, len);
            strs.push_back(str);
            fields.push_back(static_cast<http::field>(f));
            if (use_modify)
                headers.modify(static_cast<http::field>(f), str);
            else
                headers.add(static_cast<http::field>(f), str);
            REQUIRE(headers.size() == strs.size());

            for (size_t i = 0 ; i < headers.size() ; ++i)
            {
                const auto [f2, str2] = headers[i];
                REQUIRE(f2   == fields[i]);
                REQUIRE(str2 == strs[i]);
            }
        }

        // Randomly modify
        for (size_t i = 0 ; i < headers.size() ; ++i)
        {
            const size_t      idx = std::uniform_int_distribution<size_t>{0, headers.size()-1}(eng);
            const size_t      len = std::uniform_int_distribution<size_t>{0, 128}(eng);
            const std::string str = random_string(eng, len);
            strs[idx] = str;
            headers.modify(fields[idx], str);

            REQUIRE(headers.size() == strs.size());
            for (size_t j = 0 ; j < headers.size() ; ++j)
            {
                const auto [f2, str2] = headers[j];
                REQUIRE(f2   == fields[j]);
                REQUIRE(str2 == strs[j]);
            }
        }

        // Randomly remove fields
        while (headers.size() > 0)
        {
            {
                const size_t i      = std::uniform_int_distribution<size_t>{0, fields.size()-1}(eng);
                const auto   f      = fields[i];
                const auto   str    = std::move(strs[i]);
                fields.erase(begin(fields)+i);
                strs.erase(begin(strs)+i);
                headers.remove(f);
            }

            REQUIRE(headers.size() == strs.size());
            for (size_t j = 0 ; j < headers.size() ; ++j)
            {
                const auto [f2, str2] = headers[j];
                REQUIRE(f2   == fields[j]);
                REQUIRE(str2 == strs[j]);
            }
        }
    }
}