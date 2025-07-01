#include <cstring>
#include <string>
#include <vector>
#include <http.h>
#include "doctest.h"

TEST_SUITE("[BUFFER]")
{
    TEST_CASE("dynamic_buffer - string")
    {
        std::string buf;
        http::dynamic_buffer view(buf);

        buf = "hello there";
        CHECK(view.size() == buf.size());

        view.clear();
        CHECK(buf.empty());

        view.resize(4);
        CHECK(buf.size() == view.size());
        CHECK(buf.size() == 4);
        CHECK(view.data() == buf.data());
        auto asio_buffer = view.buffer();
        CHECK(asio_buffer.data() == view.data());
        CHECK(asio_buffer.data() == buf.data());
        CHECK(asio_buffer.size() == buf.size());

        const char* data = "Only a Sith deals in absolutes";
        std::strncpy((char*)view.data(), "Only", 4);
        view.append(data + 4, strlen(data) - 4);
        CHECK(view.size() == buf.size());
        CHECK(view.size() == strlen(data));
        CHECK(strcmp((const char*)view.data(), data) == 0);
    }
}