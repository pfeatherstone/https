#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    auto encoded = http::base64_encode(size, data);
    auto decoded = http::base64_decode(encoded);
    encoded.erase(std::remove(begin(encoded), end(encoded), '='), end(encoded));
    auto decoded2 = http::base64_decode(encoded);
    return 0;
}