#include <cstdint>
#include <cstddef>
#include <http.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    auto encoded = http::base64_encode(size, data);
    auto decoded = http::base64_decode(encoded);
    return 0;
}