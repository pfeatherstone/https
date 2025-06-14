![Ubuntu 22 GCC](https://github.com/pfeatherstone/https/actions/workflows/ubuntu22_gcc.yml/badge.svg)
![Ubuntu 22 Clang](https://github.com/pfeatherstone/https/actions/workflows/ubuntu22_clang.yml/badge.svg)
![Ubuntu 24 GCC](https://github.com/pfeatherstone/https/actions/workflows/ubuntu24_gcc.yml/badge.svg)
![Ubuntu 24 Clang](https://github.com/pfeatherstone/https/actions/workflows/ubuntu24_clang.yml/badge.svg)
![macOS Clang](https://github.com/pfeatherstone/https/actions/workflows/macos_clang.yml/badge.svg)
![Windows MSVC](https://github.com/pfeatherstone/https/actions/workflows/windows_msvc.yml/badge.svg)

# https
HTTPS and WSS library.
This is an experimental replacement for Boost::Beast.

## Installation

Copy the contents of `src` into your project then link to Boost::asio. If you're using transport over TLS, then link to OpenSSL::SSL and OpenSSL::Crypto.

## Examples

Try out:
- [server.cpp](examples/server.cpp)
- [client_http.cpp](examples/client_http.cpp)
- [client_ws_awaitable.cpp](examples/client_ws_awaitable.cpp)
- [client_ws_coro.cpp](examples/client_ws_coro.cpp)

Build using:

```bash
$ cmake ./examples -B build -DCMAKE_BUILD_TYPE=Release
$ cmake --build build --parallel
```

## Unit tests

Build as above. Run using:

```bash
$ ./build/tests
```

## Benchmarks

I benchmarked the example [server](examples/server.cpp) using [ab](https://httpd.apache.org/docs/2.4/programs/ab.html). 

I used the following commands for HTTP and HTTPS respectively:

```bash
$ ab -A Tommy:Aldridge -n 500000 -c <C> -k http://localhost:8000/ok
$ ab -A Tommy:Aldridge -n 500000 -c <C> -k https://localhost:8000/ok
```

Note, the example server is single threaded, uses C++20 coroutines and basic authentication (not particularly well optimized). I modified the program to use TLS 1.2 as `ab` doesn't support TLS 1.3. I have an Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz 12 core processor. I'm using gcc 13.1.0 and openssl 3.0.2. Here are the results:

| Transport | Connections | Requests / s |
| --------- | ----------- | -------------|
| TCP       | 1           | 46343.67     |
| TCP       | 2           | 84973.53     |
| TCP       | 5           | 101081.90    |
| TCP       | 10          | 108060.56    |
| TLS       | 1           | 32172.07     |
| TLS       | 2           | 58033.97     |
| TLS       | 5           | 67345.94     |
| TLS       | 10          | 69167.37     |

Not bad.

## Roadmap
- [ ] Chunked encoding
- [ ] Documentation

## Questions

- Q: Why not use Beast?

  A: I find Beast bloated and unecessarily complicated. HTTP1 and WS are simple protocols. There is SO MUCH source code in Beast and I'm not convinced it's proportionate. Additionally, you don't need Beast objects like `basic_stream` or `flat_buffer`. All you need are a few structs, enums, Asio composed operations and voila.

- Q: Why are you not writing the base library Sans-IO? It's the fashion!

  A: Because I'm only going to use this with Asio. I don't mind having state-machine logic inside an Asio composed operation rather than something custom. As far as I can tell, the only motivation for Sans-IO is unit tests. It means you don't have to open a socket.