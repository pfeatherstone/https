![Ubuntu](https://github.com/pfeatherstone/https/actions/workflows/ubuntu.yml/badge.svg)
![MacOS](https://github.com/pfeatherstone/https/actions/workflows/macos.yml/badge.svg)
![Windows](https://github.com/pfeatherstone/https/actions/workflows/windows.yml/badge.svg)
[![codecov](https://codecov.io/gh/pfeatherstone/https/branch/main/graph/badge.svg)](https://codecov.io/gh/pfeatherstone/https)

# https

Provides HTTP(s) and WS(s) primitives as Asio [composed operations](https://think-async.com/Asio/asio-1.30.2/doc/asio/overview/composition/compose.html).
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

Note, the example server is single threaded, uses C++20 coroutines and basic authentication. The tests were undertaken on an Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz 12 core processor. I'm using gcc 13.1.0 and openssl 3.0.2.

| Transport | Connections | Requests / s |
| --------- | ----------- | -------------|
| TCP       | 1           | 49299.87     |
| TCP       | 2           | 86850.14     |
| TCP       | 5           | 102857.48    |
| TCP       | 10          | 111504.62    |
| TLS       | 1           | 33671.01     |
| TLS       | 2           | 62024.36     |
| TLS       | 5           | 70269.52     |
| TLS       | 10          | 78444.07     |

Not bad.

## Roadmap
- [ ] Chunked encoding
- [ ] Documentation

## Questions

- Q: Why not use Beast?

  A: I find Beast bloated and unecessarily complicated. HTTP1 and WS are simple protocols. There is SO MUCH source code in Beast and I'm not convinced it's proportionate.

- Q: Why are you not writing the base library Sans-IO?

  A: Because I'm only going to use this with Asio. I don't mind having state-machine logic inside an Asio composed operation rather than something custom. As far as I can tell, the only motivation for Sans-IO is unit tests.