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

## Roadmap
- [ ] Chunked encoding
- [ ] Documentation

## Questions

- Q: Why not use Beast?

  A: I find Beast bloated and unecessarily complicated. HTTP1 and WS are simple protocols. There is SO MUCH source code in Beast and I'm not convinced it's proportionate. Additionally, you don't need Beast objects like `basic_stream` or `flat_buffer`. All you need are a few structs, enums, Asio composed operations and voila.

- Q: Why are you not writing the base library Sans-IO? It's the fashion!

  A: Because I'm only going to use this with Asio. I don't mind having state-machine logic inside an Asio composed operation rather than something custom. As far as I can tell, the only motivation for Sans-IO is unit tests. It means you don't have to open a socket.