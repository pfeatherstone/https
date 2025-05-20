# https
HTTPS and WSS library.
This is an experimental replacement for Boost::Beast.

## Installation

Copy the contents of `src` into your project then link to:
- Boost::asio
- OpenSSL::SSL
- OpenSSL::Crypto 

## Examples

Try out:
- `test/example.cpp`

Build using:

```bash
$ cmake ./test -B build -DCMAKE_BUILD_TYPE=Release
$ cmake --build build --parallel
```

Try using:

```bash
$ ./build/example [--use_tls]
```

Open a browser at http(s)://localhost:8000. 
Note, the example showcases basic authentication. The user is "Tommy" and the password is "Aldridge". 


## Roadmap

- [ ] Documentation
- [ ] HTTP(s) and WS(s) clients
- [ ] Unit tests

## Questions

- Q: Why not use Beast?

  A: I find Beast very bloated and unecessarily complicated. HTTP1 and WS are very simple protocols. You don't need a lot of Beast's objects like `basic_stream` or `flat_buffer`. All you need are a few structs, a few Asio composed operations and voila.

- Q: Why do I need to link to openssl when I'm not using TLS?

  A: Because of SHA1 and Base64 encoding/decoding. You need those for websockets, even without TLS, and I can't be bothered to implement those functions.

- Q: Why are you not writing the base library Sans-IO? It's the fashion!

  A: Because I'm only going to use this with Asio. I don't mind having state-machine logic inside an Asio composed operation rather than something custom. As far as I can tell, the only motivation for Sans-IO is unit tests. It means you don't have to open a socket.


