# https
HTTPS and WSS library.
This is an experimental replacement for Boost::Beast.

## Installation

Copy the contents of `src` into your project then link to:
- Boost::asio
- OpenSSL::SSL
- OpenSSL::Crypto 

## Examples

Check out:
- `test/example.cpp`
- `test/example_ssl.cpp`

Build them using:

```bash
$ cmake . -B build -DCMAKE_BUILD_TYPE=Release
$ cmake --build build --parallel
```

Try em' using:

```bash
$ ./build/example
```

or:

```bash
$ ./build/example_ssl
```

Open a browser at http(s)://localhost:8000. 
Note, the examples showcase basic authentication. The user is "Tommy" and the password is "Aldridge". 

## API

TODO

## Roadmap

- [ ] HTTP(s) and WS(s) clients
- [ ] Unit tests

## Rarely asked question

- Q: Why are you not writing the base library Sans-IO? It's the fashion!

  A: Because i'm only going to use this with Asio. I don't mind having state-machine logic inside an Asio composed operation rather than something custom. I believe the only reason people are doing this Sans-IO stuff is for unit tests. They don't actually have to open a socket. But really people are only going to use those libs with Asio.



