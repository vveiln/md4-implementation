# Pure Python MD4 Message Digest Algorithm Implementation
This repository contains a pure python3 implementation of [MD4 Message Digest Algorithm](https://tools.ietf.org/html/rfc1320). Use it if you need to look at the code, otherwise try [some other good ready-made solutions](https://kite.com/python/docs/Crypto.Hash.MD4)

## Usage

``` python

from md4 import MD4

md4 = MD4()
md4.update('message you want to hash')
md4.hexdigest()

```
## Tests

I have provided some tests to check if the code works properly. To run use `pytest-3`

```
pytest-3 test.py
```
