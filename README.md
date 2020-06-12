# High-level cryptography for Haskell (`haskell-crypto`)

Easy-and-safe-to-use high-level cryptographic primitives.

**Note: this package is experimental and WIP.**

Cryptography is hard to do right, even if you have access to low-level
cryptographic primitives – you still need to pick the right ones and
then combine them in a safe way.

Luckily, there already exists a high-level library that does this for
you: [Sodium] (based on [Nacl]). This repository contains two Haskell
packages:

* [crypto-sodium](./crypto-sodium) – high-level cryptography based on Sodium,
  spiced up with extra type-safety of the Haskell type system.
* [NaCl](./NaCl) – similar high-level bindings, but only providing the subset
  of Sodium functions that was present in the original NaCl library.

[NaCl]: https://nacl.cr.yp.to/
[Sodium]: https://libsodium.org


## Why not?


## Use

See Haddock documentation at <https://hackage.haskell.org/package/crypto-sodium>.

## Contributing

If you encounter any issues when using this library or have improvement ideas,
please open report in issue on GitHub. You are also very welcome to submit
pull request, if you feel like doing so.


## License

[MPL-2.0] © [Serokell]

[MPL-2.0]: https://spdx.org/licenses/MPL-2.0.html
[Serokell]: https://serokell.io/
