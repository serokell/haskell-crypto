# NaCl (`haskell-NaCl`)

Easy-and-safe-to-use library for cryptography.

**Note: this package is experimental and WIP.**

Cryptography is hard to do right and you should never try to implement it
on your own, even if you have access to safe and secure cryptographic
primitives. Luckily, D. J. Bernstein created [NaCl].

NaCl was designed specifically to make it hard to use it incorrectly and
thus save your from a disaster. It exposes high-level cryptographic
algorithms with underlying implementations chosen for you, so you do not
get flexibility, but you get security, which is more important.

[Sodium] is a reimplementation of NaCl with the goal to make it more
portable across different platforms. With time, it started providing
not only the same interface as NaCl, the developers of Sodium decided
to add new primitives too.

Sodium is more portable, but some people are afraid of using it,
and prefer to stick to NaCl. We agree that it is better to be
paranoid than sorry. That is why, even though this library uses
Sodium under the hood, it only exposes the primitives that
are part of the “classic” NaCl interface.

[NaCl]: https://nacl.cr.yp.to/
[Sodium]: https://libsodium.org


## Why not?


## Use


## Contributing

If you encounter any issues when using this library or have improvement ideas,
please open report in issue on GitHub. You are also very welcome to submit
pull request, if you feel like doing so.


## License

[MPL-2.0] © [Serokell]

[MPL-2.0]: https://spdx.org/licenses/MPL-2.0.html
[Serokell]: https://serokell.io/
