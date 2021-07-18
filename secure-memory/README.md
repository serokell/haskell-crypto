# secure-memory

Securely allocated and deallocated memory.

When handling sensitive data in your program, you want to be extra
careful and make sure that it is gone as soon as you are done working
with it. In a garbage-collected language like Haskell this is not so easy,
since the garbage collector can move your bytes around and create copies
of it. In addition to that, even if the memory gets eventually deallocated,
it is not guaranteed that the data will actually be zeroed-out or overriden.

To make matters even worse, if the operating system runs out of RAM while
your sensitive data remains in the memory, the page that contains your data
can get swapped out and, thus, end up on the disk, which you, of course,
absolutely want to never happen.

This library provides a (relatively) easy to use interface for working
with data allocated in a secure memory location that is guaranteed to never
end up on the disk and that will be zeroed-out as soon as you finish using it.

## Use

### Get it

Add [`secure-memory`][hackage:secure-memory] to the dependencies of your package.

The current implementation requires `libsodium`, which is a bit unfortunate and,
hopefully, this dependency will be removed in a future version.

### Data types

Use the `SensitiveBytes` data type provided by this package.

The primary interface for interacting with values of this type is the instance of the
`ByteArrayAccess` class from the [`memory`][hackage:memory] package.
Keep in mind that this instance allow you (or a function that you are passing
the values to) to freely read the sensitive bytes, so it is your responsibility to
make sure that these bytes do not get copied elsewhere.
Remember: this library only makes sure that `SensitiveBytes` are allocated in a secure
memory location and that the garbage collector will not touch them; but there
is nothing to prevent you from copying them to an insecure location.

[hackage:memory]: https://hackage.haskell.org/package/memory

See the module documentation for the exact guarantees that are provided
and note that the kinds of protections available differ by the operating
system.

### Documentation

All documentation exists is in the form of Haddock comments, you can
find them in the source code or [browse on Hackage][hackage:secure-memory].


[hackage:secure-memory]: https://hackage.haskell.org/package/secure-memory
