# `fs-verity`

This crate implements utilities for working with `fs-verity` functionality of the Linux kernel.

## What is `fs-verity`?

It allows you to make a file permanently immutable and have the kernel calculate and store
a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree)-based hash for the file that will be
instantly retrievable from the file from that point on.

The kernel will also verify all data read from the file agains the Merkle tree data, and
refure to read it if there is a mismatch. This means (as long as you trust the running kernel)
you can be absolutely sure that this instantly retrievable hash will match the data you read
from the file.

You are expected to determine whether the hash is the expected one through other means,
such as checking whether it is in a list of accepted hashes which has been signed by some key.

The kernel's `fs-verity` code does implement a basic (and optional) in-kernel signature
verification scheme. However, because you still have to manually check whether an opened file
has `fs-verity` enabled, it does not add much value and is probably more of a proof-of-concept.
This crate currently has no support for this scheme.

Currently `fs-verity` is only supported on `f2fs` and `ext4` filesystems, and you may need to
turn on the `fs-verity` option on your filesystem. See the
[Linux documentation](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#filesystem-support) for details.

## What is this crate?

You can think of it as a pure Rust replacement for the main parts of
[`fsverity-utils` / `libfsverity`](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#userspace-utility).

It consists of two parts:

* An implementation of [`sha2::digest::Digest`] which can calculate an `fs-verity` measurement
  in userland Rust code. This is useful for e.g. servers and build systems which may not want
  to (or be able to) enable `fs-verity` for files, but still need to know the digest values
  so they can be used to create e.g. a signed manifest file containing all the digests.
* On Linux systems, two functions which allow you to enable `fs-verity` for a file, and to
  fetch the digest for the file from the kernel once it's enabled. This uses the `ioctl`
  interface directly.

This was mostly produced as a coding exercise. It works and is pretty clean (well, as much
as is possible under the API constraints I set myself) and thoroughly commented, but it is
currently a bit slower than the C implementation because that uses `libcrypto`'s assembly
code for SHA256, and the SHA256 implementation in RustCrypto is not quite as fast.

One neat aspect of this implementation is that it works in a completely streaming manner,
accepting any amount of input in chunks of whatever size.

## Rust version

This crate currently requires nightly just because I used `#\[feature(str_split_once)\]` in the tests.

If you don't like nightly either help out to [stabilize that feature](https://github.com/rust-lang/rust/issues/74773) or send me a PR to remove the use of it.

## Safety

This crate calls the unsafe `libc::ioctl` function in the two function in the [`linux`] module. No other `unsafe` is used.

The underlying SHA256 and SHA512 hash functions from Rust Crypto are used. The `asm` feature of Rust Crypto is not enabled by default.

## Development notes

To run unit tests, first generate the test files using `python3 make_testfiles.py`.

The "known good" hashes were generated using the official `fsverity` tool fromm `fsverity-utils`:

```bash
sudo apt install fsverity-utils
for f in testfiles/*; do fsverity enable $f; done
fsverity measure testfiles/*
```

If that doesn't work your filesystem may not support `fs-verity` or you may need to turn on the feature in the fs superblock, see the [excellent `fs-verity` documentation](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#filesystem-support) for details.

Very recent versions (you may have to compile from [source](https://git.kernel.org/pub/scm/linux/kernel/git/ebiggers/fsverity-utils.git/)) of the `fsverity` tool also support the `digest` subcommmand, which allows you to hash the files without kernel or filesystem support:

```bash
fsverity digest testfiles/*
```

Converting this to pure Rust would be nice.

## License

This crate is licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.