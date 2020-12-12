#![feature(str_split_once)]
#![feature(slice_fill)]

// $LINUX/include/uapi/linux/fsverity.h
use sha2::Sha512;
use core::fmt::Display;
use std::{os::unix::prelude::AsRawFd, str::FromStr};
use std::{io::{BufRead, ErrorKind}, slice};
use std::cmp::min;
use std::io::Write;
use std::io::Read;
use sha2::{Digest, digest::generic_array::GenericArray, Sha256};

const FS_VERITY_HASH_ALG_SHA256: u8 = 1;
const FS_VERITY_HASH_ALG_SHA512: u8 = 2;
const FS_IOC_ENABLE_VERITY: u64 = 1082156677;
const FS_IOC_MEASURE_VERITY: u64 = 3221513862;

#[repr(C)]
pub struct fsverity_enable_arg {
    pub version: u32,
    pub hash_algorithm: u32,
    pub block_size: u32,
    pub salt_size: u32,
    pub salt_ptr: u64,
    pub sig_size: u32,
    pub __reserved1: u32,
    pub sig_ptr: u64,
    pub __reserved2: [u64; 11usize],
}

const MAX_DIGEST_SIZE: u16 = 32;
const MAX_BLOCK_SIZE: usize = 4096;

#[repr(C)]
struct fsverity_digest {
    digest_algorithm: u16,
    digest_size: u16,
    digest: [u8; MAX_DIGEST_SIZE as usize],
}


fn f_enable_verity(fd: impl AsRawFd) -> std::io::Result<()> {
    let fd = fd.as_raw_fd();

    let args = fsverity_enable_arg {
        version: 1,
        hash_algorithm: FS_VERITY_HASH_ALG_SHA256 as u32,
        block_size: 4096,
        salt_size: 0,
        salt_ptr: 0,
        sig_size: 0,
        __reserved1: Default::default(),
        sig_ptr: 0,
        __reserved2: Default::default(),
    };

    let ret = unsafe { libc::ioctl(fd, FS_IOC_ENABLE_VERITY, &args as *const _) };

    if ret != 0 {
        Err(std::io::Error::from_raw_os_error(ret))
    }
    else {
        Ok(())
    }
}

fn f_measure_verity(fd: impl AsRawFd) -> std::io::Result<fsverity_digest> {
    let fd = fd.as_raw_fd();

    let mut digest = fsverity_digest {
        digest_algorithm: 0,  // unset
        digest_size: MAX_DIGEST_SIZE,
        digest: Default::default(),
    };

    let ret = unsafe { libc::ioctl(fd, FS_IOC_MEASURE_VERITY, &mut digest as *mut _) };

    if ret != 0 {
        Err(std::io::Error::from_raw_os_error(ret))
    }
    else {
        Ok(digest)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, parse_display::FromStr, parse_display::Display, Debug)]
#[display(style = "lowercase")]
#[repr(u8)]
pub enum VerityHashAlgorithm {
    Sha256 = FS_VERITY_HASH_ALG_SHA256,
    Sha512 = FS_VERITY_HASH_ALG_SHA512,
}

/// Extends a Digest with some extra information we need, as well as two useful utility methods.
pub trait VerityHashExt : Digest {
    fn verity_hash_algorithm(&self) -> VerityHashAlgorithm;
    fn verity_input_blocksize(&self) -> usize;

    fn update_padded(&mut self, data: &[u8], padded_size: usize) {
        self.update(data);
        self.update_zeroes(padded_size.checked_sub(data.len()).unwrap());
    }

    fn update_zeroes(&mut self, mut amount: usize) {
        let zeroes = [0u8; 64];
        while amount != 0 {
            let n = zeroes.len().min(amount);
            self.update(&zeroes[..n]);
            amount -= n;
        }
    }
}

impl VerityHashExt for Sha256 {
    fn verity_hash_algorithm(&self) -> VerityHashAlgorithm {
        VerityHashAlgorithm::Sha256
    }

    fn verity_input_blocksize(&self) -> usize {
        64
    }
}

impl VerityHashExt for Sha512 {
    fn verity_hash_algorithm(&self) -> VerityHashAlgorithm {
        VerityHashAlgorithm::Sha512
    }

    fn verity_input_blocksize(&self) -> usize {
        128
    }
}

/// Logically a fixed-size block of data to be hashed (padded with zeroes if needed.)
/// Actually remembers only the hash state and how many more bytes are needed.
struct FixedSizeBlock<D: Digest + VerityHashExt> {
    inner: D,
    remaining: usize,
}

impl<D: Digest + VerityHashExt> FixedSizeBlock<D> {
    fn new(inner: D, remaining: usize) -> Self { 
        Self { inner, remaining }
    }

    fn append(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.remaining = self.remaining.checked_sub(data.len()).unwrap();
    }

    fn overflowing_append<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let (a, b) = data.split_at(data.len().min(self.remaining));
        self.append(a);
        b
    }

    fn finalize(mut self) -> GenericArray<u8, D::OutputSize> {
        self.inner.update_zeroes(self.remaining);
        self.inner.finalize()
    }
}

// https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#userspace-utility
// https://git.kernel.org/pub/scm/linux/kernel/git/ebiggers/fsverity-utils.git/tree/lib/compute_digest.c

pub fn verity_hash<R: BufRead, D: Digest + Clone + VerityHashExt>(input: &mut R, salt: &[u8]) -> std::io::Result<GenericArray<u8, D::OutputSize>> {

    let block_size = 4096usize;  // TODO allow user to pick?
    assert!(D::output_size() * 2 <= block_size);
    assert!(block_size.is_power_of_two());

    assert!(salt.len() <= 32);  // TODO error instead of panic?

    // create an immutable hash state initialized with the salt, for use as an initializer.
    let salted = {
        let mut tmp = D::new();
        // salt should be padded up to the "nearest multiple" of the input block size.
        // but since max salt size is 32, the "multiple" is in practice always 0 or 1.
        // this ensures that continues to hold in the future.
        assert!(salt.len() <= tmp.verity_input_blocksize());
        if salt.len() != 0 {
            tmp.update_padded(salt, tmp.verity_input_blocksize());
        }
        tmp
    };

    // function to create a new FixedSizeBlock with a new pre-salted hash state,
    // which is then immediately filled with some initial data.
    let new_block = |d: &[u8]| {
        let mut tmp = FixedSizeBlock::new(salted.clone(), block_size);
        tmp.append(d);
        tmp
    };

    // zero length files have a root "hash" of all zeroes. this initializer ensures that.
    let mut last_digest: GenericArray<u8, D::OutputSize> = Default::default();

    let mut levels: Vec<FixedSizeBlock<D>> = vec![];
    let mut total_size = 0;

    loop {
        let buffer = input.fill_buf()?;
        if buffer.len() == 0 { break; }

        let amount = buffer.len().min(block_size);
        let mut overflow = &buffer[..amount];

        let mut keep_space_for_one_digest = false;
        for level in levels.iter_mut() {

            overflow = level.overflowing_append(overflow);
            if overflow.len() == 0 {
                // for digest blocks, we always leave room for 1 more digest.
                // this simplifies the logic for the flush loop at the end, as it ensures each block
                // will receive exactly 1 more hash during the flush instead of 1 or 2.
                // (this also ensures the "overflowing_append" above does not actually ever split a hash
                // across two blocks, which is not supposed to happen according to docs. but that can
                // never happen anyway unless the hash function output size is not a power of two,
                // which it is for sha256 and sha512 and probably all future hash functions.)
                if !keep_space_for_one_digest || level.remaining >= last_digest.len() {
                    break;
                }
            }
            last_digest = std::mem::replace( level, new_block(overflow)).finalize();
            overflow = &last_digest;
            keep_space_for_one_digest = true;  // all but the first one
        }

        if overflow.len() != 0 {
            levels.push(new_block(overflow));
        }

        total_size += amount;
        input.consume(amount);
    }

    // flush all levels
    let mut overflow: &[u8] = &[];
    for mut level in levels.into_iter() {
        level.append(overflow);
        last_digest = level.finalize();
        overflow = &last_digest;
    }

    // https://www.kernel.org/doc/html/latest/filesystems/fsverity.html
    // $LINUX/fs/verity/fsverity_private.h
    // #[repr(C)]
    // struct fsverity_descriptor {
    //     version: u8,           /* must be 1 */
    //     hash_algorithm: u8,    /* Merkle tree hash algorithm */
    //     log_blocksize: u8,     /* log2 of size of data and tree blocks */
    //     salt_size: u8,         /* size of salt in bytes; 0 if none */
    //     sig_size: u32,         /* must be 0 */
    //     data_size: u64,        /* little-endian size of file the Merkle tree is built over */
    //     root_hash: [u8; 64],   /* Merkle tree root hash */
    //     salt: [u8; 32],        /* salt prepended to each hashed block */
    //     reserved: [u8; 144],   /* must be 0's */
    // }

    // println!("last_digest: {} size: {}", hex::encode(&last_digest), total_size);

    let mut descriptor = salted.clone();
    descriptor.update(&[1]);
    descriptor.update(&[salted.verity_hash_algorithm() as u8]);
    descriptor.update(&[block_size.trailing_zeros() as u8]);
    descriptor.update(&[salt.len() as u8]);
    descriptor.update(&0u32.to_le_bytes());
    descriptor.update(&(total_size as u64).to_le_bytes());
    descriptor.update_padded(&last_digest, 64);
    descriptor.update_padded(salt, 32);
    descriptor.update_zeroes(144);

    Ok(descriptor.finalize())
}

#[cfg(test)]
mod tests {
use sha2::Sha256;
use std::io::BufReader;
use std::fs::File;
use crate::VerityHashAlgorithm;

    #[test]
    fn test_testfiles() {

        // 'longfile' takes a while in debug mode, about 20 seconds for me.
        // in release mode it takes about a second.
        // sha256:e228078ebe9c4f7fe0c5d6a76fb2e317f5ea8bdfb227d7741e5c57cff739b5fa testfiles/longfile
        let testfiles = "
        sha256:3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95 testfiles/empty
        sha256:f5c2b9ded1595acfe8a996795264d488dd6140531f6a01f8f8086a83fd835935 testfiles/hashblock_0_0
        sha256:5c00a54bd1d8341d7bbad060ff1b8e88ed2646d7bb38db6e752cd1cff66c0a78 testfiles/hashblock_0_-1
        sha256:a7abb76568871169a79104d00679fae6521dfdb2a2648e380c02b10e96e217ff testfiles/hashblock_0_1
        sha256:c4b519068d8c8c68fd5e362fc3526c5b11e15f8eb72d4678017906f9e7f2d137 testfiles/hashblock_-1_0
        sha256:09510d2dbb55fa16f2768165c42d19c4da43301dfaa05705b2ecb4aaa4a5686a testfiles/hashblock_1_0
        sha256:7aa0bb537c623562f898386ac88acd319267e4ab3200f3fd1cf648cfdb4a0379 testfiles/hashblock_-1_-1
        sha256:f804e9777f91d3697ca015303c23251ad3d80205184cfa3d1066ab28cb906330 testfiles/hashblock_-1_1
        sha256:26159b4fc68c63881c25c33b23f2583ffaa64fee411af33c3b03238eea56755c testfiles/hashblock_1_-1
        sha256:57bed0934bf3ab4610d54938f03cff27bd0d9d76c9a77e283f9fb2b7e29c5ab8 testfiles/hashblock_1_1
        sha256:3fd7a78101899a79cd337b1b4e5414be8bcb376b133370156ef6e65026d930ed testfiles/oneblock
        sha256:c0b9455d545b6b1ee5e7b227bd1ed463aaa530a4840dcd93465163a2b3aff0da testfiles/oneblockplusonebyte
        sha256:9845e616f7d2f7a1cd6742f0546a36d2e74d4eb8ae7d9bdc0b0df982c27861b7 testfiles/onebyte
        ".trim().lines().map(|l| {
            let l = l.trim();
            let (digest, path) = l.split_once(" ").unwrap();
            let (digest_type, digest) = digest.split_once(":").unwrap();
            let digest_type = digest_type.parse::<super::VerityHashAlgorithm>().unwrap();
            let digest = hex::decode(digest).unwrap();
            (digest_type, digest, path)
        }).collect::<Vec<_>>();

        for (digest_type, digest, path) in testfiles {
            assert!(digest_type == VerityHashAlgorithm::Sha256);
            let mut f = BufReader::new(File::open(path).unwrap());
            let out = crate::verity_hash::<_, Sha256>(&mut f, &[]).unwrap();
            let tmp = hex::encode(&digest);
            let tmp2 = hex::encode(out);
            assert!(&out.as_ref() == &digest, "expected: {} found: {} for file: {}", tmp, tmp2, path);
        }

        assert_eq!(2 + 2, 4);
    }
}
