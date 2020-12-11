#![feature(str_split_once)]
#![feature(slice_fill)]

// $LINUX/include/uapi/linux/fsverity.h
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
pub enum HashAlgorithm {
    Sha256 = FS_VERITY_HASH_ALG_SHA256,
    Sha512 = FS_VERITY_HASH_ALG_SHA512,
}

static ZEROES: [u8; 64] = [0; 64];

struct ZeroReader;

impl Read for ZeroReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
}

impl BufRead for ZeroReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> { Ok(&ZEROES) }
    fn consume(&mut self, _amt: usize) {}
}

struct FixedSizeBlock<D: Digest> {
    inner: D,
    remaining: usize,
}

impl<D: Digest> FixedSizeBlock<D> {
    fn new(inner: D, remaining: usize) -> Self { 
        Self { inner, remaining }
    }

    fn append(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.remaining = self.remaining.checked_sub(data.len()).unwrap();
    }

    fn overflowing_append<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        if self.remaining < data.len() {
            self.append(&data[..self.remaining]);
            &data[self.remaining..]
        } else {
            self.append(data);
            &[]
        }
    }

    fn finalize(mut self) -> GenericArray<u8, D::OutputSize> {
        self.fill_from(&mut ZeroReader).unwrap();
        self.inner.finalize()
    }

    fn fill_from<R: BufRead>(&mut self, reader: &mut R) -> std::io::Result<()> {

        loop {
            let buffer = reader.fill_buf()?;
            let n = buffer.len().min(self.remaining);
            if n == 0 { break; }
            self.append(&buffer[..n]);
            reader.consume(n);
        }

        Ok(())
    }

    fn finalize_from<R: BufRead>(mut self, reader: &mut R) -> std::io::Result<GenericArray<u8, D::OutputSize>> {
        self.fill_from(reader)?;
        Ok(self.finalize())
    }
}

// https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#userspace-utility
// https://git.kernel.org/pub/scm/linux/kernel/git/ebiggers/fsverity-utils.git/tree/lib/compute_digest.c

pub fn verity_hash<R: BufRead, D: Digest + Clone>(input: &mut R, salt: &[u8]) -> std::io::Result<GenericArray<u8, D::OutputSize>> {

    let block_size = 4096usize;

    assert!(D::output_size().is_power_of_two() && D::output_size() < block_size);
    assert!(block_size.is_power_of_two());

    let salted = D::new().chain(salt);

    let new_block = |d: &[u8]| {
        let mut tmp = FixedSizeBlock::new(salted.clone(), block_size);
        tmp.append(d);
        tmp
    };

    let mut last_digest: GenericArray<u8, D::OutputSize> = Default::default();

    let mut levels: Vec<FixedSizeBlock<D>> = vec![];

    let mut total_size = 0;

    let mut overflow : &[u8];

    loop {
        let buffer = input.fill_buf()?;
        if buffer.len() == 0 { break; }

        let amount = buffer.len().min(block_size);
        overflow = &buffer[..amount];

        let mut i = 0usize;
        loop {
            if i >= levels.len() {
                levels.push(new_block(overflow));
                break;
            }
            // this is not *strictly* correct since digests should always be appended atomically,
            // not split between blocks. however, this is always the case as long as the digest size
            // is a power of two, which is the case for sha256 and sha512 and I suspect will always be
            // the case. (note that the block size is already defined to be a power of two.)
            overflow = levels[i].overflowing_append(overflow);
            if overflow.len() == 0 {
                // for blocks above 0, we always leave room for 1 more digest.
                // this simplifies the logic for the flush loop at the end, as it ensures each block
                // will receive exactly 1 more hash during the flush instead of 1 or 2.
                if i == 0 || levels[i].remaining >= last_digest.len() {
                    break;
                }
            }
            last_digest = std::mem::replace(&mut levels[i], new_block(overflow)).finalize();
            overflow = &last_digest;
            i += 1;
        }

        total_size += amount;
        input.consume(amount);
    }

    // flush all levels
    let mut i = 0usize;
    overflow = &[];
    while i < levels.len() {
        levels[i].append(overflow);
        last_digest = std::mem::replace(&mut levels[i], new_block(&[])).finalize();
        overflow = &last_digest;
        i += 1;
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

    println!("last_digest: {} size: {}", hex::encode(&last_digest), total_size);

    let mut descriptor = FixedSizeBlock::new(salted.clone(), 256);
    descriptor.append(&[1]);
    descriptor.append(&[FS_VERITY_HASH_ALG_SHA256]);  // FIXME should be dynamic
    descriptor.append(&[block_size.trailing_zeros() as u8]);
    descriptor.append(&[salt.len() as u8]);  // FIXME check input
    descriptor.append(&[0; 4]);
    descriptor.append(&(total_size as u64).to_le_bytes());
    descriptor.append(&last_digest);  // FIXME should be dynamic

    // TODO digest always 32 bytes???
    //descriptor.append_if_fits(&salt).unwrap();  // FIXME should be dynamic
    last_digest = descriptor.finalize();

    Ok(last_digest)
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use crate::HashAlgorithm;

    #[test]
    fn test_testfiles() {

        let testfiles = "
        sha256:3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95 testfiles/empty
        sha256:3fd7a78101899a79cd337b1b4e5414be8bcb376b133370156ef6e65026d930ed testfiles/oneblock
        sha256:c0b9455d545b6b1ee5e7b227bd1ed463aaa530a4840dcd93465163a2b3aff0da testfiles/oneblockplusonebyte
        sha256:9845e616f7d2f7a1cd6742f0546a36d2e74d4eb8ae7d9bdc0b0df982c27861b7 testfiles/onebyte
        sha256:21ac11f1c7319e1561beb9328375f73c142f7c38c0130f9b799b5290afa051ef testfiles/morelevels
        ".trim().lines().map(|l| {
            let l = l.trim();
            let (digest, path) = l.split_once(" ").unwrap();
            let (digest_type, digest) = digest.split_once(":").unwrap();
            let digest_type = digest_type.parse::<super::HashAlgorithm>().unwrap();
            let digest = hex::decode(digest).unwrap();
            (digest_type, digest, path)
        }).collect::<Vec<_>>();

        println!("{:?}", &testfiles);

        for (digest_type, digest, path) in testfiles {
            assert!(digest_type == HashAlgorithm::Sha256);
            let mut f = BufReader::new(File::open(path).unwrap());
            let out = crate::verity_hash::<_, Sha256>(&mut f, &[]).unwrap();
            let tmp = hex::encode(&digest);
            let tmp2 = hex::encode(out);
            assert!(&out.as_ref() == &digest, "expected: {} found: {} for file: {}", tmp, tmp2, path);
        }

        assert_eq!(2 + 2, 4);
    }
}
