#[allow(non_camel_case_types)]

use std::convert::TryFrom;
use std::os::unix::prelude::AsRawFd;
use super::config;

// FIXME these are calculated through complex macros that bindgen doesn't like.
//       it's also possible they are not the same on all architectures.
//       should really check this!!!
const FS_IOC_ENABLE_VERITY: u64 = 1082156677;
const FS_IOC_MEASURE_VERITY: u64 = 3221513862;

// https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#fs-ioc-enable-verity
pub fn fsverity_enable(fd: impl AsRawFd, block_size: usize, hash: config::InnerHashAlgorithm, salt: &[u8]) -> std::io::Result<()> {
    let fd = fd.as_raw_fd();
    #[repr(C)]
    pub struct fsverity_enable_arg {
        pub version: u32,
        pub hash_algorithm: u32,
        pub block_size: u32,
        pub salt_size: u32,
        pub salt_ptr: *const [u8],
        pub sig_size: u32,
        pub __reserved1: u32,
        pub sig_ptr: u64,
        pub __reserved2: [u64; 11],
    }

    let args = fsverity_enable_arg {
        version: 1,
        hash_algorithm: hash as u32,
        block_size: block_size as u32,
        salt_size: salt.len() as u32,
        salt_ptr: salt as *const _,
        sig_size: 0,
        __reserved1: 0,
        sig_ptr: 0,
        __reserved2: [0; 11],
    };

    let ret = unsafe { libc::ioctl(fd, FS_IOC_ENABLE_VERITY, &args as *const _) };

    if ret != 0 {
        Err(std::io::Error::from_raw_os_error(ret))
    }
    else {
        Ok(())
    }
}

// https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#fs-ioc-measure-verity
pub fn fsverity_measure(fd: impl AsRawFd) -> std::io::Result<(config::InnerHashAlgorithm, Box<[u8]>)> {
    let fd = fd.as_raw_fd();
    #[repr(C)]
    struct fsverity_digest {
        digest_algorithm: u16,
        digest_size: u16,
        digest: [u8; config::MAX_DIGEST_SIZE],
    }

    let mut digest = fsverity_digest {
        digest_algorithm: 0,  // unset
        digest_size: config::MAX_DIGEST_SIZE as u16,
        digest: [0; config::MAX_DIGEST_SIZE],
    };

    let ret = unsafe { libc::ioctl(fd, FS_IOC_MEASURE_VERITY, &mut digest as *mut _) };

    if ret != 0 {
        Err(std::io::Error::from_raw_os_error(ret))
    }
    else {
        Ok((
            config::InnerHashAlgorithm::try_from(digest.digest_algorithm as u8).unwrap(),
            Box::from(&digest.digest[..digest.digest_size as usize]),
        ))
    }
}
