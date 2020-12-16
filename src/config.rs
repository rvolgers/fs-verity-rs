use num_enum::TryFromPrimitive;

// source for these two: https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#fs-verity-descriptor
pub const MAX_DIGEST_SIZE: usize = 64;
pub const MAX_SALT_SIZE: usize = 32;

// linux has a hardcoded limit, see FS_VERITY_MAX_LEVELS in /fs/verity/fsverity_private.h
pub const MAX_LEVELS: usize = 8;

pub const DEFAULT_BLOCK_SIZE: usize = 4096;

// So we can have easy cross references in doc comments
use super::*;

/// Enum of the supported inner hash algorithms.
/// 
/// The [`Default`] value is `Sha256`, corresponding to the default hash algorithm in the `fsverity` tools.
/// 
/// This enum supports conversion to string using [`std::fmt::Display`] and from a string using [`parse_display::FromStr`].
/// 
/// It also supports conversion to integer using `as u8` and from integer using [`TryFromPrimitive`]). These integers values
/// match the hash algorithm numbering used in the fsverity kernel API.
/// 
/// You can create an instance of `FsVerityDigest` with this inner hash and default values for block size and
/// salt by using the `Into<Box<dyn `[`DynDigestWrite`]`>>` implementation. If you want to specify the salt and/or block
/// size, see [`DigestSpec`]. If you statically know which inner hash algorithm you want to use, you can of
/// course instantiate [`FsVerityDigest`] directly.
#[derive(Copy, Clone, PartialEq, Eq, parse_display::FromStr, parse_display::Display, Debug, TryFromPrimitive)]
#[display(style = "lowercase")]
#[repr(u8)]
pub enum InnerHashAlgorithm {
    /// As string: `sha256`. As number: `FS_VERITY_HASH_ALG_SHA256` from the kernel API.
    Sha256 = 1,

    /// As string: `sha512`. As number: `FS_VERITY_HASH_ALG_SHA512` from the kernel API.
    Sha512 = 2,
}

impl Default for InnerHashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

impl Into<Box<dyn DynDigestWrite>> for InnerHashAlgorithm {
    fn into(self) -> Box<dyn DynDigestWrite> {
        match self {
            InnerHashAlgorithm::Sha256 => Box::new(crate::FsVeritySha256::new()),
            InnerHashAlgorithm::Sha512 => Box::new(crate::FsVeritySha512::new()),
        }
    }
}

/// Struct which encapsulates the configuration of [`FsVerityDigest`]. Useful to create a [`FsVerityDigest`] with an inner hash algorithm selected at runtime.
///
/// If you statically know which inner hash algorithm you want to use, you can just instantiate [`FsVerityDigest`] directly.
///
/// You can create an instance of [`FsVerityDigest`] with this configuration by using the `Into<Box<dyn `[`DynDigestWrite`]`>>`
/// implementation. 
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DigestSpec {
    hash_algo: InnerHashAlgorithm,
    block_size: usize,
    salt: Box<[u8]>,
}

impl Default for DigestSpec {
    fn default() -> Self {
        Self {
            hash_algo: Default::default(),
            block_size: DEFAULT_BLOCK_SIZE,
            salt: Default::default(),
        }
    }
}

impl Into<Box<dyn DynDigestWrite>> for DigestSpec {
    fn into(self) -> Box<dyn DynDigestWrite> {
        match self.hash_algo {
            InnerHashAlgorithm::Sha256 => Box::new(crate::FsVeritySha256::new_with_salt_and_block_size(self.salt, self.block_size)),
            InnerHashAlgorithm::Sha512 => Box::new(crate::FsVeritySha512::new_with_salt_and_block_size(self.salt, self.block_size)),
        }
    }
}

