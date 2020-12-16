use sha2::digest;
use digest::{FixedOutputDirty, BlockInput, FixedOutput, Reset, Update};
use sha2::{Sha256, Sha512};
use std::io::Write;

use crate::config::*;

static ZEROES: [u8; 128] = [0u8; 128];

/// Trait for the inner hash algorithms we support (currently implemented for [`Sha256`] and [`Sha512`]).
/// 
/// It adds some information we need, some useful functions, and declares all the trait bounds we need
/// so we have them in one place.
pub trait InnerHash: Update + FixedOutputDirty + Reset + Clone + Default + BlockInput {
    /// The value of [`InnerHashAlgorithm`] that corresponds to this hash algorithm.
    const VERITY_HASH_ALGORITHM: InnerHashAlgorithm;

    /// Update the hash state with given data, padded with zero bytes to the given size.
    /// This will panic if `data.len() > padded_size`.
    fn update_padded(&mut self, data: &[u8], padded_size: usize) {
        self.update(data);
        self.update_zeroes(padded_size.checked_sub(data.len()).unwrap());
    }

    /// Update the hash state with the given amount of zero bytes
    fn update_zeroes(&mut self, amount: usize) {
        let (quotient, remainder) = (amount / ZEROES.len(), amount % ZEROES.len());
        if remainder != 0 { self.update(&ZEROES[..remainder]); }
        for _ in 0..quotient { self.update(&ZEROES); }
    }

    /// The size in bytes of the digests produced by this hash function
    fn digest_output_size() -> usize {
        <Self::OutputSize as digest::generic_array::typenum::Unsigned>::to_usize()
    }

    /// The native input block size of this hash function (in bytes)
    fn digest_block_size() -> usize {
        <Self::BlockSize as digest::generic_array::typenum::Unsigned>::to_usize()
    }
}

impl InnerHash for Sha256 {
    const VERITY_HASH_ALGORITHM: InnerHashAlgorithm = InnerHashAlgorithm::Sha256;
}

impl InnerHash for Sha512 {
    const VERITY_HASH_ALGORITHM: InnerHashAlgorithm = InnerHashAlgorithm::Sha512;
}

/// Logically this represents a fixed-size block of data to be hashed (padded with zeroes if needed.)
/// It actually remembers only the hash state and how many more bytes are needed, not the data itself.
/// But that's an implementation detail.
#[derive(Clone)]
struct FixedSizeBlock<D> where D: InnerHash {
    inner: D,
    remaining: usize,
}

impl<D> FixedSizeBlock<D> where D: InnerHash {
    fn new(inner: D, block_size: usize) -> Self {
        Self { inner: inner.clone(), remaining: block_size }
    }

    /// Appends data to block, panics if it doesn't fit.
    fn append(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.remaining = self.remaining.checked_sub(data.len()).unwrap();
    }

    /// Fills the remaining space in the block with zero bytes.
    fn fill_to_end(&mut self) {
        self.inner.update_zeroes(self.remaining);
        self.remaining = 0;
    }

    /// Appends as much as possible to the block, returning the data that wouldn't fit.
    fn overflowing_append<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let (a, b) = data.split_at(self.remaining.min(data.len()));
        self.append(a);
        b
    }

    // Returns the final hash of the block, consuming it.
    fn finalize_into(mut self, dest: &mut digest::Output<D>) {
        self.fill_to_end();
        self.inner.finalize_into(dest);
    }

    /// Return the final hash of the block, and then reset its state to a copy of the given block.
    fn finalize_into_and_reset_from(&mut self, dest: &mut digest::Output<D>, template: &Self) {
        self.fill_to_end();
        // using the dirty variant is okay because we overwrite all our state right after this
        self.inner.finalize_into_dirty(dest);
        self.clone_from(template);
    }
}

#[derive(Clone)]
pub struct FsVerityDigest<D=Sha256, S=[u8; 0]> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {
    block_size: usize,
    /// We have to keep the actual salt around (not just its digest) as it is needed for the final hash operation.
    salt: S,
    /// Cloned whenever we need a new empty block.
    empty_block: FixedSizeBlock<D>,
    /// The currently relevant hierarchy of blocks in the Merkle tree.
    levels: Vec<FixedSizeBlock<D>>,
}

/// Returns an instance of the hash algorithm which has been fed the given salt,
/// zero-padded to a multiple of the hash algorithm's input block size.
fn salted_digest<D: InnerHash>(salt: &[u8]) -> D {
    let mut tmp = <D as digest::Digest>::new();
    // in practice this will run either 0 or 1 iterations, due to low MAX_SALT_SIZE
    for chunk in salt.chunks(D::digest_block_size()) {
        tmp.update_padded(chunk, D::digest_block_size());
    }
    tmp
}

impl<D> FsVerityDigest<D> where D: InnerHash {

    /// Creates a new instance of `FsVerityDigest` with an empty salt.
    ///
    /// This is probably what you want.
    pub fn new() -> Self {
        Self::new_with_salt(Default::default())
    }
}

impl<D, S> FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {

    pub fn inner_hash_algorithm(&self) -> InnerHashAlgorithm {
        D::VERITY_HASH_ALGORITHM
    }

    /// Creates a new instance of `FsVerityDigest` with the given salt. The salt will be mixed
    /// into every internal hash calculation.
    ///
    /// Note that the current Linux kernel does not allow you to read the salt used for a
    /// particular verity-protected file, which may be a problem depending on your use case.
    ///
    /// This will panic if the salt is longer than [`MAX_SALT_SIZE`] bytes.
    pub fn new_with_salt(salt: S) -> Self {
        Self::new_with_salt_and_block_size(salt, DEFAULT_BLOCK_SIZE)
    }

    /// Creates a new instance of `FsVerityDigest` with the given salt and a custom block size.
    ///
    /// This will panic if the salt is longer than [`MAX_SALT_SIZE`] bytes.
    ///
    /// If you want to be compatible with the Linux kernel implementation it is *not* a good idea
    /// to change the `block_size`, as the kernel currently requires it to be equal to the system
    /// page size, which is 4096 on just about every relevant architecture.
    ///
    /// The block size must be a power of two, and it must be at least twice the size of the
    /// digests produced by the inner hash algorithm. This code will panic otherwise.
    pub fn new_with_salt_and_block_size(salt: S, block_size: usize) -> Self {

        // TODO error instead of panic?
        assert!(salt.as_ref().len() <= MAX_SALT_SIZE);
        assert!(block_size.is_power_of_two());
        assert!(block_size >= D::digest_output_size() * 2);
        assert!(D::digest_output_size() <= MAX_DIGEST_SIZE);

        let empty_block = FixedSizeBlock::new(salted_digest(salt.as_ref()), block_size);

        Self {
            block_size,
            salt,
            empty_block,
            levels: vec![],
        }
    }
}

impl<D, S> Default for FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {
    fn default() -> Self { Self::new_with_salt(Default::default()) }
}

impl<D, S> Update for FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {

    fn update(&mut self, data: impl AsRef<[u8]>) {
        // self.levels represents the hierarchy of currently-relevant Merkle tree blocks.
        // level 0 is filled with input data. when the block at level n fills up, the hash of its
        // contents is appended to the block at level n + 1, and it is reset to an empty state.
        // this process can repeat if that causes the next level to fill up and so on.
        //
        // we do not actually keep the data written into each block, only the hash state.
        //
        // invariants:
        // - level 0 is (once it's created) never empty. it *may* be completely full.
        // - levels 1..n are never full, they always have room for one more hash. they *may* be empty.
        // - overflow is never larger than self.block_size
        //
        // the reason for the asymmetry between flushing of level[0] and the others is that it makes
        // flushing the final state (at the end of file) a lot simpler, because it guarantees that
        // each level will produce exactly one more digest for the next level during the final flush.
        for chunk in data.as_ref().chunks(self.block_size) {

            // keep moving up the hierarchy as long as dealing with the current level produces data
            // that needs to be appended to the next level.
            let mut keep_space_for_one_digest = false;
            let mut last_digest: digest::Output<Self>;
            let mut overflow = chunk;  // input data is treated as overflow into level[0]
            for level in self.levels.iter_mut() {

                // due to multiple reasons, the overflowing_append call will only ever split the data
                // in overflow across two blocks when writing input data (into level 0.) splitting a
                // digest across two blocks would be incorrect, so it is good that this never happens.
                // (the first reason is that valid block sizes and currently known digest sizes are all
                // powers of two, so the block size is always an exact multiple of the digest size.
                // the second reason is that (as mentioned) we always make sure there is room for one
                // more full digest.)
                overflow = level.overflowing_append(overflow);
                if keep_space_for_one_digest {
                    // done if there is enough space left in this level for one full digest
                    if level.remaining >= D::digest_output_size() {
                        assert!(overflow.len() == 0);  // if remaining > 0 there can't be overflow
                        break;
                    }
                } else {
                    // done if there was no overflow, even if the block is now totally full
                    if overflow.len() == 0 { break; }
                }

                // can't write directly into last_digest because overflow is (sometimes) a
                // reference to last_digest, so we have to wait until we're done with overflow.
                let mut tmp: digest::Output<Self> = Default::default();
                level.finalize_into_and_reset_from(&mut tmp, &self.empty_block);
                level.append(overflow);
                last_digest = tmp;

                overflow = &last_digest;

                keep_space_for_one_digest = true;  // only false for level[0]
            }

            // if there is still overflow, add a new top level to the Merkle tree
            if overflow.len() != 0 {

                // note that this is very unlikely, with default settings you will have to write
                // more bytes than can be counted with an u64 before hitting this.
                assert!(self.levels.len() < MAX_LEVELS);

                let mut level = self.empty_block.clone();
                level.append(overflow);
                self.levels.push(level);
            }
        }
    }
}

impl<D, S> FixedOutputDirty for FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {
    type OutputSize = D::OutputSize;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<D>) {

        // a block is self.block_size bytes; a digest is D::digest_output_size() bytes.
        // dividing them gives the "compression factor", meaning how many times smaller the
        // representation of the data becomes each time it moves up a level in the tree.
        // this means that for every level we go up, each byte in that level represents
        // this many times more input bytes than the previous level.
        // we will use this to recover the total number of bytes written from the number
        // of bytes written to each level. this is needed to calculate the final digest.
        // we could also have tracked the number of bytes written directly of course, but
        // besides showing off I guess this is a good consistency check.
        let compression_factor = self.block_size / D::digest_output_size();
        let mut total_size: usize = 0;
        let mut scale: usize = 1;  // at level[0], each byte represents 1 input byte

        // flush all levels, and calculate the hash of the top level. in the docs for fs_verity
        // this is called the "root hash". zero length files are defined to have a root hash of
        // all zeroes, and we can comply with this easily by initializing last_digest to zero.
        // the root hash is ambiguous by itself, since it is simply a hash of block_size bytes
        // of data, and that data could have been either file data or digests of other blocks.
        // you always need the file size as well to properly interpret the root hash.
        // this means there is no additional risk of ambiguity if a block is ever discovered
        // which happens to hash to all zeros.
        let mut last_digest: digest::Output<Self> = Default::default();
        let mut overflow: &[u8] = &[];
        for mut level in self.levels.drain(..) {
            total_size += scale * (self.block_size - level.remaining);
            level.append(overflow);
            level.finalize_into(&mut last_digest);
            overflow = &last_digest;
            scale *= compression_factor;
        }

        // the root hash, file size, hash algorithm, and salt are combined into a structure
        // called a 'verity descriptor'. the (salted) hash of this data is the final result,
        // and it is called a 'verity measurement'.
        // https://www.kernel.org/doc/html/latest/filesystems/fsverity.html#fs-verity-descriptor

        let mut descriptor: D = salted_digest(self.salt.as_ref());
        descriptor.update(&[1]);
        descriptor.update(&[D::VERITY_HASH_ALGORITHM as u8]);
        descriptor.update(&[self.block_size.trailing_zeros() as u8]);
        descriptor.update(&[self.salt.as_ref().len() as u8]);
        descriptor.update(&[0; 4]);
        descriptor.update(&(total_size as u64).to_le_bytes());
        descriptor.update_padded(&last_digest, MAX_DIGEST_SIZE);
        descriptor.update_padded(self.salt.as_ref(), MAX_SALT_SIZE);
        descriptor.update_zeroes(144);

        descriptor.finalize_into(out);
    }
}

/// NOTE: This reports the base hash function's input block size, *not* the Merkle tree block size you
/// specify when creating the `FsVerityDigest`!
///
/// While this may be confusing, it is probably more faithful to the purpose of the `BlockInput` trait.
/// We don't need to buffer an entire Merkle tree block in memory; data can be efficiently processed
/// in chunks of the base hash's input block size.
impl<D, S> BlockInput for FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {
    /// Equal to the inner hash algorithm's block size.
    type BlockSize = <D as BlockInput>::BlockSize;
}

/// Resets to a blank state, but with the same Merkle tree block size and salt
impl<D, S> Reset for FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {
    fn reset(&mut self) {
        // Pretty basic implementation but good enough
        *self = Self::new_with_salt_and_block_size(self.salt.clone(), self.block_size);
    }
}

impl<D, S> Write for FsVerityDigest<D, S> where D: InnerHash, S: AsRef<[u8]> + Clone + Default {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// For trait objects of [`FsVerityDigest`], when the inner hash is not statically known (see [`DigestSpec`])
pub trait DynDigestWrite: sha2::digest::DynDigest + Write {}
impl<D: InnerHash + 'static, S: AsRef<[u8]> + Clone + Default + 'static> DynDigestWrite for FsVerityDigest<D, S> {}

/// Alias for `FsVerityDigest<Sha256>`
pub type FsVeritySha256<S> = FsVerityDigest<Sha256, S>;

/// Alias for `FsVerityDigest<Sha512>`
pub type FsVeritySha512<S> = FsVerityDigest<Sha512, S>;

#[cfg(test)]
mod tests {
    use crate::DynDigestWrite;
    use std::io::BufReader;
    use std::fs::File;
    use crate::InnerHashAlgorithm;

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
            let digest_type = digest_type.parse::<super::InnerHashAlgorithm>().unwrap();
            let digest = hex::decode(digest).unwrap();
            (digest_type, digest, path)
        }).collect::<Vec<_>>();

        for (digest_type, digest, path) in testfiles {
            assert!(digest_type == InnerHashAlgorithm::Sha256);
            let mut f = BufReader::new(File::open(path).unwrap());
            let mut tmp: Box<dyn DynDigestWrite> = digest_type.into();
            std::io::copy(&mut f, &mut tmp).unwrap();
            let out = tmp.finalize();

            let tmp = hex::encode(&digest);
            let tmp2 = hex::encode(&out);
            assert!(out.as_ref() == &digest, "expected: {} found: {} for file: {}", tmp, tmp2, path);
        }
    }
}
