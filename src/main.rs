use std::{env::args, fs::File, io::{BufReader, Result}};

use fs_verity::FsVeritySha256;
use sha2::Digest;

// #[cfg(target_os = "linux")]
// use fs_verity::linux::fsverity_measure;

fn main() -> Result<()> {

    for arg in args().skip(1) {
        let mut f = BufReader::new(File::open(&arg)?);
        let mut d = FsVeritySha256::new();
        std::io::copy(&mut f, &mut d)?;
        let algo = d.inner_hash_algorithm();
        let digest = d.finalize();
        println!("{}:{} {}", algo, hex::encode(digest), &arg);

        // For comparison with the native value
        // #[cfg(target_os = "linux")]
        // {
        //     let (algo, digest) = fsverity_measure(File::open(&arg)?)?;
        //     println!("{}:{} {}", algo, hex::encode(digest), &arg);
        // }
    }

    Ok(())
}