// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;

use blot::core::Blot;
use blot::multihash::Sha3256;

fn main() -> std::io::Result<()> {
    // Computes the blot hash with the SHA3-256 algorithm.
    let hash = "foo".digest(Sha3256);

    println!("{}", &hash);

    Ok(())
}
