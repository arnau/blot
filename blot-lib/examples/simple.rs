// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

#[macro_use]
extern crate blot;

use blot::core::Blot;
use blot::multihash::Sha3256;
use blot::value::Value;

fn main() -> std::io::Result<()> {
    // Creates a `blot::value::Value`.
    let set: Value<Sha3256> = set!{"foo", "bar", list![1, 1.0]};

    // Computes the blot hash with the SHA3-256 algorithm.
    let hash = set.digest(Sha3256);

    println!("{}", &hash);

    Ok(())
}
