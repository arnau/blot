// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

#[macro_use]
extern crate blot;

use blot::multihash::Sha3256;
use blot::seal::Seal;
use blot::value::Value;
use blot::Blot;

fn main() -> std::io::Result<()> {
    let seal: Value<Sha3256> =
        seal!("**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038")
            .unwrap();
    // Creates a `blot::value::Value`.
    let set: Value<Sha3256> = set!{"foo", "bar", list![1, 1.0], seal};

    // Computes the blot hash with the SHA3-256 algorithm.
    let hash = set.digest(Sha3256);

    println!("{}", &hash);

    Ok(())
}
