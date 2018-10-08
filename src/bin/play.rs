// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;

// use blot::core::Blot;
use blot::seal::Seal;

fn main() -> std::io::Result<()> {
    // println!("{}", "foo".blake2b512());
    let blk = "**REDACTED**b2404020fb5053ecefc742b73665625613de5ea09917988fac07d2977ece1c9bebb1aa0e5dfe8e3f2ae7b30ac3b97fac511a4745d71f5d4dbb211d69d06b34fb031e60";

    let seal = Seal::from_str(blk);

    println!("{:?}", seal);

    Ok(())
}
