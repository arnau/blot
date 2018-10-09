// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

#[macro_use]
extern crate blot;
extern crate hex;

use blot::core::Blot;
use blot::seal::Seal;
use blot::value::Value;
use hex::FromHex;

fn main() -> std::io::Result<()> {
    let hash = raw!("12206b18693874513ba13da54d61aafa7cad0c8f5573f3431d6f1c04b07ddb27d6bb").unwrap();
    let entry = list![6, "GB", Value::Timestamp("2016-04-05T13:23:05Z".into()), hash];
    println!("{}", entry.sha2256());

    // println!("{}", "foo".blake2b512());
    let blk = "**REDACTED**b2404020fb5053ecefc742b73665625613de5ea09917988fac07d2977ece1c9bebb1aa0e5dfe8e3f2ae7b30ac3b97fac511a4745d71f5d4dbb211d69d06b34fb031e60";

    let seal = Seal::from_str(blk);

    println!("{:?}", seal);

    Ok(())
}
