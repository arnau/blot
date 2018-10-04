// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
extern crate digest;

use blot::core::Blot;
use blot::value::Value;
use digest::Digest;
use std::collections::HashMap;

// fn print_digest<T: Digest>(hash: Hash<T>) {
//     match hash.digest() {
//         None => println!("nothing to print"),
//         Some(bytes) => {
//             for byte in bytes.iter() {
//                 print!("{:02x}", byte);
//             }
//         }
//     }
//     println!("");
// }

fn main() -> std::io::Result<()> {
    let v = vec!["foo", "bar"];

    println!("{}", v.sha2256());

    Ok(())
}
