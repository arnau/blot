// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
extern crate digest;
extern crate itertools;
extern crate serde_json;

use blot::core::{float_normalize, Blot, Hash};
// use blot::value::Value;
use digest::Digest;
use serde_json::{Error, Value};

use itertools::Itertools;
use std::fs::File;
use std::io::prelude::*;

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
    let mut file = File::open("tests/common_json.test")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let lines: Vec<&str> = contents
        .lines()
        .filter(|x| x.len() != 0 && !x.starts_with('#'))
        .collect();

    for line in &lines.into_iter().chunks(2) {
        let pair: Vec<&str> = line.collect();
        println!("{:?}", &pair);
    }

    Ok(())
}
