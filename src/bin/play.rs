// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
extern crate digest;
extern crate serde_json;

use blot::core::{Blot, Hash};
// use blot::value::Value;
use digest::Digest;
use serde_json::{Error, Value};

fn print_digest<T: Digest>(hash: Hash<T>) {
    match hash.digest() {
        None => println!("nothing to print"),
        Some(bytes) => {
            for byte in bytes.iter() {
                print!("{:02x}", byte);
            }
        }
    }
    println!("");
}

fn untyped_example() -> Result<(), Error> {
    // Some JSON input data as a &str. Maybe this comes from the user.
    let data = r#"["foo", "bar"]"#;

    // Parse the string of data into serde_json::Value.
    let v: Value = serde_json::from_str(data)?;

    println!("{:?}", &v);
    println!("{}", &v.sha2256());

    // Access parts of the data by indexing with square brackets.
    println!("{} {}", v["name"], v["groups"][0]);

    Ok(())
}

fn main() {
    // println!("{}", "foo".blake2b512());
    // println!("{}", "foo".blake2b256());

    // println!("{:?}", val);
    untyped_example();
}
