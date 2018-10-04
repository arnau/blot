// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
// extern crate digest;
extern crate serde_json;

use blot::core::Blot;
use serde_json::Value;

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

    let s = "**REDACTED**32ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2";

    println!("{}", s.get(12..).expect("X"));

    // let value: Value = serde_json::from_str(r#"["**REDACTED**a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038", "bar"]"#).unwrap();
    // println!("{}", &value.sha2256());

    Ok(())
}
