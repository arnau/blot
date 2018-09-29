// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
extern crate sha2;
use blot::core::Blot;

use std::collections::HashMap;

fn main() {
    // println!("{}", "foo".sha2256());
    // println!("{}", 1u16.sha2256());
    // println!("{}", true.sha2256());

    // let v = vec!["foo"];
    // // let v = Some("foo");
    // println!("{}", v.sha2256());

    let mut h: HashMap<&str, u32> = HashMap::new();

    h.insert("a", 1);
    h.insert("b", 2);

    for (k, v) in h.into_iter() {
        println!("{} {}", k, v);
    }
}
