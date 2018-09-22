// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
extern crate sha2;
use blot::core::Blot;

fn main() {
    println!("{:x}", "foo".blot(sha2::Sha256::default()));
    println!("{}", "foo".sha2256());
    println!("{}", "foo".sha2512());
    println!("{:x}", "foo".sha2256().digest().unwrap());
}
