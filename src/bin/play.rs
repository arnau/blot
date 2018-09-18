// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
use blot::core::Blot;

fn main() {
    // println!("{:x}", "foo".blot(Sha2256::default()));
    println!("{}", "foo".sha2256());
    println!("{:x}", "foo".sha2256().digest().unwrap());

    // println!("{:x}", &Blot::<Sha2256>::blot(&String::from("foo")));

    // println!("{:x}", &Blot::<Sha2256>::blot(&1u8));
    // println!("{:x}", &Blot::<Sha2256>::blot(&1usize));

    // let f = Blot::<Sha2512>::blot("foo");
    // println!("{:x}", &f);
}
