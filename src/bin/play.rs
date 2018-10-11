// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

#[macro_use]
extern crate blot;
extern crate serde;
extern crate serde_json;

use blot::core::Blot;
use blot::value::Value;

fn main() -> std::io::Result<()> {
    let s: Value = serde_json::from_str(r#"["foo"]"#).unwrap();

    println!("{:?}", &s);

    Ok(())
}
