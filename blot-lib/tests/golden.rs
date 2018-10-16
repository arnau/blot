// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

#![cfg(feature = "common_json")]

extern crate blot;
extern crate digest;
extern crate itertools;
extern crate serde_json;

use blot::core::Blot;
use blot::multihash::Sha2256;
use itertools::Itertools;
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;

#[test]
fn common_json_golden() {
    let mut file = File::open("tests/common_json.test").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let lines: Vec<&str> = contents
        .lines()
        .filter(|x| x.len() != 0 && !x.starts_with('#'))
        .collect();

    for line in &lines.into_iter().chunks(2) {
        let pair: Vec<&str> = line.collect();
        let value: Value = serde_json::from_str(pair[0]).unwrap();
        let actual = format!("{}", value.digest(Sha2256).digest());
        let expected = pair[1];

        assert_eq!(actual, expected);
    }
}
