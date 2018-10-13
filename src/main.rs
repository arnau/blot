// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

#[macro_use]
extern crate clap;
extern crate blot;
extern crate serde_json;

use blot::core::Blot;
use blot::multihash::Tag;
use blot::value::Value;
use std::process;

use clap::{App, Arg};

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about("Print blot checksums")
        .arg(
            Arg::with_name("input")
                .help("The data as JSON")
                .long_help(
                    r#"
For example, "foo", {"foo": "bar"}, [1, "foo"]
                "#,
                ).required(true)
                .index(1),
        ).arg(
            Arg::with_name("algorithm")
                .help("Hashing algorithm")
                .short("a")
                .long("algorithm")
                .takes_value(true)
                .default_value("sha2-256")
                .possible_values(&[
                    "sha1",
                    "sha2-256",
                    "sha2-512",
                    "sha3-224",
                    "sha3-256",
                    "sha3-384",
                    "sha3-512",
                    "blake2b-512",
                    "blake2s-256",
                ]),
        ).arg(
            Arg::with_name("verbose")
                .help("Verbose mode")
                .long("verbose"),
        ).get_matches();

    let alg = value_t!(matches, "algorithm", Tag).unwrap_or_else(|e| e.exit());
    let input = matches.value_of("input").unwrap();

    let value: Value = serde_json::from_str(&input).unwrap();
    let hash = value.foo(alg);

    println!("{:#}", &hash);
}
