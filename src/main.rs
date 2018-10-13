// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

#[macro_use]
extern crate clap;
extern crate ansi_term;
extern crate blot;
extern crate serde_json;

use ansi_term::Colour::{Black, Fixed};
use blot::core::Blot;
use blot::multihash::{Hash, Multihash, Tag};
use blot::value::Value;

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

    if matches.is_present("verbose") {
        display_verbose(&hash);
    } else {
        display(&hash);
    }
}

fn display(hash: &Hash) {
    let code = format!("{:02x}", &hash.tag().code());
    let length = format!("{:02x}", &hash.tag().length());
    let digest = format!("{}", &hash.digest());

    print!("{}", Black.on(Fixed(198)).paint(code));
    print!("{}", Black.on(Fixed(39)).paint(length));
    println!("{}", Fixed(221).on(Black).paint(digest));
}

fn display_verbose(hash: &Hash) {
    let code = format!("{:#02x}", &hash.tag().code());
    let length = format!("{:#02x}", &hash.tag().length());
    let digest = format!("0x{}", &hash.digest());

    println!("Name:");
    println!("  {}", Black.on(Fixed(255)).paint(hash.tag().name()));
    println!("\nCodec:");
    println!("  {}", Black.on(Fixed(198)).paint(code));
    println!("\nLength:");
    println!("  {}", Black.on(Fixed(39)).paint(length));
    println!("\nDigest:");
    println!("  {}", Fixed(221).on(Black).paint(digest));
}
