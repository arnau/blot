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
use blot::multihash::{self, Hash, Multihash};
use blot::value::{Value, ValueSet};
use std::io::{self, Read};

use clap::{App, AppSettings, Arg};

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::AllowNegativeNumbers)
        .about("Print blot checksums")
        .arg(
            Arg::with_name("input")
                .help("The data as JSON")
                .long_help(
                    r#"
For example, "foo", {"foo": "bar"}, [1, "foo"]
                "#,
                )
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
        ).arg(Arg::with_name("sequence")
              .help("Sequence mode. JSON")
              .long_help("JSON only has arrays but Blot has lists and sets where the former is hashed as is and the latter disregards the order of the items and ensures there are no duplicates.")
              .long("sequence")
              .takes_value(true)
              .default_value("list")
              .possible_values(&["list", "set"])
        ).arg(
            Arg::with_name("verbose")
                .help("Verbose mode")
                .long("verbose"),
        ).get_matches();

    let input = matches
        .value_of("input")
        .map(handle_stdin)
        .unwrap_or_else(|| consume_stdin());
    let seq_mode = matches.value_of("sequence").unwrap();
    let verbose = matches.is_present("verbose");

    match matches.value_of("algorithm").unwrap() {
        "sha1" => digest_command(&input, seq_mode, verbose, multihash::Sha1),
        "sha2-256" => digest_command(&input, seq_mode, verbose, multihash::Sha2256),
        "sha2-512" => digest_command(&input, seq_mode, verbose, multihash::Sha2512),
        "sha3-224" => digest_command(&input, seq_mode, verbose, multihash::Sha3224),
        "sha3-256" => digest_command(&input, seq_mode, verbose, multihash::Sha3256),
        "sha3-384" => digest_command(&input, seq_mode, verbose, multihash::Sha3384),
        "sha3-512" => digest_command(&input, seq_mode, verbose, multihash::Sha3512),
        "blake2b-512" => digest_command(&input, seq_mode, verbose, multihash::Blake2b512),
        "blake2s-256" => digest_command(&input, seq_mode, verbose, multihash::Blake2s256),
        _ => unreachable!(),
    };
}

fn consume_stdin() -> String {
    let mut buffer = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    handle.read_to_string(&mut buffer).unwrap();

    buffer
}

fn handle_stdin(input: &str) -> String {
    if input == "-" {
        consume_stdin()
    } else {
        input.to_string()
    }
}

fn digest_command<D: Multihash>(input: &str, seq_mode: &str, verbose: bool, digester: D) {
    let value = match seq_mode {
        "list" => serde_json::from_str::<Value<D>>(&input).expect("Valid json"),
        "set" => serde_json::from_str::<ValueSet<D>>(&input)
            .expect("Valid json")
            .to_value(),
        _ => unreachable!(),
    };

    let hash = value.digest(digester);

    if verbose {
        display_verbose(&hash);
    } else {
        display(&hash);
    }
}

fn display<T: Multihash>(hash: &Hash<T>) {
    let code = format!("{:02x}", &hash.tag().code());
    let length = format!("{:02x}", &hash.tag().length());
    let digest = format!("{}", &hash.digest());

    print!("{}", Black.on(Fixed(198)).paint(code));
    print!("{}", Black.on(Fixed(39)).paint(length));
    println!("{}", Fixed(221).on(Black).paint(digest));
}

fn display_verbose<T: Multihash>(hash: &Hash<T>) {
    println!(
        "{} {:#02x} ({})",
        Black.on(Fixed(198)).paint("Codec: "),
        &hash.tag().code(),
        hash.tag().name()
    );
    println!(
        "{} {:#02x}",
        Black.on(Fixed(39)).paint("Length:"),
        &hash.tag().length()
    );
    println!(
        "{} 0x{}",
        Black.on(Fixed(221)).paint("Digest:"),
        &hash.digest()
    );
}
