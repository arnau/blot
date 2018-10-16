// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot library

extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate serde;
extern crate serde_json;

#[cfg(feature = "blake2")]
extern crate blake2 as crypto_blake2;
#[cfg(feature = "sha-1")]
extern crate sha1 as crypto_sha1;
#[cfg(feature = "sha2")]
extern crate sha2 as crypto_sha2;
#[cfg(feature = "sha3")]
extern crate sha3 as crypto_sha3;

pub mod core;
pub mod json;
pub mod multihash;
pub mod seal;
pub mod tag;
pub mod uvar;
pub mod value;
