// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot library

extern crate digest;
extern crate sha2 as crypto_sha2;

pub mod core;
pub mod multihash;
pub mod sha2256;
// pub mod sha2512;
pub mod tag;

// pub use sha2256::Sha2256;
// pub use sha2512::Sha2512;
