// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot library
//!
//! **blot** computes the checksum for the given blob of data following the
//! [Objecthash] algorithm adapted to work with [Multihash] hints.
//!
//! [Objecthash]: https://github.com/benlaurie/objecthash
//! [Multihash]: https://github.com/multiformats/multihash
//!
//! blot foundation is the trait [`Blot`]. By default all Rust's primitives
//! are implemented (See [`core`]). If you need more flexibility, either implement it for your
//! types or use [`value::Value`].
//!
//! [`Blot`] requires a hashing function implementing the [`Multihash`] trait. The `default` feature
//! enables SHA1, SHA2, SHA3 and Blake2.
//!
//! # Example: primitives
//!
//! ```
//! use blot::core::Blot;
//! use blot::multihash::Sha3256;
//!
//! println!("{}", "foo".digest(Sha3256));
//! println!("{}", 1.digest(Sha3256));
//! println!("{}", vec![1, 2, 3].digest(Sha3256));
//! ```
//!
//! # Example: mixed collections
//!
//! Mixed collections require a type able to describe them consistently, like the [`value::Value`]
//! enum.
//!
//! ```
//! #[macro_use]
//! extern crate blot;
//! use blot::core::Blot;
//! use blot::multihash::Sha3256;
//! use blot::value::Value;
//!
//! fn main() {
//!     let value: Value<Sha3256> = set!{"foo", "bar", list![1, 1.0], set!{}};
//!
//!     println!("{}", value.digest(Sha3256));
//! }
//! ```

#[cfg(feature = "blot_json")]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "blot_json")]
extern crate regex;
#[cfg(feature = "blot_json")]
extern crate serde;
#[cfg(feature = "blot_json")]
extern crate serde_json;

extern crate hex;

#[cfg(feature = "blake2")]
extern crate blake2 as crypto_blake2;
#[cfg(feature = "sha-1")]
extern crate sha1 as crypto_sha1;
#[cfg(feature = "sha2")]
extern crate sha2 as crypto_sha2;
#[cfg(feature = "sha3")]
extern crate sha3 as crypto_sha3;

pub mod core;
pub mod multihash;
pub mod seal;
pub mod tag;
pub mod uvar;
pub mod value;

#[cfg(feature = "blot_json")]
pub mod json;

pub use core::Blot;
pub use multihash::Multihash;
