// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

//! Aliases for known hashing functions (digesters).

use blake2;
use sha2;

pub type Sha2512 = sha2::Sha512;
pub type Sha2256 = sha2::Sha256;
pub type Blake2b = blake2::Blake2b;
pub type Blake2s = blake2::Blake2s;

// pub struct Blake2b256
