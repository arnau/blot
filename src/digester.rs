// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

//! Aliases for known hashing functions (digesters).

use blake2;
use sha2;
use sha3;

// SHA2
pub type Sha2512 = sha2::Sha512;
pub type Sha2256 = sha2::Sha256;

// SHA3
pub type Sha3512 = sha3::Sha3_512;
pub type Sha3384 = sha3::Sha3_384;
pub type Sha3256 = sha3::Sha3_256;
pub type Sha3224 = sha3::Sha3_224;

// Blake2
pub type Blake2b512 = blake2::Blake2b;
pub type Blake2s256 = blake2::Blake2s;
