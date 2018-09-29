// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

//! Aliases for known hashing functions (digesters).

use crypto_sha2;

pub type Sha2512 = crypto_sha2::Sha512;
pub type Sha2256 = crypto_sha2::Sha256;
