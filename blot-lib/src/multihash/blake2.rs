// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot implementation for blake2.

use super::{Harvest, Multihash, MultihashError};
use crypto_blake2 as digester;
use crypto_blake2::Digest;
use tag::Tag;
use uvar::Uvar;

// Blake2b-512

#[derive(Debug, PartialEq)]
pub struct Blake2b512;

impl Default for Blake2b512 {
    fn default() -> Self {
        Blake2b512
    }
}

impl From<Blake2b512> for Uvar {
    fn from(hash: Blake2b512) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Blake2b512, MultihashError> {
    fn from(code: Uvar) -> Result<Blake2b512, MultihashError> {
        let n: u64 = code.into();

        if n == 0xb240 {
            Ok(Blake2b512)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Blake2b512 {
    type Digester = digester::Blake2b;

    fn name(&self) -> &'static str {
        "blake2b-512"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0xb240)
    }

    fn length(&self) -> u8 {
        64
    }

    fn digest_primitive(&self, tag: Tag, bytes: &[u8]) -> Harvest {
        let mut digester = Self::Digester::default();
        digester.input(&tag.to_bytes());
        digester.input(bytes);
        digester.result().as_ref().to_vec().into()
    }

    fn digest_collection(&self, tag: Tag, list: Vec<Vec<u8>>) -> Harvest {
        let mut digester = Self::Digester::default();
        digester.input(&tag.to_bytes());

        for bytes in list {
            digester.input(&bytes);
        }

        digester.result().as_ref().to_vec().into()
    }
}

// Blake2s-256

#[derive(Debug, PartialEq)]
pub struct Blake2s256;

impl Default for Blake2s256 {
    fn default() -> Self {
        Blake2s256
    }
}

impl From<Blake2s256> for Uvar {
    fn from(hash: Blake2s256) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Blake2s256, MultihashError> {
    fn from(code: Uvar) -> Result<Blake2s256, MultihashError> {
        let n: u64 = code.into();

        if n == 0xb260 {
            Ok(Blake2s256)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Blake2s256 {
    type Digester = digester::Blake2s;

    fn name(&self) -> &'static str {
        "blake2s-256"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0xb260)
    }

    fn length(&self) -> u8 {
        32
    }

    fn digest_primitive(&self, tag: Tag, bytes: &[u8]) -> Harvest {
        let mut digester = Self::Digester::default();
        digester.input(&tag.to_bytes());
        digester.input(bytes);
        digester.result().as_ref().to_vec().into()
    }

    fn digest_collection(&self, tag: Tag, list: Vec<Vec<u8>>) -> Harvest {
        let mut digester = Self::Digester::default();
        digester.input(&tag.to_bytes());

        for bytes in list {
            digester.input(&bytes);
        }

        digester.result().as_ref().to_vec().into()
    }
}
