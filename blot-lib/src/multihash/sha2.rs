// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot implementation for sha2.

use super::{Harvest, Multihash, MultihashError};
use crypto_sha2 as digester;
use crypto_sha2::Digest;
use tag::Tag;
use uvar::Uvar;

// Sha2-256

#[derive(Clone, Debug, PartialEq)]
pub struct Sha2256;

impl Default for Sha2256 {
    fn default() -> Self {
        Sha2256
    }
}

impl From<Sha2256> for Uvar {
    fn from(hash: Sha2256) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha2256, MultihashError> {
    fn from(code: Uvar) -> Result<Sha2256, MultihashError> {
        let n: u64 = code.into();

        if n == 0x12 {
            Ok(Sha2256)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha2256 {
    type Digester = digester::Sha256;

    fn name(&self) -> &'static str {
        "sha2-256"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x12)
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

// Sha2-512

#[derive(Clone, Debug, PartialEq)]
pub struct Sha2512;

impl Default for Sha2512 {
    fn default() -> Self {
        Sha2512
    }
}

impl From<Sha2512> for Uvar {
    fn from(hash: Sha2512) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha2512, MultihashError> {
    fn from(code: Uvar) -> Result<Sha2512, MultihashError> {
        let n: u64 = code.into();

        if n == 0x13 {
            Ok(Sha2512)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha2512 {
    type Digester = digester::Sha512;

    fn name(&self) -> &'static str {
        "sha2-512"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x13)
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
