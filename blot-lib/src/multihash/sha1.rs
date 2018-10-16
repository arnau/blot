// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot implementation for sha1

use super::{Harvest, Multihash, MultihashError};
use crypto_sha1 as digester;
use crypto_sha1::Digest;
use tag::Tag;
use uvar::Uvar;

#[derive(Clone, Debug, PartialEq)]
pub struct Sha1;

impl Default for Sha1 {
    fn default() -> Self {
        Sha1
    }
}

impl From<Sha1> for Uvar {
    fn from(hash: Sha1) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha1, MultihashError> {
    fn from(code: Uvar) -> Result<Sha1, MultihashError> {
        let n: u64 = code.into();

        if n == 0x11 {
            Ok(Sha1)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha1 {
    type Digester = digester::Sha1;

    fn name(&self) -> &'static str {
        "sha1"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x11)
    }

    fn length(&self) -> u8 {
        20
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
