// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Blot implementation for sha3.

use super::{Harvest, Multihash, MultihashError};
use crypto_sha3 as digester;
use crypto_sha3::Digest;
use tag::Tag;
use uvar::Uvar;

// Sha3-512

#[derive(Debug, PartialEq)]
pub struct Sha3512;

impl Default for Sha3512 {
    fn default() -> Self {
        Sha3512
    }
}

impl From<Sha3512> for Uvar {
    fn from(hash: Sha3512) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha3512, MultihashError> {
    fn from(code: Uvar) -> Result<Sha3512, MultihashError> {
        let n: u64 = code.into();

        if n == 0x14 {
            Ok(Sha3512)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha3512 {
    type Digester = digester::Sha3_512;

    fn name(&self) -> &'static str {
        "sha3-512"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x14)
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

// Sha3-384

#[derive(Debug, PartialEq)]
pub struct Sha3384;

impl Default for Sha3384 {
    fn default() -> Self {
        Sha3384
    }
}

impl From<Sha3384> for Uvar {
    fn from(hash: Sha3384) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha3384, MultihashError> {
    fn from(code: Uvar) -> Result<Sha3384, MultihashError> {
        let n: u64 = code.into();

        if n == 0x15 {
            Ok(Sha3384)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha3384 {
    type Digester = digester::Sha3_384;

    fn name(&self) -> &'static str {
        "sha3-384"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x15)
    }

    fn length(&self) -> u8 {
        48
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

// Sha3-256

#[derive(Debug, PartialEq)]
pub struct Sha3256;

impl Default for Sha3256 {
    fn default() -> Self {
        Sha3256
    }
}

impl From<Sha3256> for Uvar {
    fn from(hash: Sha3256) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha3256, MultihashError> {
    fn from(code: Uvar) -> Result<Sha3256, MultihashError> {
        let n: u64 = code.into();

        if n == 0x16 {
            Ok(Sha3256)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha3256 {
    type Digester = digester::Sha3_256;

    fn name(&self) -> &'static str {
        "sha3-256"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x16)
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

// Sha3-224

#[derive(Debug, PartialEq)]
pub struct Sha3224;

impl Default for Sha3224 {
    fn default() -> Self {
        Sha3224
    }
}

impl From<Sha3224> for Uvar {
    fn from(hash: Sha3224) -> Uvar {
        hash.code()
    }
}

impl From<Uvar> for Result<Sha3224, MultihashError> {
    fn from(code: Uvar) -> Result<Sha3224, MultihashError> {
        let n: u64 = code.into();

        if n == 0x17 {
            Ok(Sha3224)
        } else {
            Err(MultihashError::Unknown)
        }
    }
}

impl Multihash for Sha3224 {
    type Digester = digester::Sha3_224;

    fn name(&self) -> &'static str {
        "sha3-224"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x17)
    }

    fn length(&self) -> u8 {
        28
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
