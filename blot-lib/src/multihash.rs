// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use digest;
use digester;
use std::fmt;
use uvar::Uvar;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Digest(Vec<u8>);

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl Digest {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Digest {
    fn from(vec: Vec<u8>) -> Digest {
        Digest(vec)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hash<T: Multihash> {
    tag: T,
    digest: Digest,
}

impl<T: Multihash> Hash<T> {
    pub fn new<D: Into<Digest>>(tag: T, digest: D) -> Hash<T> {
        Hash {
            tag,
            digest: digest.into(),
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn tag(&self) -> &T {
        &self.tag
    }
}

impl<T: Multihash> fmt::Display for Hash<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:02x}", &self.tag.code())?;
        write!(formatter, "{:02x}", &self.tag.length())?;
        write!(formatter, "{}", &self.digest)?;

        Ok(())
    }
}

/// Multihash trait to be implemented by any algorithm used by Blot.
///
/// For example, the SHA3-512 algorithm:
///
/// ```
/// use blot::multihash::{Sha3512, Multihash};
/// use blot::uvar::Uvar;
///
/// let tag = Sha3512::default();
///
/// assert_eq!(tag.name(), "sha3-512");
/// assert_eq!(tag.code(), Uvar::new(vec![0x14]));
/// assert_eq!(tag.length(), 64);
/// ```
pub trait Multihash: Default + PartialEq {
    type Digester: digest::Digest + Clone;

    fn length(&self) -> u8;
    fn code(&self) -> Uvar;
    fn name(&self) -> &str;
    fn digester(&self) -> Self::Digester {
        Self::Digester::default()
    }
}

#[derive(Debug)]
pub enum MultihashError {
    Unknown,
}

// Sha1

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

    fn digester(&self) -> Self::Digester {
        Self::Digester::default()
    }
}

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
    type Digester = digester::Sha2256;

    fn name(&self) -> &'static str {
        "sha2-256"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x12)
    }

    fn length(&self) -> u8 {
        32
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
    type Digester = digester::Sha2512;

    fn name(&self) -> &'static str {
        "sha2-512"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x13)
    }

    fn length(&self) -> u8 {
        64
    }
}

// Sha3-512

#[derive(Clone, Debug, PartialEq)]
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
    type Digester = digester::Sha3512;

    fn name(&self) -> &'static str {
        "sha3-512"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x14)
    }

    fn length(&self) -> u8 {
        64
    }
}

// Sha3-384

#[derive(Clone, Debug, PartialEq)]
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
    type Digester = digester::Sha3384;

    fn name(&self) -> &'static str {
        "sha3-384"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x15)
    }

    fn length(&self) -> u8 {
        48
    }
}

// Sha3-256

#[derive(Clone, Debug, PartialEq)]
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
    type Digester = digester::Sha3256;

    fn name(&self) -> &'static str {
        "sha3-256"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x16)
    }

    fn length(&self) -> u8 {
        32
    }
}

// Sha3-224

#[derive(Clone, Debug, PartialEq)]
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
    type Digester = digester::Sha3224;

    fn name(&self) -> &'static str {
        "sha3-224"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0x17)
    }

    fn length(&self) -> u8 {
        28
    }
}

// Blake2b-512

#[derive(Clone, Debug, PartialEq)]
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
    type Digester = digester::Blake2b512;

    fn name(&self) -> &'static str {
        "blake2b-512"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0xb240)
    }

    fn length(&self) -> u8 {
        64
    }
}

// Blake2s-256

#[derive(Clone, Debug, PartialEq)]
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
    type Digester = digester::Blake2s256;

    fn name(&self) -> &'static str {
        "blake2s-256"
    }

    fn code(&self) -> Uvar {
        Uvar::from(0xb260)
    }

    fn length(&self) -> u8 {
        32
    }
}
