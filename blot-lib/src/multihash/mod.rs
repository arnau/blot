// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use std::fmt;
use tag::Tag;
use uvar::Uvar;

#[cfg(feature = "sha-1")]
mod sha1;
#[cfg(feature = "sha1")]
pub use self::sha1::Sha1;

#[cfg(feature = "sha2")]
mod sha2;
#[cfg(feature = "sha2")]
pub use self::sha2::{Sha2256, Sha2512};

#[cfg(feature = "sha3")]
mod sha3;
#[cfg(feature = "sha3")]
pub use self::sha3::{Sha3224, Sha3256, Sha3384, Sha3512};

#[cfg(feature = "blake2")]
mod blake2;
#[cfg(feature = "blake2")]
pub use self::blake2::{Blake2b512, Blake2s256};

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
    type Digester: Default;

    fn length(&self) -> u8;
    fn code(&self) -> Uvar;
    fn name(&self) -> &str;
    fn digester(&self) -> Self::Digester {
        Self::Digester::default()
    }

    fn digest_primitive(&self, tag: Tag, bytes: &[u8]) -> Harvest;
    fn digest_collection(&self, tag: Tag, list: Vec<Vec<u8>>) -> Harvest;
}

#[derive(Debug)]
pub enum MultihashError {
    Unknown,
}

/// Multihash harvest digest.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Harvest(Box<[u8]>);

impl AsRef<[u8]> for Harvest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for Harvest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.as_ref() {
            write!(formatter, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl Harvest {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Harvest {
    fn from(vec: Vec<u8>) -> Self {
        Harvest(vec.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for Harvest {
    fn from(b: Box<[u8]>) -> Self {
        Harvest(b)
    }
}

/// Multihash tagged hash. Tags a harvested digest with a multihash implementation.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Hash<T: Multihash> {
    tag: T,
    digest: Harvest,
}

impl<T: Multihash> Hash<T> {
    pub fn new<D: Into<Harvest>>(tag: T, digest: D) -> Hash<T> {
        Hash {
            tag,
            digest: digest.into(),
        }
    }

    pub fn digest(&self) -> &Harvest {
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
