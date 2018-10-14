// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use std::fmt;
use std::str::FromStr;
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
pub struct Hash {
    tag: Stamp,
    digest: Digest,
}

impl Hash {
    pub fn new<T: Into<Digest>>(tag: Stamp, digest: T) -> Hash {
        Hash {
            tag,
            digest: digest.into(),
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn tag(&self) -> &Stamp {
        &self.tag
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:02x}", &self.tag.code())?;
        write!(formatter, "{:02x}", &self.tag.length())?;
        write!(formatter, "{}", &self.digest)?;

        Ok(())
    }
}

pub trait Multihash {
    fn length(&self) -> u8;
    fn code(&self) -> Uvar; // uvar ranges from u8 to u64
    fn name(&self) -> &str;
}

/// A generic multihash bag.
///
/// Convenience representation to move the tuple {name, code, length} around.
#[derive(Clone)]
pub struct Bag {
    code: Uvar,
    name: &'static str,
    length: u8,
}

impl Multihash for Bag {
    fn code(&self) -> Uvar {
        self.code.clone()
    }

    fn name(&self) -> &str {
        self.name
    }

    fn length(&self) -> u8 {
        self.length
    }
}

/// Stamp of known multihash tags.
///
/// For example, the SHA3-512 tag is:
///
/// ```
/// use blot::multihash::{Stamp, Multihash};
/// use blot::uvar::Uvar;
///
/// let name: &str = Stamp::Sha3512.into();
/// let code: Uvar = Stamp::Sha3512.into();
/// let length: u8 = Stamp::Sha3512.length();
///
/// assert_eq!(name, "sha3-512");
/// assert_eq!(code, Uvar::new(vec![0x14]));
/// assert_eq!(length, 64);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Stamp {
    /// SHA-1 (20-byte hash size)
    Sha1,
    /// SHA-256 (32-byte hash size)
    Sha2256,
    /// SHA-512 (64-byte hash size)
    Sha2512,
    /// SHA3-512 (64-byte hash size)
    Sha3512,
    /// SHA3-384 (48-byte hash size)
    Sha3384,
    /// SHA3-256 (32-byte hash size)
    Sha3256,
    /// SHA3-224 (28-byte hash size)
    Sha3224,
    /// Blake2b-256 (32-byte hash size)
    // Blake2b256,
    /// Blake2b-512 (64-byte hash size)
    Blake2b512,
    /// Blake2s-256 (32-byte hash size)
    Blake2s256,
}

impl From<u64> for Stamp {
    fn from(code: u64) -> Stamp {
        match code {
            0x11 => Stamp::Sha1,
            0x12 => Stamp::Sha2256,
            0x13 => Stamp::Sha2512,
            0x14 => Stamp::Sha3512,
            0x15 => Stamp::Sha3384,
            0x16 => Stamp::Sha3256,
            0x17 => Stamp::Sha3224,
            0xb240 => Stamp::Blake2b512,
            0xb260 => Stamp::Blake2s256,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum StampError {
    Unknown,
}

impl From<Uvar> for Result<Stamp, StampError> {
    fn from(code: Uvar) -> Result<Stamp, StampError> {
        let n: u64 = code.into();

        match n {
            0x11 => Ok(Stamp::Sha1),
            0x12 => Ok(Stamp::Sha2256),
            0x13 => Ok(Stamp::Sha2512),
            0x14 => Ok(Stamp::Sha3512),
            0x15 => Ok(Stamp::Sha3384),
            0x16 => Ok(Stamp::Sha3256),
            0x17 => Ok(Stamp::Sha3224),
            0xb240 => Ok(Stamp::Blake2b512),
            0xb260 => Ok(Stamp::Blake2s256),
            _ => Err(StampError::Unknown),
        }
    }
}

impl From<Stamp> for Uvar {
    fn from(hash: Stamp) -> Uvar {
        match hash {
            Stamp::Sha1 => 0x11.into(),
            Stamp::Sha2256 => 0x12.into(),
            Stamp::Sha2512 => 0x13.into(),
            Stamp::Sha3512 => 0x14.into(),
            Stamp::Sha3384 => 0x15.into(),
            Stamp::Sha3256 => 0x16.into(),
            Stamp::Sha3224 => 0x17.into(),
            Stamp::Blake2b512 => 0xb240.into(),
            Stamp::Blake2s256 => 0xb260.into(),
        }
    }
}

impl From<Stamp> for String {
    fn from(hash: Stamp) -> String {
        let s: &str = hash.into();
        s.into()
    }
}

impl<'a> From<Stamp> for &'a str {
    fn from(hash: Stamp) -> &'a str {
        match hash {
            Stamp::Sha1 => "sha1",
            Stamp::Sha2256 => "sha2-256",
            Stamp::Sha2512 => "sha2-512",
            Stamp::Sha3512 => "sha3-512",
            Stamp::Sha3384 => "sha3-384",
            Stamp::Sha3256 => "sha3-256",
            Stamp::Sha3224 => "sha3-224",
            Stamp::Blake2b512 => "blake2b-512",
            Stamp::Blake2s256 => "blake2s-256",
        }
    }
}

impl<'a> From<&'a str> for Stamp {
    fn from(name: &str) -> Stamp {
        match name {
            "sha1" => Stamp::Sha1,
            "sha2-256" => Stamp::Sha2256,
            "sha2-512" => Stamp::Sha2512,
            "sha3-512" => Stamp::Sha3512,
            "sha3-384" => Stamp::Sha3384,
            "sha3-256" => Stamp::Sha3256,
            "sha3-224" => Stamp::Sha3224,
            "blake2b-512" => Stamp::Blake2b512,
            "blake2s-256" => Stamp::Blake2s256,
            _ => unimplemented!(),
        }
    }
}

impl FromStr for Stamp {
    type Err = StampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Stamp::Sha1),
            "sha2-256" => Ok(Stamp::Sha2256),
            "sha2-512" => Ok(Stamp::Sha2512),
            "sha3-512" => Ok(Stamp::Sha3512),
            "sha3-384" => Ok(Stamp::Sha3384),
            "sha3-256" => Ok(Stamp::Sha3256),
            "sha3-224" => Ok(Stamp::Sha3224),
            "blake2b-512" => Ok(Stamp::Blake2b512),
            "blake2s-256" => Ok(Stamp::Blake2s256),
            _ => Err(StampError::Unknown),
        }
    }
}

impl From<Stamp> for Bag {
    fn from(hash: Stamp) -> Bag {
        Bag {
            name: hash.clone().into(),
            code: hash.code(),
            length: hash.length(),
        }
    }
}

impl Multihash for Stamp {
    fn name(&self) -> &str {
        self.clone().into()
    }

    fn code(&self) -> Uvar {
        Uvar::from(self.clone())
    }

    fn length(&self) -> u8 {
        match self {
            Stamp::Sha1 => 20,
            Stamp::Sha2256 => 32,
            Stamp::Sha2512 => 64,
            Stamp::Sha3512 => 64,
            Stamp::Sha3384 => 48,
            Stamp::Sha3256 => 32,
            Stamp::Sha3224 => 28,
            Stamp::Blake2b512 => 64,
            Stamp::Blake2s256 => 32,
        }
    }
}
