// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use ansi_term::Colour::{Black, Fixed};
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
    tag: Tag,
    digest: Digest,
}

impl Hash {
    pub fn new<T: Into<Digest>>(tag: Tag, digest: T) -> Hash {
        Hash {
            tag,
            digest: digest.into(),
        }
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest.as_slice()
    }

    pub fn tag(&self) -> &Tag {
        &self.tag
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        if formatter.alternate() {
            let code = format!("{:02x}", &self.tag.code());
            let length = format!("{:02x}", &self.tag.length());
            let digest = format!("{}", &self.digest);

            write!(formatter, "{}", Black.on(Fixed(198)).paint(code))?;
            write!(formatter, "{}", Black.on(Fixed(39)).paint(length))?;
            write!(formatter, "{}", Fixed(221).on(Black).paint(digest))?;
        } else {
            write!(formatter, "{:02x}", &self.tag.code())?;
            write!(formatter, "{:02x}", &self.tag.length())?;
            write!(formatter, "{}", &self.digest)?;
        }

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

/// A known multihash tag.
///
/// For example, the SHA3-512 tag is:
///
/// ```
/// use blot::multihash::{Tag, Multihash};
/// use blot::uvar::Uvar;
///
/// let name: &str = Tag::Sha3512.into();
/// let code: Uvar = Tag::Sha3512.into();
/// let length: u8 = Tag::Sha3512.length();
///
/// assert_eq!(name, "sha3-512");
/// assert_eq!(code, Uvar::new(vec![0x14]));
/// assert_eq!(length, 64);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Tag {
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

impl From<u64> for Tag {
    fn from(code: u64) -> Tag {
        match code {
            0x11 => Tag::Sha1,
            0x12 => Tag::Sha2256,
            0x13 => Tag::Sha2512,
            0x14 => Tag::Sha3512,
            0x15 => Tag::Sha3384,
            0x16 => Tag::Sha3256,
            0x17 => Tag::Sha3224,
            // 0xb220 => Tag::Blake2b256,
            0xb240 => Tag::Blake2b512,
            0xb260 => Tag::Blake2s256,
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum TagError {
    Unknown,
}

impl From<Uvar> for Result<Tag, TagError> {
    fn from(code: Uvar) -> Result<Tag, TagError> {
        let n: u64 = code.into();

        match n {
            0x11 => Ok(Tag::Sha1),
            0x12 => Ok(Tag::Sha2256),
            0x13 => Ok(Tag::Sha2512),
            0x14 => Ok(Tag::Sha3512),
            0x15 => Ok(Tag::Sha3384),
            0x16 => Ok(Tag::Sha3256),
            0x17 => Ok(Tag::Sha3224),
            0xb240 => Ok(Tag::Blake2b512),
            0xb260 => Ok(Tag::Blake2s256),
            _ => Err(TagError::Unknown),
        }
    }
}

impl From<Tag> for Uvar {
    fn from(hash: Tag) -> Uvar {
        match hash {
            Tag::Sha1 => 0x11.into(),
            Tag::Sha2256 => 0x12.into(),
            Tag::Sha2512 => 0x13.into(),
            Tag::Sha3512 => 0x14.into(),
            Tag::Sha3384 => 0x15.into(),
            Tag::Sha3256 => 0x16.into(),
            Tag::Sha3224 => 0x17.into(),
            // Tag::Blake2b256 => 0xb220,
            Tag::Blake2b512 => 0xb240.into(),
            Tag::Blake2s256 => 0xb260.into(),
        }
    }
}

impl From<Tag> for String {
    fn from(hash: Tag) -> String {
        let s: &str = hash.into();
        s.into()
    }
}

impl<'a> From<Tag> for &'a str {
    fn from(hash: Tag) -> &'a str {
        match hash {
            Tag::Sha1 => "sha1",
            Tag::Sha2256 => "sha2-256",
            Tag::Sha2512 => "sha2-512",
            Tag::Sha3512 => "sha3-512",
            Tag::Sha3384 => "sha3-384",
            Tag::Sha3256 => "sha3-256",
            Tag::Sha3224 => "sha3-224",
            // Tag::Blake2b256 => "blake2b-256",
            Tag::Blake2b512 => "blake2b-512",
            Tag::Blake2s256 => "blake2s-256",
        }
    }
}

impl<'a> From<&'a str> for Tag {
    fn from(name: &str) -> Tag {
        match name {
            "sha1" => Tag::Sha1,
            "sha2-256" => Tag::Sha2256,
            "sha2-512" => Tag::Sha2512,
            "sha3-512" => Tag::Sha3512,
            "sha3-384" => Tag::Sha3384,
            "sha3-256" => Tag::Sha3256,
            "sha3-224" => Tag::Sha3224,
            // "blake2b-256" => Tag::Blake2b256,
            "blake2b-512" => Tag::Blake2b512,
            "blake2s-256" => Tag::Blake2s256,
            _ => unimplemented!(),
        }
    }
}

impl FromStr for Tag {
    type Err = TagError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Tag::Sha1),
            "sha2-256" => Ok(Tag::Sha2256),
            "sha2-512" => Ok(Tag::Sha2512),
            "sha3-512" => Ok(Tag::Sha3512),
            "sha3-384" => Ok(Tag::Sha3384),
            "sha3-256" => Ok(Tag::Sha3256),
            "sha3-224" => Ok(Tag::Sha3224),
            "blake2b-512" => Ok(Tag::Blake2b512),
            "blake2s-256" => Ok(Tag::Blake2s256),
            _ => Err(TagError::Unknown),
        }
    }
}

impl From<Tag> for Bag {
    fn from(hash: Tag) -> Bag {
        Bag {
            name: hash.clone().into(),
            code: hash.code(),
            length: hash.length(),
        }
    }
}

impl Multihash for Tag {
    fn name(&self) -> &str {
        self.clone().into()
    }

    fn code(&self) -> Uvar {
        Uvar::from(self.clone())
    }

    fn length(&self) -> u8 {
        match self {
            Tag::Sha1 => 20,
            Tag::Sha2256 => 32,
            Tag::Sha2512 => 64,
            Tag::Sha3512 => 64,
            Tag::Sha3384 => 48,
            Tag::Sha3256 => 32,
            Tag::Sha3224 => 28,
            Tag::Blake2b512 => 64,
            Tag::Blake2s256 => 32,
        }
    }
}
