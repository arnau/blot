// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

pub trait Multihash {
    fn length(&self) -> u8;
    fn code(&self) -> u64; // uvar ranges from u8 to u64
    fn name(&self) -> &str;
}

/// A generic multihash bag.
///
/// Convenience representation to move the tuple {name, code, length} around.
#[derive(Clone)]
pub struct Bag {
    code: u64,
    name: &'static str,
    length: u8,
}

impl Multihash for Bag {
    fn code(&self) -> u64 {
        self.code
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
/// use blot::multihash::Tag;
///
/// let name: &str = Tag::Sha3512.into();
/// let code: u64 = Tag::Sha3512.into();
/// let length: u8 = Tag::Sha3512.length();
///
/// assert_eq!(name, "sha3-512");
/// assert_eq!(code, 0x14);
/// assert_eq!(length, 64);
/// ```
#[derive(Clone)]
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
    Blake2b256,
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
            0xb220 => Tag::Blake2b256,
            0xb240 => Tag::Blake2b512,
            0xb260 => Tag::Blake2s256,
            _ => unimplemented!(),
        }
    }
}

impl From<Tag> for u64 {
    fn from(hash: Tag) -> u64 {
        match hash {
            Tag::Sha1 => 0x11,
            Tag::Sha2256 => 0x12,
            Tag::Sha2512 => 0x13,
            Tag::Sha3512 => 0x14,
            Tag::Sha3384 => 0x15,
            Tag::Sha3256 => 0x16,
            Tag::Sha3224 => 0x17,
            Tag::Blake2b256 => 0xb220,
            Tag::Blake2b512 => 0xb240,
            Tag::Blake2s256 => 0xb260,
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
            Tag::Blake2b256 => "blake2b-256",
            Tag::Blake2b512 => "blake2b-512",
            Tag::Blake2s256 => "blake2s-256",
        }
    }
}

// TODO: Use FromStr instead
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
            "blake2b-256" => Tag::Blake2b256,
            "blake2b-512" => Tag::Blake2b512,
            "blake2s-256" => Tag::Blake2s256,
            _ => unimplemented!(),
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

impl Tag {
    pub fn name(&self) -> &str {
        self.clone().into()
    }

    pub fn code(&self) -> u64 {
        u64::from(self.clone())
    }

    pub fn length(&self) -> u8 {
        match self {
            Tag::Sha1 => 20,
            Tag::Sha2256 => 32,
            Tag::Sha2512 => 64,
            Tag::Sha3512 => 64,
            Tag::Sha3384 => 48,
            Tag::Sha3256 => 32,
            Tag::Sha3224 => 28,
            Tag::Blake2b256 => 32,
            Tag::Blake2b512 => 64,
            Tag::Blake2s256 => 32,
        }
    }
}
