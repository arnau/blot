// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use core::{Blot, Output};
use digest::generic_array::GenericArray;
use digest::{Digest, FixedOutput};
use hex::{FromHex, FromHexError};
use multihash::{Tag, TagError};
use uvar::{Uvar, UvarError};

#[derive(Debug)]
pub enum SealError {
    NotRedacted,
    DigestTooShort,
    UnexpectedLength(Tag, u8),
    UvarParseError(UvarError),
    TagError(TagError),
    HexError(FromHexError),
}

impl From<UvarError> for SealError {
    fn from(err: UvarError) -> SealError {
        SealError::UvarParseError(err)
    }
}

impl From<TagError> for SealError {
    fn from(err: TagError) -> SealError {
        SealError::TagError(err)
    }
}

impl From<FromHexError> for SealError {
    fn from(err: FromHexError) -> SealError {
        SealError::HexError(err)
    }
}

/// 0x77 is equivalent to the original "**REDACTED**" mark.
pub const SEAL_MARK: u8 = 0x77;

#[derive(Debug, PartialEq)]
pub struct Seal {
    tag: Tag,
    digest: Vec<u8>,
}

impl Seal {
    pub fn digest_hex(&self) -> String {
        let mut result = String::new();

        for byte in &self.digest {
            result.push_str(&format!("{:02x}", byte));
        }

        result
    }

    pub fn from_str(raw: &str) -> Result<Seal, SealError> {
        if !raw.starts_with("**REDACTED**") {
            return Err(SealError::NotRedacted);
        }

        let bytes = Vec::from_hex(raw.get(12..).expect("REDACTED"))?;

        // TODO: Check 0x77
        Seal::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Seal, SealError> {
        let (code, rest) = Uvar::take(&bytes)?;
        let tag: Result<Tag, _> = code.into();

        match tag {
            Err(err) => Err(SealError::TagError(err)),
            Ok(tag) => {
                if rest.len() < 2 {
                    return Err(SealError::DigestTooShort);
                }

                let length = *&rest[0];
                let digest = &rest[1..];

                if length != tag.length() {
                    return Err(SealError::UnexpectedLength(tag, length));
                }

                if digest.len() as u8 != length {
                    return Err(SealError::UnexpectedLength(tag, digest.len() as u8));
                }

                Ok(Seal {
                    tag: tag,
                    digest: digest.into(),
                })
            }
        }
    }
}

impl Blot for Seal {
    fn blot<Hasher: Digest + Clone>(
        &self,
        _hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        GenericArray::from_slice(&self.digest).clone()
    }
}
