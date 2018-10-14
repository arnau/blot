// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Sealed digest multihash.
//!
//! Type [`Seal`] represents a sealed digest multihash.

use core::{Blot, Output};
use digest::generic_array::GenericArray;
use digest::{Digest, FixedOutput};
use hex::{FromHex, FromHexError};
use multihash::{Multihash, Stamp, StampError};
use uvar::{Uvar, UvarError};

#[derive(Debug)]
pub enum SealError {
    NotRedacted,
    DigestTooShort,
    UnexpectedLength(Stamp, u8),
    UvarParseError(UvarError),
    StampError(StampError),
    HexError(FromHexError),
}

impl From<UvarError> for SealError {
    fn from(err: UvarError) -> SealError {
        SealError::UvarParseError(err)
    }
}

impl From<StampError> for SealError {
    fn from(err: StampError) -> SealError {
        SealError::StampError(err)
    }
}

impl From<FromHexError> for SealError {
    fn from(err: FromHexError) -> SealError {
        SealError::HexError(err)
    }
}

/// 0x77 is equivalent to the original `**REDACTED**` mark.
pub const SEAL_MARK: u8 = 0x77;

/// The `Seal` type. See [the module level documentation](index.html) for more.
#[derive(Clone, Debug, PartialEq)]
pub struct Seal {
    tag: Stamp,
    digest: Vec<u8>,
}

impl Seal {
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    pub fn tag(&self) -> &Stamp {
        &self.tag
    }

    pub fn digest_hex(&self) -> String {
        let mut result = String::new();

        for byte in &self.digest {
            result.push_str(&format!("{:02x}", byte));
        }

        result
    }

    /// Creates a `Seal` from a string. The string must have either the Objecthash prefix
    /// `**REDACTED**` or the blot [`SEAL_MARK`].
    ///
    /// You can use [`from_bytes`] if you have a list of bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate blot;
    /// # use blot::seal::Seal;
    /// let seal_classic = Seal::from_str("**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038");
    /// let seal = Seal::from_str("771220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038");
    ///
    /// assert!(seal_classic.is_ok());
    /// assert!(seal.is_ok());
    /// assert_eq!(seal.unwrap(), seal_classic.unwrap());
    /// ```
    pub fn from_str(input: &str) -> Result<Seal, SealError> {
        let bare = if input.starts_with("**REDACTED**") {
            input
                .get(12..)
                .expect("Expected a redacted hash starting with `**REDACTED**`")
        } else if input.starts_with("77") {
            input
                .get(2..)
                .expect("Expected a redacted hash starting with `0x77`")
        } else {
            return Err(SealError::NotRedacted);
        };

        let bytes = Vec::from_hex(bare)?;

        Seal::from_bytes_without_mark(&bytes)
    }

    /// Creates a `Seal` from a list of bytes. The first byte must be the
    /// [`SEAL_MARK`].
    ///
    /// You can use [`from_str`] if your redacted hash uses the original Objecthash `"**REDACTED**"` prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate hex;
    /// # extern crate blot;
    /// # use blot::seal::Seal;
    /// # use hex::FromHex;
    /// let bytes = Vec::from_hex("771220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038").unwrap();
    /// let seal = Seal::from_bytes(&bytes);
    ///
    /// assert!(seal.is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// This operation fails with [`SealError::NotRedacted`] if the first byte is not `0x77`, the
    /// seal mark.
    pub fn from_bytes(bytes: &[u8]) -> Result<Seal, SealError> {
        if bytes[0] != SEAL_MARK {
            return Err(SealError::NotRedacted);
        }

        Seal::from_bytes_without_mark(&bytes[1..])
    }

    fn from_bytes_without_mark(bytes: &[u8]) -> Result<Seal, SealError> {
        let (code, rest) = Uvar::take(&bytes)?;
        let tag: Result<Stamp, _> = code.into();

        match tag {
            Err(err) => Err(SealError::StampError(err)),
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
    fn blot<Hasher: Digest + Clone + FixedOutput>(
        &self,
        _hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        GenericArray::from_slice(&self.digest).clone()
    }
}
