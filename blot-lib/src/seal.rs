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
use multihash::Multihash;
use uvar::{Uvar, UvarError};

#[derive(Debug)]
pub enum SealError {
    InvalidStamp { actual: Uvar, expected: Uvar },
    NotRedacted,
    DigestTooShort,
    UnexpectedLength { actual: u8, expected: u8 },
    UvarParseError(UvarError),
    HexError(FromHexError),
}

impl From<UvarError> for SealError {
    fn from(err: UvarError) -> SealError {
        SealError::UvarParseError(err)
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
pub struct Seal<T: Multihash> {
    tag: T,
    digest: Vec<u8>,
}

impl<T: Multihash> Seal<T> {
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    pub fn tag(&self) -> &T {
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
    /// use blot::seal::Seal;
    /// use blot::multihash::{Multihash, Sha2256};
    ///
    /// let seal_classic: Result<Seal<Sha2256>, _> = Seal::from_str("**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038");
    /// let seal: Result<Seal<Sha2256>, _> = Seal::from_str("771220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038");
    ///
    /// assert!(seal_classic.is_ok());
    /// assert!(seal.is_ok());
    /// assert_eq!(seal.unwrap(), seal_classic.unwrap());
    /// ```
    pub fn from_str(input: &str) -> Result<Seal<T>, SealError> {
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
    /// use blot::seal::Seal;
    /// use blot::multihash::{Multihash, Sha2256};
    /// use hex::FromHex;
    ///
    /// let bytes = Vec::from_hex("771220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038").unwrap();
    /// let seal: Result<Seal<Sha2256>, _> = Seal::from_bytes(&bytes);
    ///
    /// assert!(seal.is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// This operation fails with [`SealError::NotRedacted`] if the first byte is not `0x77`, the
    /// seal mark.
    pub fn from_bytes(bytes: &[u8]) -> Result<Seal<T>, SealError> {
        if bytes[0] != SEAL_MARK {
            return Err(SealError::NotRedacted);
        }

        Seal::from_bytes_without_mark(&bytes[1..])
    }

    fn from_bytes_without_mark(bytes: &[u8]) -> Result<Seal<T>, SealError> {
        let (code, rest) = Uvar::take(&bytes)?;
        let tag = T::default();

        if tag.code() != code {
            return Err(SealError::InvalidStamp {
                actual: code,
                expected: tag.code(),
            });
        }

        if rest.len() < 2 {
            return Err(SealError::DigestTooShort);
        }

        let length = *&rest[0];
        let digest = &rest[1..];

        if length != tag.length() {
            return Err(SealError::UnexpectedLength {
                expected: tag.length(),
                actual: length,
            });
        }

        if digest.len() as u8 != length {
            return Err(SealError::UnexpectedLength {
                expected: tag.length(),
                actual: digest.len() as u8,
            });
        }

        Ok(Seal {
            tag: tag,
            digest: digest.into(),
        })
    }
}

impl<T: Multihash> Blot for Seal<T> {
    fn blot<Hasher: Digest + Clone + FixedOutput>(
        &self,
        _hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        GenericArray::from_slice(&self.digest).clone()
    }
}
