// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use crypto_sha2::Digest;
use crypto_sha2::Sha256;
use digest::generic_array::typenum::U32;
use digest::generic_array::{ArrayLength, GenericArray};
use digest::FixedOutput;
use std::fmt;
use tag::Tag;

pub type Output<T> = GenericArray<u8, T>;

pub trait Multihash {
    type Hasher: Digest;
    fn digest(&self) -> Option<Output<<Self::Hasher as FixedOutput>::OutputSize>>;
}

#[derive(Clone, Debug)]
pub struct Hash<T: Digest> {
    name: String,
    function_type: u8,
    length: u8,
    digest: Option<Output<<T as FixedOutput>::OutputSize>>,
}

impl<T: Digest> fmt::Display for Hash<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &self.digest {
            None => Err(fmt::Error),
            Some(bytes) => {
                write!(formatter, "{:02x}", &self.function_type)?;
                write!(formatter, "{:02x}", &self.length)?;
                for byte in bytes.iter() {
                    write!(formatter, "{:02x}", byte)?;
                }

                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sha2256(Hash<Sha256>);

impl Sha2256 {
    pub fn new(digest: Option<Output<<Sha256 as FixedOutput>::OutputSize>>) -> Self {
        Sha2256(Hash {
            name: "sha2-256".to_string(),
            function_type: 0x12,
            length: 0x20,
            digest,
        })
    }

    pub fn digest(&self) -> Option<Output<<Sha256 as FixedOutput>::OutputSize>> {
        self.0.digest
    }
}

impl fmt::Display for Sha2256 {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

pub trait Blot {
    fn blot<Hasher: Digest + Clone>(&self, Hasher) -> Output<<Hasher as FixedOutput>::OutputSize>;

    fn sha2256(&self) -> Sha2256 {
        let output = self.blot(Sha256::default());
        Sha2256::new(Some(output))
    }
}

fn primitive<Hasher: Digest>(
    mut hasher: Hasher,
    tag: Tag,
    bytes: &[u8],
) -> Output<<Hasher as FixedOutput>::OutputSize> {
    hasher.input(&tag.to_bytes());
    hasher.input(bytes);
    hasher.result()
}

impl Blot for str {
    fn blot<Hasher: Digest + Clone>(
        &self,
        mut hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Unicode, self.as_bytes())
    }
}
