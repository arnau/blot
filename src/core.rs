// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use crypto_sha2::Digest;
use crypto_sha2::{Sha256, Sha512};
use digest::generic_array::GenericArray;
use digest::FixedOutput;
use multihash;
use std::fmt;
use tag::Tag;

pub type Output<T> = GenericArray<u8, T>;

#[derive(Clone)]
pub struct Hash<T: Digest> {
    tag: multihash::Tag,
    digest: Option<Output<<T as FixedOutput>::OutputSize>>,
}

impl<Hasher: Digest> Hash<Hasher> {
    pub fn digest(&self) -> &Option<Output<<Hasher as FixedOutput>::OutputSize>> {
        &self.digest
    }
}

impl<T: Digest> fmt::Display for Hash<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &self.digest {
            None => Err(fmt::Error),
            Some(bytes) => {
                write!(formatter, "{:02x}", &self.tag.code())?;
                write!(formatter, "{:02x}", &self.tag.length())?;
                for byte in bytes.iter() {
                    write!(formatter, "{:02x}", byte)?;
                }

                Ok(())
            }
        }
    }
}

pub trait Blot {
    fn blot<Hasher: Digest + Clone>(&self, Hasher) -> Output<<Hasher as FixedOutput>::OutputSize>;

    fn sha2256(&self) -> Hash<Sha256> {
        let output = self.blot(Sha256::default());
        Hash {
            tag: multihash::Tag::Sha2256,
            digest: Some(output),
        }
    }

    fn sha2512(&self) -> Hash<Sha512> {
        let output = self.blot(Sha512::default());
        Hash {
            tag: multihash::Tag::Sha2512,
            digest: Some(output),
        }
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
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Unicode, self.as_bytes())
    }
}
