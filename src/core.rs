// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>,
// at your option. This file may not be copied, modified, or distributed except
// according to those terms.

use crypto_sha2::Digest;
use digest::generic_array::{ArrayLength, GenericArray};
use digest::FixedOutput;
use tag::Tag;

pub type Output<T> = GenericArray<u8, T>;

pub trait Blot<Hasher: Digest> {
    fn blot(&self) -> Output<<Hasher as FixedOutput>::OutputSize>;

    fn primitive(&self, tag: Tag, bytes: &[u8]) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let mut hasher = Hasher::default();

        hasher.input(&tag.to_bytes());
        hasher.input(bytes);
        hasher.result()
    }
}
