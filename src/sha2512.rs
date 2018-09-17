// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>,
// at your option. This file may not be copied, modified, or distributed except
// according to those terms.

use crypto_sha2::Sha512;
use digest::generic_array::typenum::U64;

use core::{Blot, Output};
use tag::Tag;

pub type Sha2512 = Sha512;

impl Blot<Sha2512> for str {
    fn blot(&self) -> Output<U64> {
        Blot::<Sha2512>::primitive(self, Tag::Unicode, self.as_bytes())
    }
}

impl Blot<Sha2512> for String {
    fn blot(&self) -> Output<U64> {
        Blot::<Sha2512>::primitive(self, Tag::Unicode, self.as_bytes())
    }
}

macro_rules! impl_integer (($type:ident) => (
    impl Blot<Sha2512> for $type {
        fn blot(&self) -> Output<U64> {
            Blot::<Sha2512>::primitive(self, Tag::Integer, self.to_string().as_bytes())
        }
    }
));

impl_integer!(i16);
impl_integer!(i32);
impl_integer!(i64);
impl_integer!(i8);
impl_integer!(isize);
impl_integer!(u16);
impl_integer!(u32);
impl_integer!(u64);
impl_integer!(u8);
impl_integer!(usize);
