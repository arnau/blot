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
use std;
use std::collections::HashSet;
use std::fmt;
use tag::Tag;

pub type Output<T> = GenericArray<u8, T>;

#[derive(Clone, Debug, PartialEq, Eq)]
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

// TODO: Explore a way to use Multihash instead of Digest and Tag
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

impl<'a, T: ?Sized + Blot> Blot for &'a T {
    #[inline]
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        T::blot(*self, hasher)
    }
}

impl Blot for str {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Unicode, self.as_bytes())
    }
}

impl Blot for String {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Unicode, self.as_bytes())
    }
}

impl<'a> Blot for &'a [u8] {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Raw, self)
    }
}

impl<'a, T: Blot> Blot for Option<T> {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        match self {
            None => primitive(hasher, Tag::Null, "".as_bytes()),
            Some(a) => a.blot(hasher),
        }
    }
}

impl<'a> Blot for bool {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let string = if *self { "1" } else { "0" };
        primitive(hasher, Tag::Bool, string.as_bytes())
    }
}

macro_rules! blot_integer (($type:ident) => {
 impl Blot for $type {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Integer, self.to_string().as_bytes())
    }
}

});

blot_integer!(u8);
blot_integer!(u16);
blot_integer!(u32);
blot_integer!(u64);
blot_integer!(usize);
blot_integer!(i8);
blot_integer!(i16);
blot_integer!(i32);
blot_integer!(i64);
blot_integer!(isize);

impl<T: Blot> Blot for Vec<T> {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let xs: Vec<u8> = self
            .iter()
            .flat_map(|item| item.blot(hasher.clone()))
            .collect();

        primitive(hasher, Tag::List, &xs)
    }
}

// TODO: Explore alternative with fewer gymnastics
impl<T: Blot + Eq + std::hash::Hash> Blot for HashSet<T> {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let mut xs: Vec<Vec<u8>> = self
            .iter()
            .map(|item| {
                item.blot(hasher.clone())
                    .as_slice()
                    .iter()
                    .map(|x| *x)
                    .collect::<Vec<u8>>()
            }).collect();

        xs.sort_unstable();

        let bytes: Vec<u8> = xs.iter().flat_map(|x| x.clone()).collect();

        primitive(hasher, Tag::Set, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::generic_array::typenum::U32;

    // Test helper
    fn hash2256_from_slice(slice: &[u8]) -> Hash<Sha256> {
        let digest = *GenericArray::<u8, U32>::from_slice(slice);
        Hash {
            tag: multihash::Tag::Sha2256,
            digest: Some(digest),
        }
    }

    #[test]
    fn unicode_blot_raw() {
        let expected = hash2256_from_slice(&vec![
            166, 166, 229, 231, 131, 195, 99, 205, 149, 105, 62, 193, 137, 194, 104, 35, 21, 217,
            86, 134, 147, 151, 115, 134, 121, 181, 99, 5, 242, 9, 80, 56,
        ]);
        let actual = "foo".sha2256();

        assert_eq!(actual.tag, expected.tag);
        assert_eq!(actual.digest, expected.digest);
    }

    #[test]
    fn bool_blot_raw() {
        let expected = hash2256_from_slice(
            &hex!("7dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193")[..],
        );
        let actual = true.sha2256();

        assert_eq!(actual.tag, expected.tag);
        assert_eq!(actual.digest, expected.digest);
    }

    #[test]
    fn unicode_blot() {
        let pairs = [
            (
                "ԱԲաբ",
                "12202a2a4485a4e338d8df683971956b1090d2f5d33955a81ecaad1a75125f7a316c",
            ),
            (
                "ϓ",
                "1220f72826713a01881404f34975447bd6edcb8de40b191dc57097ebf4f5417a554d",
            ),
            (
                "foo",
                "1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038",
            ),
        ];
        for (raw, expected) in pairs.iter() {
            let actual = format!("{}", raw.sha2256());
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn null_blot() {
        let expected = "12201b16b1df538ba12dc3f97edbb85caa7050d46c148134290feba80f8236c83db9";
        let actual = format!("{}", None::<String>.sha2256());

        assert_eq!(actual, expected);
    }

    #[test]
    fn raw_blot() {
        let expected = "1220e318859db4d2acc89c0d503ddbcf8331625125a79018d19cf8f8d1336b7eb39e";
        let bytes = hex!("6b18693874513ba13da54d61aafa7cad0c8f5573f3431d6f1c04b07ddb27d6bb");
        let actual = format!("{}", (&bytes[..]).sha2256());
        assert_eq!(actual, expected);
    }

    #[test]
    fn bool_blot() {
        assert_eq!(
            format!("{}", true.sha2256()),
            "12207dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193"
        );
        assert_eq!(
            format!("{}", false.sha2256()),
            "1220c02c0b965e023abee808f2b548d8d5193a8b5229be6f3121a6f16e2d41a449b3"
        );
    }

    #[test]
    fn int_blot() {
        let pairs = [
            (
                0,
                "1220a4e167a76a05add8a8654c169b07b0447a916035aef602df103e8ae0fe2ff390",
            ),
            (
                42,
                "1220ebc35dc1b8e2602b72beb8d8e5bcdb2babe90f57bcb54ad7282ec798659d2196",
            ),
        ];
        for (raw, expected) in pairs.iter() {
            let actual = format!("{}", raw.sha2256());
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn empty_list_blot() {
        let expected = "1220acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0";
        let list: Vec<u8> = vec![];
        let actual = format!("{}", list.sha2256());
        assert_eq!(actual, expected);
    }

    #[test]
    fn list_blot() {
        let pairs = [
            (
                vec!["foo"],
                "1220268bc27d4974d9d576222e4cdbb8f7c6bd6791894098645a19eeca9c102d0964",
            ),
            (
                vec!["foo", "bar"],
                "122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2",
            ),
        ];
        for (raw, expected) in pairs.iter() {
            let actual = format!("{}", raw.sha2256());
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn empty_set_blot() {
        let expected = "1220043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89";
        let set: HashSet<u8> = HashSet::new();
        let actual = format!("{}", set.sha2256());
        assert_eq!(actual, expected);
    }

    #[test]
    fn set_blot() {
        let expected = "1220a4fef47742c80337b2eb0dcc6ed36610c93aca0afef86a65f381020b9de2284d";
        let mut set: HashSet<&str> = HashSet::new();
        set.insert("foo");
        let actual = format!("{}", set.sha2256());
        assert_eq!(actual, expected);
    }

    // #[test]
    // fn empty_dict_blot() {
    //     let expected = "122018ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4";
    //     let dict: HashMap<&str, u8> = HashSet::new();
    //     let actual = format!("{}", dict.sha2256());
    //     assert_eq!(actual, expected);
    // }

    // #[test]
    // fn dict_blot() {
    //     let expected = "12207ef5237c3027d6c58100afadf37796b3d351025cf28038280147d42fdc53b960";
    //     let mut dict: HashMap<&str, &str> = HashSet::new();
    //     dict.insert("foo", "bar");
    //     let actual = format!("{}", dict.sha2256());
    //     assert_eq!(actual, expected);
    // }
}
