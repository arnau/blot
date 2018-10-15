// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

use digest::generic_array::GenericArray;
pub use digest::Digest;
use digest::FixedOutput;

use multihash::{Hash, Multihash};
use std;
use std::collections::{BTreeMap, HashMap, HashSet};
use tag::Tag;

pub type Output<T> = GenericArray<u8, T>;

// TODO: Explore a way to use Multihash instead of Digest and Tag
pub trait Blot {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize>;

    fn digest<T: Multihash>(&self, tag: T) -> Hash<T> {
        let hash = self.blot(tag.digester());
        let digest = hash.as_slice().to_vec();
        Hash::new(tag, digest)
    }
}

/// Hashes a list of bytes tagged with the given tag.
///
/// Plumbing function to implement `trait Blot` for new types.
///
/// ```
/// use blot::core;
/// use blot::tag::Tag;
/// use blot::digester::Sha2256;
///
/// core::primitive(Sha2256::default(), Tag::Unicode, "foo".as_bytes());
/// ```
pub fn primitive<Hasher: Digest + FixedOutput>(
    mut hasher: Hasher,
    tag: Tag,
    bytes: &[u8],
) -> Output<<Hasher as FixedOutput>::OutputSize> {
    hasher.input(&tag.to_bytes());
    hasher.input(bytes);
    hasher.result()
}

/// Hashes a list of lists of bytes tagged with the given tag.
///
/// Plumbing function to implement `trait Blot` for new types.
pub fn collection<Hasher: Digest + FixedOutput>(
    mut hasher: Hasher,
    tag: Tag,
    list: Vec<Vec<u8>>,
) -> Output<<Hasher as FixedOutput>::OutputSize> {
    hasher.input(&tag.to_bytes());
    for bytes in list {
        hasher.input(&bytes);
    }
    hasher.result()
}

impl<'a, T: ?Sized + Blot> Blot for &'a T {
    #[inline]
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        T::blot(*self, hasher)
    }
}

impl Blot for str {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Unicode, self.as_bytes())
    }
}

impl Blot for String {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Unicode, self.as_bytes())
    }
}

impl Blot for [u8] {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        primitive(hasher, Tag::Raw, self)
    }
}

impl<'a, T: Blot> Blot for Option<T> {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
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
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let string = if *self { "1" } else { "0" };
        primitive(hasher, Tag::Bool, string.as_bytes())
    }
}

macro_rules! blot_integer (($type:ident) => {
    impl Blot for $type {
        fn blot<Hasher: Digest + FixedOutput + Clone>(
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
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let mut h = hasher.clone();
        h.input(&Tag::List.to_bytes());

        for el in self {
            h.input(el.blot(hasher.clone()).as_slice())
        }

        h.result()
    }
}

impl<T: Blot + Eq + std::hash::Hash> Blot for HashSet<T> {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let mut list: Vec<Vec<u8>> = self
            .iter()
            .map(|item| {
                item.blot(hasher.clone())
                    .as_slice()
                    .iter()
                    .map(|x| *x)
                    .collect::<Vec<u8>>()
            }).collect();

        list.sort_unstable();

        collection(hasher, Tag::Set, list)
    }
}

impl<K, V> Blot for HashMap<K, V>
where
    K: Blot + Eq + std::hash::Hash,
    V: Blot + PartialEq,
{
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let mut list: Vec<Vec<u8>> = self
            .iter()
            .map(|(k, v)| {
                let mut res: Vec<u8> = Vec::with_capacity(64);
                res.extend_from_slice(k.blot(hasher.clone()).as_slice());
                res.extend_from_slice(v.blot(hasher.clone()).as_slice());

                res
            }).collect();

        list.sort_unstable();

        collection(hasher, Tag::Dict, list)
    }
}

impl<K, V> Blot for BTreeMap<K, V>
where
    K: Blot + Eq + std::hash::Hash,
    V: Blot + PartialEq,
{
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        let mut list: Vec<Vec<u8>> = self
            .iter()
            .map(|(k, v)| {
                let mut res: Vec<u8> = Vec::with_capacity(64);
                res.extend_from_slice(k.blot(hasher.clone()).as_slice());
                res.extend_from_slice(v.blot(hasher.clone()).as_slice());

                res
            }).collect();

        list.sort_unstable();

        collection(hasher, Tag::Dict, list)
    }
}

impl Blot for f32 {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        (*self as f64).blot(hasher)
    }
}

impl Blot for f64 {
    fn blot<Hasher: Digest + FixedOutput + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        if self.is_nan() {
            primitive(hasher, Tag::Float, "NaN".as_bytes())
        } else if self.is_infinite() {
            let s = if self.is_sign_negative() {
                "-Infinity"
            } else {
                "Infinity"
            };
            primitive(hasher, Tag::Float, s.as_bytes())
        } else {
            primitive(hasher, Tag::Float, float_normalize(*self).as_bytes())
        }
    }
}

pub fn float_normalize(mut f: f64) -> String {
    if f == 0.0 {
        return "+0:".to_owned();
    }

    let mut s = String::new();

    // sign
    if f < 0. {
        s.push('-');
        f = -f;
    } else {
        s.push('+');
    }

    // exponent
    let mut e = 0;

    while f > 1. {
        f = f / 2.;
        e = e + 1;
    }

    while f <= 0.5 {
        f = f * 2.;
        e = e - 1;
    }

    s.push_str(&e.to_string());
    s.push(':');

    // mantissa
    assert!(f <= 1.);
    assert!(f > 0.5);
    // TODO: Return Result

    while f != 0. {
        if f >= 1. {
            s.push('1');
            f = f - 1.;
        } else {
            s.push('0');
        }

        assert!(f < 1.);
        assert!(s.len() < 1000);

        f = f * 2.;
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use multihash::Sha2256;

    #[test]
    fn bool_blot_raw() {
        let expected = "7dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193";
        let actual = true.digest(Sha2256);

        assert_eq!(format!("{}", actual.digest()), expected);
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
            let actual = format!("{}", raw.digest(Sha2256));
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn null_blot() {
        let expected = "12201b16b1df538ba12dc3f97edbb85caa7050d46c148134290feba80f8236c83db9";
        let actual = format!("{}", None::<String>.digest(Sha2256));

        assert_eq!(actual, expected);
    }

    #[test]
    fn raw_blot() {
        let expected = "1220e318859db4d2acc89c0d503ddbcf8331625125a79018d19cf8f8d1336b7eb39e";
        let bytes =
            Vec::from_hex("6b18693874513ba13da54d61aafa7cad0c8f5573f3431d6f1c04b07ddb27d6bb")
                .unwrap();
        let actual = format!("{}", (&bytes[..]).digest(Sha2256));
        assert_eq!(actual, expected);
    }

    #[test]
    fn bool_blot() {
        assert_eq!(
            format!("{}", true.digest(Sha2256)),
            "12207dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193"
        );
        assert_eq!(
            format!("{}", false.digest(Sha2256)),
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
            let actual = format!("{}", raw.digest(Sha2256));
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn zero_float_blot() {
        let expected = "122060101d8c9cb988411468e38909571f357daa67bff5a7b0a3f9ae295cd4aba33d";
        let actual = format!("{}", 0.0.digest(Sha2256));
        assert_eq!(actual, expected);
    }
    #[test]
    fn float_blot() {
        use std::f64;
        let pairs = [
            (
                -0.0,
                "122060101d8c9cb988411468e38909571f357daa67bff5a7b0a3f9ae295cd4aba33d",
            ),
            (
                f64::NAN,
                "12205d6c301a98d835732d459d7018a8d546872f7ba3c39a45ba481746d2c6d566d9",
            ),
            (
                f64::INFINITY,
                "1220e0309b2362dc6aaf595338cd9e116761640f74927bcdc4f76e8e6433738f25c7",
            ),
            (
                f64::NEG_INFINITY,
                "12201167518d5554ba86d9b176af0a57f29d425bedaa9847c245cc397b37533228f7",
            ),
        ];
        for (raw, expected) in pairs.iter() {
            let actual = format!("{}", raw.digest(Sha2256));
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn empty_list_blot() {
        let expected = "1220acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0";
        let list: Vec<u8> = vec![];
        let actual = format!("{}", list.digest(Sha2256));
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
            let actual = format!("{}", raw.digest(Sha2256));
            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn empty_set_blot() {
        let expected = "1220043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89";
        let set: HashSet<u8> = HashSet::new();
        let actual = format!("{}", set.digest(Sha2256));
        assert_eq!(actual, expected);
    }

    #[test]
    fn set_blot() {
        let expected = "1220a4fef47742c80337b2eb0dcc6ed36610c93aca0afef86a65f381020b9de2284d";
        let mut set: HashSet<&str> = HashSet::new();
        set.insert("foo");
        let actual = format!("{}", set.digest(Sha2256));
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty_dict_blot() {
        let expected = "122018ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4";
        let dict: HashMap<&str, u8> = HashMap::new();
        let actual = format!("{}", dict.digest(Sha2256));
        assert_eq!(actual, expected);
    }

    #[test]
    fn dict_blot() {
        let expected = "12207ef5237c3027d6c58100afadf37796b3d351025cf28038280147d42fdc53b960";
        let mut dict: HashMap<&str, &str> = HashMap::new();
        dict.insert("foo", "bar");
        let actual = format!("{}", dict.digest(Sha2256));
        assert_eq!(actual, expected);
    }
}
