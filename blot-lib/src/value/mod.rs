// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

//use std::fmt::{self, Display};

//use core::{collection, primitive, Blot, Output};
//use digest::{Digest, FixedOutput};
//use multihash::Multihash;
//use seal::Seal;
//use std::collections::HashMap;
//use tag::Tag;

//pub mod de;

//// TODO: Hack to generate a value with all sequences as sets instead of lists.
////
//// See `de.rs` for more details.
//#[derive(Clone, Debug, PartialEq)]
//pub struct ValueSet<T: Multihash>(Value<T>);

//impl<T: Multihash> ValueSet<T> {
//    pub fn to_value(self) -> Value<T> {
//        self.0
//    }
//}

//#[derive(Clone, Debug, PartialEq)]
//pub enum Value<T: Multihash> {
//    Null,
//    Bool(bool),
//    Integer(i64),
//    Float(f64),
//    String(String),
//    Timestamp(String),
//    Redacted(Seal<T>),
//    Raw(Vec<u8>),
//    List(Vec<Value<T>>),
//    Set(Vec<Value<T>>),
//    Dict(HashMap<String, Value<T>>),
//}

//#[derive(Debug)]
//pub enum ValueError {
//    Unknown,
//}

//impl Display for ValueError {
//    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//        write!(formatter, "{:?}", self)
//    }
//}

//impl<T: Multihash> Blot for Value<T> {
//    fn blot<Hasher: Digest + FixedOutput + Clone>(
//        &self,
//        hasher: Hasher,
//    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
//        match self {
//            Value::Null => None::<u8>.blot(hasher.clone()),
//            Value::Bool(raw) => raw.blot(hasher.clone()),
//            Value::Integer(raw) => raw.blot(hasher.clone()),
//            Value::Float(raw) => raw.blot(hasher.clone()),
//            Value::String(raw) => raw.blot(hasher.clone()),
//            Value::Timestamp(raw) => primitive(hasher.clone(), Tag::Timestamp, raw.as_bytes()),
//            Value::Redacted(raw) => raw.blot(hasher.clone()),
//            Value::Raw(raw) => raw.as_slice().blot(hasher.clone()),
//            Value::List(raw) => raw.blot(hasher.clone()),
//            Value::Set(raw) => {
//                let mut list: Vec<Vec<u8>> = raw
//                    .iter()
//                    .map(|item| {
//                        item.blot(hasher.clone())
//                            .as_slice()
//                            .iter()
//                            .map(|x| *x)
//                            .collect::<Vec<u8>>()
//                    }).collect();

//                list.sort_unstable();
//                list.dedup();

//                collection(hasher, Tag::Set, list)
//            }
//            Value::Dict(raw) => raw.blot(hasher.clone()),
//        }
//    }
//}

//#[macro_export]
//macro_rules! set {
//    ( $( $x:expr ),* ) => {
//        {
//            let mut temp_vec: Vec<Value> = Vec::new();
//            $(
//                temp_vec.push($x.into());
//            )*
//            Value::Set(temp_vec)
//        }
//    };
//}

//#[macro_export]
//macro_rules! raw {
//    ($input:expr) => {{
//        Vec::from_hex($input).map(|hash| Value::Raw(hash))
//    }};
//}

//#[macro_export]
//macro_rules! list {
//    ( $( $x:expr ),* ) => {
//        {
//            let mut temp_vec: Vec<Value> = Vec::new();
//            $(
//                temp_vec.push($x.into());
//            )*
//            Value::List(temp_vec)
//        }
//    };
//}

//impl<'a, T: Multihash> From<&'a str> for Value<T> {
//    fn from(raw: &str) -> Value<T> {
//        Value::String(raw.into())
//    }
//}

//impl<'a, T: Multihash> From<String> for Value<T> {
//    fn from(raw: String) -> Value<T> {
//        Value::String(raw)
//    }
//}

//impl<T: Multihash> From<i64> for Value<T> {
//    fn from(raw: i64) -> Value<T> {
//        Value::Integer(raw)
//    }
//}

//impl<T: Multihash> From<f64> for Value<T> {
//    fn from(raw: f64) -> Value<T> {
//        Value::Float(raw)
//    }
//}

//impl<T: Multihash> From<Vec<Value<T>>> for Value<T> {
//    fn from(raw: Vec<Value<T>>) -> Value<T> {
//        Value::List(raw)
//    }
//}

//impl<T: Multihash> From<Seal<T>> for Value<T> {
//    fn from(raw: Seal<T>) -> Value<T> {
//        Value::Redacted(raw)
//    }
//}

//#[cfg(test)]
//mod tests {
//    use super::*;
//    use multihash::Stamp;

//    #[test]
//    fn common() {
//        let expected = "122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2";
//        let value: Value = vec!["foo".into(), "bar".into()].into();
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));

//        assert_eq!(actual, expected);
//    }

//    #[test]
//    fn int_list() {
//        let pairs = [
//            (
//                list![123],
//                "12201b93f704451e1a7a1b8c03626ffcd6dec0bc7ace947ff60d52e1b69b4658ccaa",
//            ),
//            (
//                list![1, 2, 3],
//                "1220157bf16c70bd4c9673ffb5030552df0ee2c40282042ccdf6167850edc9044ab7",
//            ),
//            (
//                list![123456789012345],
//                "12203488b9bc37cce8223a032760a9d4ef488cdfebddd9e1af0b31fcd1d7006369a4",
//            ),
//            (
//                list![123456789012345, 678901234567890],
//                "1220031ef1aaeccea3bced3a1c6237a4fc00ed4d629c9511922c5a3f4e5c128b0ae4",
//            ),
//        ];

//        for (value, expected) in pairs.iter() {
//            let actual = format!("{}", &value.digest(Stamp::Sha2256));

//            assert_eq!(&actual, expected);
//        }
//    }

//    #[test]
//    fn floats() {
//        let mut map: HashMap<String, Value> = HashMap::new();
//        map.insert(
//            "bar".into(),
//            list![
//                "baz",
//                Value::Null,
//                1.0,
//                1.5,
//                0.0001,
//                1000.0,
//                2.0,
//                -23.1234,
//                2.0
//            ],
//        );
//        let value = list!["foo", Value::Dict(map)];
//        let expected = "1220783a423b094307bcb28d005bc2f026ff44204442ef3513585e7e73b66e3c2213";
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));

//        assert_eq!(&actual, expected);
//    }

//    #[test]
//    fn int_floats() {
//        let mut map: HashMap<String, Value> = HashMap::new();
//        map.insert(
//            "bar".into(),
//            vec![
//                "baz".into(),
//                Value::Null,
//                1.into(),
//                1.5.into(),
//                0.0001.into(),
//                1000.into(),
//                2.into(),
//                (-23.1234).into(),
//                2.into(),
//            ].into(),
//        );
//        let value = Value::List(vec!["foo".into(), Value::Dict(map)]);
//        let expected = "1220726e7ae9e3fadf8a2228bf33e505a63df8db1638fa4f21429673d387dbd1c52a";
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));

//        assert_eq!(&actual, expected);
//    }

//    #[test]
//    fn set() {
//        let mut map: HashMap<String, Value> = HashMap::new();
//        let mut map2: HashMap<String, Value> = HashMap::new();
//        map2.insert(
//            "thing2".into(),
//            Value::Set(vec![1.into(), 2.into(), "s".into()]),
//        );
//        map.insert("thing1".into(), Value::Dict(map2));
//        map.insert("thing3".into(), 1234.567.into());
//        let value = Value::Dict(map);

//        let expected = "1220618cf0582d2e716a70e99c2f3079d74892fec335e3982eb926835967cb0c246c";
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));

//        assert_eq!(&actual, expected);
//    }

//    #[test]
//    fn complex_set() {
//        let value = set!{"foo", 23.6, set!{set!{}}, set!{set!{1}}};

//        let expected = "12203773b0a5283f91243a304d2bb0adb653564573bc5301aa8bb63156266ea5d398";
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));

//        assert_eq!(&actual, expected);
//    }

//    #[test]
//    fn complex_set_repeated() {
//        let value = set!{
//            "foo",
//            23.6,
//            set!{set!{}},
//            set!{set!{1}},
//            set!{set!{}}
//        };

//        let expected = "12203773b0a5283f91243a304d2bb0adb653564573bc5301aa8bb63156266ea5d398";
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));

//        assert_eq!(&actual, expected);
//    }

//    #[test]
//    fn raw() {
//        let pairs = vec![
//            (
//                Value::Raw(vec![]),
//                "1220454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
//            ),
//            (
//                Value::Raw(vec![255, 255]),
//                "122043ad246c14bf0bc0b2ac9cab9fae202a181ab4c6abb07fb40cad8c67a4cab8ee",
//            ),
//            (
//                Value::Raw(vec![0, 0, 0]),
//                "1220d877bf4e5023a6df5262218800a7162e240c84e44696bb2c3ad1c5e756f3dac1",
//            ),
//        ];

//        for (value, expected) in pairs.iter() {
//            let actual = format!("{}", &value.digest(Stamp::Sha2256));

//            assert_eq!(&actual, expected);
//        }
//    }

//    #[test]
//    fn redacted() {
//        let expected = "1220454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1";
//        let seal = Seal::from_str(
//            "**REDACTED**1220454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
//        ).unwrap();
//        let value = Value::Redacted(seal);
//        let actual = format!("{}", &value.digest(Stamp::Sha2256));
//        assert_eq!(&actual, expected);
//    }

//    #[test]
//    fn redacted_mix() {
//        let expected = list!["foo", "bar"].digest(Stamp::Sha2256);
//        let foo = Seal::from_str(
//            "**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038",
//        ).unwrap();
//        let actual = list![foo, "bar"].digest(Stamp::Sha2256);
//        assert_eq!(actual.to_string(), expected.to_string());
//    }

//}
