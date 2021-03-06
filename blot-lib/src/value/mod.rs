// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

//! Represents a multi-type value able to express any Objecthash combination.

use std::fmt::{self, Display};

use core::Blot;
use multihash::{Harvest, Multihash};
use seal::Seal;
use std::collections::HashMap;
use tag::Tag;

#[cfg(feature = "blot_json")]
pub mod de;

#[derive(Clone, Debug, PartialEq)]
pub enum Value<T: Multihash> {
    /// Represents a null value (similar to JSON's null).
    Null,
    /// Represents a boolean.
    Bool(bool),
    /// Represents a signed 64-bit integer.
    Integer(i64),
    /// Represents a 64-bit floating point.
    Float(f64),
    /// Represents a string.
    String(String),
    /// Represents a RFC3339 timestamp.
    Timestamp(String),
    /// Represents a sealed value (i.e. hash resulting of a redacted value).
    Redacted(Seal<T>),
    /// Represents a raw list of bytes.
    Raw(Vec<u8>),
    /// Represents a list of values.
    List(Vec<Value<T>>),
    /// Represents a set of values.
    Set(Vec<Value<T>>),
    /// Represents an attribute-value dictionary.
    Dict(HashMap<String, Value<T>>),
}

impl<T: Multihash> Value<T> {
    pub fn sequences_as_sets(self) -> Self {
        match self {
            Value::List(list) => Value::Set(list),
            Value::Dict(dict) => Value::Dict(
                dict.into_iter()
                    .map(|(k, v)| (k, v.sequences_as_sets()))
                    .collect(),
            ),
            value => value,
        }
    }
}

#[derive(Debug)]
pub enum ValueError {
    Unknown,
}

impl Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

impl<T: Multihash> Blot for Value<T> {
    fn blot<D: Multihash>(&self, digester: &D) -> Harvest {
        match self {
            Value::Null => None::<u8>.blot(digester),
            Value::Bool(raw) => raw.blot(digester),
            Value::Integer(raw) => raw.blot(digester),
            Value::Float(raw) => raw.blot(digester),
            Value::String(raw) => raw.blot(digester),
            Value::Timestamp(raw) => digester
                .clone()
                .digest_primitive(Tag::Timestamp, raw.as_bytes()),
            Value::Redacted(raw) => raw.blot(digester),
            Value::Raw(raw) => raw.as_slice().blot(digester),
            Value::List(raw) => raw.blot(digester),
            Value::Set(raw) => {
                println!("in set");
                let mut list: Vec<Vec<u8>> = raw
                    .iter()
                    .map(|item| {
                        item.blot(digester)
                            .as_slice()
                            .iter()
                            .map(|x| *x)
                            .collect::<Vec<u8>>()
                    }).collect();

                list.sort_unstable();
                list.dedup();

                digester.clone().digest_collection(Tag::Set, list)
            }
            Value::Dict(raw) => raw.blot(digester),
        }
    }
}

#[macro_export]
macro_rules! set {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($x.into());
            )*
            Value::Set(temp_vec)
        }
    };
}

#[macro_export]
macro_rules! raw {
    ($input:expr) => {{
        Vec::from_hex($input).map(|hash| Value::Raw(hash))
    }};
}

#[macro_export]
macro_rules! list {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($x.into());
            )*
            Value::List(temp_vec)
        }
    };
}

#[macro_export]
macro_rules! seal {
    ($input:expr) => {{
        Seal::from_str($input).map(Value::Redacted)
    }};
}

impl<'a, T: Multihash> From<&'a str> for Value<T> {
    fn from(raw: &str) -> Value<T> {
        Value::String(raw.into())
    }
}

impl<'a, T: Multihash> From<String> for Value<T> {
    fn from(raw: String) -> Value<T> {
        Value::String(raw)
    }
}

impl<T: Multihash> From<i64> for Value<T> {
    fn from(raw: i64) -> Value<T> {
        Value::Integer(raw)
    }
}

impl<T: Multihash> From<f64> for Value<T> {
    fn from(raw: f64) -> Value<T> {
        Value::Float(raw)
    }
}

impl<T: Multihash> From<Vec<Value<T>>> for Value<T> {
    fn from(raw: Vec<Value<T>>) -> Value<T> {
        Value::List(raw)
    }
}

impl<T: Multihash> From<Seal<T>> for Value<T> {
    fn from(raw: Seal<T>) -> Value<T> {
        Value::Redacted(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::Sha2256;

    #[test]
    fn common() {
        let expected = "122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2";
        let value: Value<Sha2256> = vec!["foo".into(), "bar".into()].into();
        let actual = format!("{}", &value.digest(Sha2256));

        assert_eq!(actual, expected);
    }

    #[test]
    fn int_list() {
        let pairs: [(Value<Sha2256>, &str); 4] = [
            (
                list![123],
                "12201b93f704451e1a7a1b8c03626ffcd6dec0bc7ace947ff60d52e1b69b4658ccaa",
            ),
            (
                list![1, 2, 3],
                "1220157bf16c70bd4c9673ffb5030552df0ee2c40282042ccdf6167850edc9044ab7",
            ),
            (
                list![123456789012345],
                "12203488b9bc37cce8223a032760a9d4ef488cdfebddd9e1af0b31fcd1d7006369a4",
            ),
            (
                list![123456789012345, 678901234567890],
                "1220031ef1aaeccea3bced3a1c6237a4fc00ed4d629c9511922c5a3f4e5c128b0ae4",
            ),
        ];

        for (value, expected) in pairs.iter() {
            let actual = format!("{}", &value.digest(Sha2256));

            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn floats() {
        let mut map: HashMap<String, Value<Sha2256>> = HashMap::new();
        map.insert(
            "bar".into(),
            list![
                "baz",
                Value::Null,
                1.0,
                1.5,
                0.0001,
                1000.0,
                2.0,
                -23.1234,
                2.0
            ],
        );
        let value = list!["foo", Value::Dict(map)];
        let expected = "1220783a423b094307bcb28d005bc2f026ff44204442ef3513585e7e73b66e3c2213";
        let actual = format!("{}", &value.digest(Sha2256));

        assert_eq!(&actual, expected);
    }

    #[test]
    fn int_floats() {
        let mut map: HashMap<String, Value<Sha2256>> = HashMap::new();
        map.insert(
            "bar".into(),
            vec![
                "baz".into(),
                Value::Null,
                1.into(),
                1.5.into(),
                0.0001.into(),
                1000.into(),
                2.into(),
                (-23.1234).into(),
                2.into(),
            ].into(),
        );
        let value = Value::List(vec!["foo".into(), Value::Dict(map)]);
        let expected = "1220726e7ae9e3fadf8a2228bf33e505a63df8db1638fa4f21429673d387dbd1c52a";
        let actual = format!("{}", &value.digest(Sha2256));

        assert_eq!(&actual, expected);
    }

    #[test]
    fn set() {
        let mut map: HashMap<String, Value<Sha2256>> = HashMap::new();
        let mut map2: HashMap<String, Value<Sha2256>> = HashMap::new();
        map2.insert(
            "thing2".into(),
            Value::Set(vec![1.into(), 2.into(), "s".into()]),
        );
        map.insert("thing1".into(), Value::Dict(map2));
        map.insert("thing3".into(), 1234.567.into());
        let value = Value::Dict(map);

        let expected = "1220618cf0582d2e716a70e99c2f3079d74892fec335e3982eb926835967cb0c246c";
        let actual = format!("{}", &value.digest(Sha2256));

        assert_eq!(&actual, expected);
    }

    #[test]
    fn complex_set() {
        let value: Value<Sha2256> = set!{"foo", 23.6, set!{set!{}}, set!{set!{1}}};

        let expected = "12203773b0a5283f91243a304d2bb0adb653564573bc5301aa8bb63156266ea5d398";
        let actual = format!("{}", &value.digest(Sha2256));

        assert_eq!(&actual, expected);
    }

    #[test]
    fn complex_set_repeated() {
        let value: Value<Sha2256> = set!{
            "foo",
            23.6,
            set!{set!{}},
            set!{set!{1}},
            set!{set!{}}
        };

        let expected = "12203773b0a5283f91243a304d2bb0adb653564573bc5301aa8bb63156266ea5d398";
        let actual = format!("{}", &value.digest(Sha2256));

        assert_eq!(&actual, expected);
    }

    #[test]
    fn raw() {
        let pairs: [(Value<Sha2256>, &str); 3] = [
            (
                Value::Raw(vec![]),
                "1220454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
            ),
            (
                Value::Raw(vec![255, 255]),
                "122043ad246c14bf0bc0b2ac9cab9fae202a181ab4c6abb07fb40cad8c67a4cab8ee",
            ),
            (
                Value::Raw(vec![0, 0, 0]),
                "1220d877bf4e5023a6df5262218800a7162e240c84e44696bb2c3ad1c5e756f3dac1",
            ),
        ];

        for (value, expected) in pairs.iter() {
            let actual = format!("{}", &value.digest(Sha2256));

            assert_eq!(&actual, expected);
        }
    }

    #[test]
    fn redacted() {
        let expected = "1220454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1";
        let seal: Seal<Sha2256> = Seal::from_str(
            "**REDACTED**1220454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1",
        ).unwrap();
        let value = Value::Redacted(seal);
        let actual = format!("{}", &value.digest(Sha2256));
        assert_eq!(&actual, expected);
    }

    #[test]
    fn redacted_mix() {
        let expected_value: Value<Sha2256> = list!["foo", "bar"];
        let expected = expected_value.digest(Sha2256);
        let foo: Seal<Sha2256> = Seal::from_str(
            "**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038",
        ).unwrap();
        let actual = list![foo, "bar"].digest(Sha2256);
        assert_eq!(actual.to_string(), expected.to_string());
    }

}
