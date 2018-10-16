// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

use hex::FromHex;
use multihash::Multihash;
use regex::Regex;
use seal::Seal;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashMap;
use std::fmt;

use super::{Value, ValueSet};

enum Schema {
    /// Visitor that transforms all sequences to `Value::List`.
    SeqAsList,

    /// Visitor that transforms all sequences to `Value::Set`.
    SeqAsSet,
}

use std::marker::PhantomData;
struct ValueVisitor<T: Multihash>(Schema, PhantomData<*const T>);

impl<'de, T: Multihash> Visitor<'de> for ValueVisitor<T> {
    type Value = Value<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expecting a valid JSON value.")
    }

    #[inline]
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Bool(value))
    }

    #[inline]
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Integer(value.into()))
    }

    #[inline]
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        use std::i64;

        if value <= (i64::MAX as u64) {
            Ok(Value::Integer(value as i64))
        } else {
            Err(E::custom(format!("i64 out of range: {}", value)))
        }
    }

    #[inline]
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Float(value.into()))
    }

    #[inline]
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.into())
    }

    #[inline]
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // TODO: A mismatch between seal and value hashing functions will result in a Raw hash, not
        // in a failure.
        if let Ok(seal) = Seal::from_str(&value) {
            return Ok(Value::Redacted(seal));
        }

        if let Ok(raw) = Vec::from_hex(&value) {
            return Ok(Value::Raw(raw));
        }

        lazy_static! {
            static ref RE: Regex = Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
                .expect("Regex to compile");
        }

        if RE.is_match(&value) {
            return Ok(Value::Timestamp(value));
        }

        Ok(Value::String(value))
    }

    #[inline]
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    #[inline]
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer)
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    #[inline]
    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut vec = Vec::new();

        while let Some(elem) = visitor.next_element()? {
            vec.push(elem);
        }

        match self.0 {
            Schema::SeqAsList => Ok(Value::List(vec)),
            Schema::SeqAsSet => Ok(Value::Set(vec)),
        }
    }

    fn visit_map<V>(self, mut access: V) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut dict = HashMap::new();

        while let Some((key, value)) = access.next_entry()? {
            dict.insert(key, value);
        }

        Ok(Value::Dict(dict))
    }
}

impl<'de, T: Multihash> Deserialize<'de> for Value<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ValueVisitor(Schema::SeqAsList, PhantomData))
    }
}

impl<'de, T: Multihash> Deserialize<'de> for ValueSet<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(ValueVisitor(Schema::SeqAsSet, PhantomData))
            .map(ValueSet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::{Sha2256, Sha3256};
    use serde_json;

    #[test]
    fn basic_string_value() {
        let input = r#""abc""#;
        let expected = r#"Ok(String("abc"))"#.to_string();
        let res = serde_json::from_str::<Value<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn classic_redacted_value() {
        let input =
            r#""**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038""#;
        let expected = r#"Ok(Redacted(Seal { tag: Sha2256, digest: [166, 166, 229, 231, 131, 195, 99, 205, 149, 105, 62, 193, 137, 194, 104, 35, 21, 217, 86, 134, 147, 151, 115, 134, 121, 181, 99, 5, 242, 9, 80, 56] }))"#.to_string();
        let res = serde_json::from_str::<Value<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn redacted_value() {
        let input = r#""771220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038""#;
        let expected = r#"Ok(Redacted(Seal { tag: Sha2256, digest: [166, 166, 229, 231, 131, 195, 99, 205, 149, 105, 62, 193, 137, 194, 104, 35, 21, 217, 86, 134, 147, 151, 115, 134, 121, 181, 99, 5, 242, 9, 80, 56] }))"#.to_string();
        let res = serde_json::from_str::<Value<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn raw_value() {
        let input = r#""1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038""#;
        let expected = r#"Ok(Raw([18, 32, 166, 166, 229, 231, 131, 195, 99, 205, 149, 105, 62, 193, 137, 194, 104, 35, 21, 217, 86, 134, 147, 151, 115, 134, 121, 181, 99, 5, 242, 9, 80, 56]))"#.to_string();
        let res = serde_json::from_str::<Value<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn redacted_value_wrong_algorithm() {
        let input = r#""771220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038""#;
        let expected = r#"Ok(Raw([119, 18, 32, 166, 166, 229, 231, 131, 195, 99, 205, 149, 105, 62, 193, 137, 194, 104, 35, 21, 217, 86, 134, 147, 151, 115, 134, 121, 181, 99, 5, 242, 9, 80, 56]))"#;
        let res = serde_json::from_str::<Value<Sha3256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn list_value() {
        let input = r#"[1, 2]"#;
        let expected = r#"Ok(List([Integer(1), Integer(2)]))"#;
        let res = serde_json::from_str::<Value<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn set_value() {
        let input = r#"[1, 2]"#;
        let expected = r#"Ok(ValueSet(Set([Integer(1), Integer(2)])))"#;
        let res = serde_json::from_str::<ValueSet<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }

    #[test]
    fn timestamp_value() {
        let input = r#""2018-10-13T15:50:00Z""#;
        let expected = r#"Ok(Timestamp("2018-10-13T15:50:00Z"))"#;
        let res = serde_json::from_str::<Value<Sha2256>>(input);

        assert_eq!(format!("{:?}", res), expected);
    }
}
