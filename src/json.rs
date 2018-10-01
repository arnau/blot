// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except
// according to those terms.

//! Blot implementation for common JSON.
//!
//! This implementation treats all numbers as f64.
//!
//! ```
//! extern crate serde_json;
//! extern crate blot;
//! use serde_json::{self, Value};
//! use blot::core::Blot;
//!
//! let data = r#"["foo", "bar"]"#;
//! let value: Value = serde_json::from_str(data).unwrap();
//!
//! assert_eq!(format!("{}", &value.sha2256()), "122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2");
//! ```

use core::{collection, Blot, Output};
use digest::{Digest, FixedOutput};
use serde_json::{Map, Number, Value};
use tag::Tag;

impl Blot for Map<String, Value> {
    fn blot<Hasher: Digest + Clone>(
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

#[cfg(feature = "common_json")]
impl Blot for Number {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        self.as_f64()
            .expect("Casting JSON Number as f64 failed")
            .blot(hasher)
    }
}

#[cfg(not(feature = "common_json"))]
impl Blot for Number {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        if self.is_f64() {
            self.as_f64()
                .expect("Casting JSON Number as f64 failed")
                .blot(hasher)
        } else if self.is_u64() {
            self.as_u64()
                .expect("Casting JSON Number as u64 failed")
                .blot(hasher)
        } else {
            self.as_i64()
                .expect("Casting JSON Number as i64 failed")
                .blot(hasher)
        }
    }
}

impl Blot for Value {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        match self {
            Value::Null => None::<u8>.blot(hasher.clone()),
            Value::Bool(raw) => raw.blot(hasher.clone()),
            Value::Number(raw) => raw.blot(hasher.clone()),
            Value::String(raw) => raw.blot(hasher.clone()),
            Value::Array(raw) => raw.blot(hasher.clone()),
            Value::Object(raw) => raw.blot(hasher.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{self, Value};

    #[test]
    fn common() {
        let expected = "122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2";
        let value: Value = serde_json::from_str(r#"["foo", "bar"]"#).unwrap();
        let actual = format!("{}", &value.sha2256());

        assert_eq!(actual, expected);
    }

    #[cfg(not(feature = "common_json"))]
    mod default {
        use super::*;
        use serde_json::{self, Value};
        #[test]
        fn int_list() {
            let pairs = [
                (
                    r#"[123]"#,
                    "12201b93f704451e1a7a1b8c03626ffcd6dec0bc7ace947ff60d52e1b69b4658ccaa",
                ),
                (
                    r#"[1, 2, 3]"#,
                    "1220157bf16c70bd4c9673ffb5030552df0ee2c40282042ccdf6167850edc9044ab7",
                ),
                (
                    r#"[123456789012345]"#,
                    "12203488b9bc37cce8223a032760a9d4ef488cdfebddd9e1af0b31fcd1d7006369a4",
                ),
                (
                    r#"[123456789012345, 678901234567890]"#,
                    "1220031ef1aaeccea3bced3a1c6237a4fc00ed4d629c9511922c5a3f4e5c128b0ae4",
                ),
            ];
            for (raw, expected) in pairs.iter() {
                let value: Value = serde_json::from_str(raw).unwrap();
                let actual = format!("{}", &value.sha2256());

                assert_eq!(&actual, expected);
            }
        }

        #[test]
        fn int_float_mix() {
            let pairs = [
                (
                    r#"["foo", {"bar":["baz", null, 1.0, 1.5, 0.0001, 1000.0, 2.0, -23.1234, 2.0]}]"#,
                        "1220783a423b094307bcb28d005bc2f026ff44204442ef3513585e7e73b66e3c2213"
                ),
                (
                    r#"["foo", {"bar":["baz", null, 1, 1.5, 0.0001, 1000, 2, -23.1234, 2]}]"#,
                    "1220726e7ae9e3fadf8a2228bf33e505a63df8db1638fa4f21429673d387dbd1c52a"
                )
            ];
            for (raw, expected) in pairs.iter() {
                let value: Value = serde_json::from_str(raw).unwrap();
                let actual = format!("{}", &value.sha2256());

                assert_eq!(&actual, expected);
            }
        }
    }

    #[cfg(feature = "common_json")]
    mod common_json {
        use super::*;
        use serde_json::{self, Value};
        #[test]
        fn int_list() {
            let pairs = [
                (
                    r#"[123]"#,
                    "12202e72db006266ed9cdaa353aa22b9213e8a3c69c838349437c06896b1b34cee36",
                ),
                (
                    r#"[1, 2, 3]"#,
                    "1220925d474ac71f6e8cb35dd951d123944f7cabc5cda9a043cf38cd638cc0158db0",
                ),
                (
                    r#"[123456789012345]"#,
                    "1220f446de5475e2f24c0a2b0cd87350927f0a2870d1bb9cbaa794e789806e4c0836",
                ),
                (
                    r#"[123456789012345, 678901234567890]"#,
                    "1220d4cca471f1c68f62fbc815b88effa7e52e79d110419a7c64c1ebb107b07f7f56",
                ),
            ];
            for (raw, expected) in pairs.iter() {
                let value: Value = serde_json::from_str(raw).unwrap();
                let actual = format!("{}", &value.sha2256());

                assert_eq!(&actual, expected);
            }
        }
    }
}
