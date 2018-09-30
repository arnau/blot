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
use serde_json::{Map, Value};
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

impl Blot for Value {
    fn blot<Hasher: Digest + Clone>(
        &self,
        hasher: Hasher,
    ) -> Output<<Hasher as FixedOutput>::OutputSize> {
        match self {
            Value::Null => None::<u8>.blot(hasher.clone()),
            Value::Bool(raw) => raw.blot(hasher.clone()),
            // Value::Number(raw) => raw.blot(hasher.clone()),
            Value::String(raw) => raw.blot(hasher.clone()),
            Value::Array(raw) => raw.blot(hasher.clone()),
            Value::Object(raw) => raw.blot(hasher.clone()),
            _ => unimplemented!(),
        }
    }
}
