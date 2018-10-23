#![feature(specialization)]

#[macro_use]
extern crate pyo3;
extern crate serde_json;

extern crate blot;

use blot::multihash::{Sha1, Sha2256, Sha2512, Sha3224, Sha3256, Sha3384, Sha3512};
use blot::value::Value;
use blot::Blot;

use pyo3::prelude::*;

enum BridgeError {
    InvalidJson,
}

impl From<BridgeError> for pyo3::PyErr {
    fn from(err: BridgeError) -> Self {
        match err {
            BridgeError::InvalidJson => {
                PyErr::new::<pyo3::exc::TypeError, _>("Invalid JSON. Common pitfalls are passing a simple string 'foo' instead of a json string '\"foo\"'.")
            }
        }
    }
}

macro_rules! impl_digest (($name:ident, $type:ident) => {
    #[pyfunction]
    fn $name(input: String) -> PyResult<String> {
        let value: Value<$type> = serde_json::from_str(&input)
            .map_err(|_| BridgeError::InvalidJson)?;
        let hash = value.digest($type::default());

        Ok(hash.to_string())
    }
});

impl_digest!(sha1, Sha1);
impl_digest!(sha2256, Sha2256);
impl_digest!(sha2512, Sha2512);
impl_digest!(sha3512, Sha3512);
impl_digest!(sha3384, Sha3384);
impl_digest!(sha3256, Sha3256);
impl_digest!(sha3224, Sha3224);

#[pymodinit]
fn blot(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_function!(sha1))?;
    m.add_function(wrap_function!(sha2256))?;
    m.add_function(wrap_function!(sha2512))?;
    m.add_function(wrap_function!(sha3512))?;
    m.add_function(wrap_function!(sha3384))?;
    m.add_function(wrap_function!(sha3256))?;
    m.add_function(wrap_function!(sha3224))?;

    Ok(())
}
