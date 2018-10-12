// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Uvar is an implementation of unsigned variable integers.
//!
//! https://github.com/multiformats/unsigned-varint

use std::fmt;

const MAXBYTES: usize = 9;

// TODO: Internal representation is a vector for the time being. In the future it might change to
// either u64 or an array.
#[derive(Debug, Clone, PartialEq)]
pub struct Uvar(Vec<u8>);

impl Uvar {
    /// Constructs a new uvar from a byte list. Use {Uvar::from_bytes} if you need a safe
    /// constructor.
    pub fn new(bytes: Vec<u8>) -> Uvar {
        Uvar(bytes)
    }

    /// Consumes the list of bytes.
    ///
    /// ```
    /// use blot::uvar::Uvar;
    ///
    /// assert_eq!(Uvar::from_bytes(&[0x12]).unwrap().to_bytes(), vec![0x12]);
    /// ```
    pub fn to_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Transforms a byte list into a uvar.
    pub fn from_bytes(buffer: &[u8]) -> Result<Uvar, UvarError> {
        if buffer.len() > MAXBYTES {
            return Err(UvarError::Overflow);
        }

        let (n, _) = Uvar::take(buffer)?;

        Ok(n)
    }

    /// Takes a uvar from a list of bytes and returns it with the rest of bytes.
    ///
    /// ```
    /// use blot::uvar::Uvar;
    ///
    /// let buffer = vec![0x12, 0x07, 0x06];
    /// let (uvar, bytes) = Uvar::take(&buffer).unwrap();
    ///
    /// assert_eq!(uvar, Uvar::from_bytes(&[0x12]).unwrap());
    /// ```
    pub fn take(buffer: &[u8]) -> Result<(Uvar, &[u8]), UvarError> {
        for (i, b) in buffer.into_iter().enumerate() {
            if b & 0x80 == 0 {
                let code = Uvar((&buffer[..i + 1]).into());
                let rest = &buffer[i + 1..];

                return Ok((code, rest));
            }

            if i >= MAXBYTES {
                return Err(UvarError::Overflow);
            }
        }

        Err(UvarError::Underflow)
    }
}

impl fmt::LowerHex for Uvar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&u64::from(self.clone()), f)
    }
}

impl fmt::UpperHex for Uvar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&u64::from(self.clone()), f)
    }
}

impl fmt::Binary for Uvar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Binary::fmt(&u64::from(self.clone()), f)
    }
}

impl fmt::Display for Uvar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}", &self)
    }
}

impl From<Uvar> for u64 {
    fn from(uvar: Uvar) -> u64 {
        let mut n = 0;

        for (i, b) in uvar.to_bytes().iter().enumerate() {
            n = n << (i * 8) | u64::from(b & 0xFF);
        }

        n
    }
}

/// This conversion consumes full bytes, not 7bit bytes as you would expect from variable integers.
///
/// WARNING: This method forces to Big Endian. It hasn't been tested properly with different architectures.
impl From<u64> for Uvar {
    fn from(n: u64) -> Uvar {
        let mut buffer = Vec::with_capacity(MAXBYTES);
        let mut value = n.to_be();

        while value > 0 {
            let k = value & 0xFF;
            if k != 0 {
                buffer.push(k as u8);
            }

            value = value >> 8;
        }

        Uvar(buffer)
    }
}

// macro_rules! impl_for_array (($len:expr) => {
//     impl From<Uvar> for [u8; $len] {
//         fn from(n: Uvar) -> [u8; $len] {
//             let mut buffer = [0; $len];
//             let mut value = n.unbox();
//             let mut i = 0;

//             while value > 0x7F {
//                 buffer[i] = (value as u8) | 0x80;
//                 value >>= 7;
//                 i += 1;
//             }

//             buffer[i] = value as u8;

//             buffer
//         }
//     }
// });

// impl_for_array!(9);
// impl_for_array!(8);
// impl_for_array!(7);
// impl_for_array!(6);
// impl_for_array!(5);
// impl_for_array!(4);
// impl_for_array!(3);
// impl_for_array!(2);
// impl_for_array!(1);

#[derive(Debug)]
pub enum UvarError {
    Overflow,
    Underflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_single() {
        let actual = Uvar::from_bytes(&[0x12]).unwrap();
        let expected = Uvar(vec![0x12]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_bytes_multi() {
        let actual = Uvar::from_bytes(&[0xb2, 0x40]).unwrap();
        let expected = Uvar(vec![0xb2, 0x40]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn to_bytes() {
        let actual = Uvar(vec![0xb2, 0x40]).to_bytes();
        let expected = &[0xb2, 0x40];
        assert_eq!(&actual, expected);
    }

    #[test]
    fn identity() {
        let actual = Uvar::from_bytes(&[0xb2, 0x40]).unwrap().to_bytes();
        let expected = &[0xb2, 0x40];
        assert_eq!(&actual, expected);
    }

    #[test]
    fn to_u64() {
        for (buffer, expected) in &[(vec![0x12], 0x12), (vec![0xb2, 0x40], 0xb240)] {
            let actual: u64 = Uvar::from_bytes(&buffer).unwrap().into();

            assert_eq!(actual, *expected);
        }
    }

    #[test]
    fn from_u64() {
        for (buffer, n) in &[(vec![0x12], 0x12), (vec![0xb2, 0x40], 0xb240)] {
            let num: u64 = *n;
            let expected = Uvar::from_bytes(&buffer).unwrap();
            let actual: Uvar = num.into();

            assert_eq!(actual, expected);
        }
    }

}
