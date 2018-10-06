// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Uvar is an implementation of unsigned variable integers.
//!
//! https://github.com/multiformats/unsigned-varint

const MAXBYTES: usize = 9;

// TODO: Internal representation is a vector for the time being. In the future it might change to
// either u64 or an array.
#[derive(Debug, PartialEq)]
pub struct Uvar(Vec<u8>);

impl Uvar {
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
        let mut n = 0;

        for (i, b) in buffer.into_iter().enumerate() {
            let k = u64::from(b & 0x7f);
            n = n | k << (i * 7);

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

// TODO: Review usefulness
impl From<u64> for Uvar {
    fn from(n: u64) -> Uvar {
        let mut buffer = Vec::with_capacity(9);
        let mut value = n;

        while value > 0x7F {
            buffer.push((value as u8) | 0x80);
            value >>= 7;
        }

        buffer.push(value as u8);

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
}
