// Copyright 2018 Arnau Siches

// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>,
// at your option. This file may not be copied, modified, or distributed except
// according to those terms.

//! Tag bytes

#[derive(Debug, Clone, Copy)]
pub enum Tag {
    Bool = 0x62,
    Dict = 0x64,
    Float = 0x66,
    Integer = 0x69,
    List = 0x6C,
    Null = 0x6E,
    Raw = 0x72,
    Set = 0x73,
    Unicode = 0x75,
}

impl Tag {
    pub fn to_bytes(&self) -> [u8; 1] {
        [*self as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_byte() {
        assert_eq!(Tag::Unicode.to_bytes(), [0x75; 1])
    }
}
