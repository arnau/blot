// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

extern crate blot;
// extern crate digest;
extern crate hex;
extern crate serde_json;

use blot::core::Blot;
// use blot::value::Value;
// use serde_json::Value;
use blot::multihash;
use blot::uvar;
use hex::FromHex;

#[derive(Debug)]
enum SealError {
    NotRedacted,
    UnknownMultihash,
    UnexpectedLength(multihash::Tag, u8),
    UvarParseError(String),
}

impl From<String> for SealError {
    fn from(s: String) -> SealError {
        SealError::UvarParseError(s)
    }
}

#[derive(Debug)]
struct Seal {
    tag: multihash::Tag,
    digest: Vec<u8>,
}

// 1. hex -> bytes                   // 0xb24040...
// 2. bytes -> (code=uvar, bytes)    // ([0xb2, 0x40], [0x40, ...])
// 3. bytes -> (length=int, digest)  // (0x40, [...])

//impl Seal {
//    pub fn digest_hex(&self) -> String {
//        let mut result = String::new();

//        for byte in &self.digest {
//            result.push_str(&format!("{:02x}", byte));
//        }

//        result
//    }

//    // TODO:
//    //
//    // * if it's not redacted ("**REDACTED**" or 0x77 uvar), return NotRedacted.
//    // * Take the first uvar and the next byte as length.
//    // * If it is an unknown multihash, return UnknownMultihash.
//    // * If the rest of the bytes is not the found length, return UnexpectedLength(tag, length)
//    // * Create Some seal with the mh tag and the digest.
//    pub fn parse(raw: &str) -> Result<Seal, SealError> {
//        if raw.starts_with("**REDACTED**") {
//            let digest = Vec::from_hex(raw.get(12..).expect("REDACTED")).expect("Hexadecimal");

//            let d2 = digest.clone();
//            let (code, rest) = uvar::u64(&d2[..])?;

//            println!("{:02x} {:?} {}", &code, &rest, &rest.len());
//            println!("{:02x}", uvar::decode(&digest));

//            Ok(Seal {
//                tag: multihash::Tag::Sha2256,
//                digest: digest,
//            })
//        } else {
//            Err(SealError::NotRedacted)
//        }
//    }
//}

//fn test() {
//    let expected = "122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2";
//    let value = "**REDACTED**1220a6a6e5e783c363cd95693ec189c2682315d956869397738679b56305f2095038";
//    let seal = Seal::parse(&value);

//    // println!("{:?}", &seal);
//    println!("{}", seal.unwrap().digest_hex());
//    // assert_eq!(actual, expected);
//}

// From hex to (prefix, digest):
//
// 1. Transform hex to bytes
// 2. Take bytes until MSB is 0
fn main() -> std::io::Result<()> {
    // println!("{}", "foo".blake2b512());
    // let blk = "b2404020fb5053ecefc742b73665625613de5ea09917988fac07d2977ece1c9bebb1aa0e5dfe8e3f2ae7b30ac3b97fac511a4745d71f5d4dbb211d69d06b34fb031e60";
    // let bytes = Vec::from_hex(blk).unwrap();

    let mut n = 0xb240u64.to_be();
    let mut vec = Vec::new();

    while n > 0 {
        let k = n & 0xFF;
        if k != 0 {
            vec.push(k);
        }

        n >>= 8;
    }

    println!("{:?}", &vec);

    Ok(())
}
