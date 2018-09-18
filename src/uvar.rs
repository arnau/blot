// Copyright 2018 Arnau Siches
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to
// those terms.

//! Uvar is an implementation of unsigned variable integers

const U8_LEN: usize = 2;
const U16_LEN: usize = 3;
const U32_LEN: usize = 5;
const U64_LEN: usize = 10;
const U128_LEN: usize = 19;

// https://github.com/paritytech/unsigned-varint/blob/master/src/decode.rs
macro_rules! encode {
    ($number:expr, $buf:expr) => {{
        let mut n = $number;
        let mut i = 0;
        for b in $buf.iter_mut() {
            *b = n as u8 | 0x80;
            n >>= 7;
            if n == 0 {
                *b &= 0x7f;
                break;
            }
            i += 1
        }
        debug_assert_eq!(n, 0);
        &$buf[0..=i]
    }};
}

macro_rules! decode {
    ($buf:expr, $max_bytes:expr, $typ:ident) => {{
        let mut n = 0;
        for (i, b) in $buf.iter().cloned().enumerate() {
            let k = $typ::from(b & 0x7F);
            n |= k << (i * 7);
            if b & 0x80 == 0 {
                return Ok((n, &$buf[i + 1..]));
            }
            if i == $max_bytes {
                return Err("Overflow".into());
            }
        }
        Err("Insufficient".into())
    }};
}

pub fn length(value: u64) -> usize {
    let zero_len = 64 - value.leading_zeros();
    let offset = if zero_len == 0 { 7 } else { 6 };
    ((offset + zero_len) / 7) as usize
}

pub fn encode(value: u64, buf: &mut [u8]) -> &[u8] {
    let mut off = 0;
    let mut val = value;

    while val > 127 {
        buf[off] = (val as u8) | 128;
        off += 1;
        val >>= 7;
    }
    buf[off] = val as u8;

    buf
}

pub fn decode(buf: &[u8]) -> u64 {
    let mut val = 0 as u64;
    let mut fac = 1 as u64;
    let mut off = 0;

    loop {
        let byte = buf[off];
        off += 1;
        val += fac * u64::from(byte & 127);
        fac <<= 7;
        if byte & 128 == 0 {
            break;
        }
    }

    val
}

fn has_significant_bit(n: u8) -> bool {
    (n & (0b00000001 << 7)) != 0
}

fn shifu(n: u8) -> u8 {
    n & 0b10000000
}

fn encu16(n: u16, buf: &mut [u8; U16_LEN]) -> &[u8] {
    encode!(n, buf)
}

fn u16(buf: &[u8]) -> Result<(u16, &[u8]), String> {
    decode!(buf, 2, u16)
}

fn u64(buf: &[u8]) -> Result<(u64, &[u8]), String> {
    decode!(buf, 9, u64)
}

fn main() {
    println!("{:x}", 0xb240);
    println!("{:b}", 0xb240);

    println!("{:?}", has_significant_bit(0x12));
    println!("{:08b}", 0x12);
    println!("{:?}", has_significant_bit(0xb2));
    println!("{:08b}", 0xb2);

    println!("{:08b}", shifu(0xb2));
    println!("{:08b}", shifu(0x12));

    println!("{:?}", encode(0xb240, &mut [0; U16_LEN]));
    println!("{:?}", encu16(0xb240, &mut [0; U16_LEN]));
    let (n, rest) = u16(&[192, 228, 2]).unwrap();
    println!("{:x}, {:?}", n, rest);

    let (n64, rest64) = u64(&[192, 228, 2]).unwrap();
    println!("{:x}, {:?}", n64, rest64);

    println!("{:x}", decode(&[192, 228, 2]));
    println!("{:x}", u64::from_str_radix("b240", 16).unwrap());
}
