// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

extern crate yobicrypto;
extern crate hex;

use yobicrypto::{Random, Scalar};
use yobicrypto::{BinarySerialize, HexSerialize};

#[test]
fn scalar_from_bytes_succ() {
    let b = &[47, 224, 8, 238, 162, 198, 156, 92, 133, 36, 121, 240, 204, 49, 196, 166, 27, 10, 33, 15, 10, 188, 54, 83, 214, 103, 39, 8, 180, 70, 232, 10];
    let res = Scalar::from_bytes(b);
    assert!(res.is_ok())
}

#[test]
fn scalar_from_bytes_fail() {
    let mut b = [0u8; 64];
    Random::bytes_mut(&mut b);
    let res = Scalar::from_bytes(&b[..]);
    assert!(res.is_err())
}

#[test]
fn scalar_to_bytes_succ() {
    let scalar_a = Scalar::random();
    let scalar_buf = scalar_a.to_bytes().unwrap();
    let scalar_b = Scalar::from_bytes(&scalar_buf).unwrap();
    assert_eq!(scalar_a, scalar_b)
}

#[test]
fn scalar_from_hex_succ() {
    let b = &[47, 224, 8, 238, 162, 198, 156, 92, 133, 36, 121, 240, 204, 49, 196, 166, 27, 10, 33, 15, 10, 188, 54, 83, 214, 103, 39, 8, 180, 70, 232, 10];
    let s = hex::encode(b);
    let res = Scalar::from_hex(&s);
    assert!(res.is_ok())
}

#[test]
fn scalar_from_hex_fail() {
    let s = "df36e1c444a5986aaa9cb0e7352617425eb439274dfb49d794df78b79697413";
    let res = Scalar::from_hex(s);
    assert!(res.is_err())
}

#[test]
fn scalar_to_hex_succ() {
    let scalar_a = Scalar::random();
    let scalar_a_hex = scalar_a.to_hex().unwrap();
    let scalar_b = Scalar::from_hex(scalar_a_hex.as_str()).unwrap();
    assert_eq!(scalar_a, scalar_b)
}

#[test]
fn scalar_add_succ() {
    let a = Scalar::from_u64(1).unwrap();
    let b = Scalar::from_u64(2).unwrap();
    let c = Scalar::from_u64(3).unwrap();
    assert_eq!(c, (&a+&b))
}

#[test]
fn scalar_sub_succ() {
    let a = Scalar::from_u64(3).unwrap();
    let b = Scalar::from_u64(2).unwrap();
    let c = Scalar::from_u64(1).unwrap();
    assert_eq!(c, (&a-&b))
}

#[test]
fn scalar_mul_succ() {
    let a = Scalar::from_u64(2).unwrap();
    let b = Scalar::from_u64(3).unwrap();
    let c = Scalar::from_u64(6).unwrap();
    assert_eq!(c, (&a*&b))
}
