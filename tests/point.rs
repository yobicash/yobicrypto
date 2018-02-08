// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! Yobicrypto `point` module tests.

extern crate yobicrypto;

use yobicrypto::{Random, Point};
use yobicrypto::{BinarySerialize, HexSerialize};

#[test]
fn point_from_bytes_succ() {
    let p = Point::random().unwrap().to_bytes().unwrap();
    let res = Point::from_bytes(p.as_slice());
    assert!(res.is_ok())
}

#[test]
fn point_from_bytes_fail() {
    let mut b = [0u8; 64];
    Random::bytes_mut(&mut b);
    let res = Point::from_bytes(&b[..]);
    assert!(res.is_err())
}

#[test]
fn point_to_bytes_succ() {
    let p_a = Point::random().unwrap();
    let p_buf = p_a.to_bytes().unwrap();
    let p_b = Point::from_bytes(p_buf.as_slice()).unwrap();
    assert_eq!(p_a, p_b)
}

#[test]
fn point_from_hex_succ() {
    let s = "df36e1c444a5986aaa9cb0e7352617425eb439274dfb49d794df78b796974131";
    let res = Point::from_hex(s);
    assert!(res.is_ok())
}

#[test]
fn point_from_hex_fail() {
    let s = "df36e1c444a5986aaa9cb0e7352617425eb439274dfb49d794df78b79697413";
    let res = Point::from_hex(s);
    assert!(res.is_err())
}

#[test]
fn point_to_hex_succ() {
    let point_a = Point::random().unwrap();
    let point_a_hex = point_a.to_hex().unwrap();
    let point_b = Point::from_hex(point_a_hex.as_str()).unwrap();
    assert_eq!(point_a, point_b)
}
