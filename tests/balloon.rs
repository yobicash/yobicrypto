// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

extern crate yobicrypto;
extern crate num;

use num::bigint::BigUint;
use num::traits::One;
use num::ToPrimitive;

use yobicrypto::{Random, Digest, BalloonParams, BalloonHasher};
use yobicrypto::{Validate, BinarySerialize};

#[test]
fn balloon_params_new_succ() {
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let res = BalloonParams::new(s_cost, t_cost, delta);
    assert!(res.is_ok())
}

#[test]
fn balloon_params_new_fail() {
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = 0;
    let delta = 3;
    let res = BalloonParams::new(s_cost, t_cost, delta);
    assert!(res.is_err())
}

#[test]
fn balloon_params_from_memory_succ() {
    let lower_memory = BalloonParams::default().memory().unwrap();
    let addendum = BigUint::from(1u32<<30);
    let memory = (lower_memory + addendum).to_u32().unwrap();
    let res = BalloonParams::from_memory(memory);
    assert!(res.is_ok())
}

#[test]
fn balloon_params_from_memory_fail() {
    let lower_memory = BalloonParams::default().memory().unwrap();
    let one: BigUint = One::one();
    let memory = (lower_memory - one).to_u32().unwrap();
    let res = BalloonParams::from_memory(memory);
    assert!(res.is_err())
}

#[test]
fn balloon_params_validate_succ() {
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let res = params.validate();
    assert!(res.is_ok())
}

#[test]
fn balloon_params_validate_fail() {
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let mut params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    params.s_cost = 0;
    let res = params.validate();
    assert!(res.is_err())
}

#[test]
fn balloon_params_bytes_succ() {
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = Random::u32_range(3..10).unwrap();
    let params_a = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let params_buf = params_a.to_bytes().unwrap();
    let params_b = BalloonParams::from_bytes(params_buf.as_slice()).unwrap();
    assert_eq!(params_a, params_b)
}

#[test]
fn balloon_hasher_new_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let res = BalloonHasher::new(salt, params);
    assert!(res.is_ok())
}

#[test]
fn balloon_hasher_new_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let mut params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    params.t_cost = 0;
    let res = BalloonHasher::new(salt, params);
    assert!(res.is_err())
}

#[test]
fn balloon_hasher_from_memory_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let lower_memory = BalloonParams::default().memory().unwrap();
    let addendum = BigUint::from(1u32<<30);
    let memory = (lower_memory + addendum).to_u32().unwrap();
    let res = BalloonHasher::from_memory(salt, memory);
    assert!(res.is_ok())
}

#[test]
fn balloon_hasher_from_memory_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let lower_memory = BalloonParams::default().memory().unwrap();
    let one: BigUint = One::one();
    let memory = (lower_memory - one).to_u32().unwrap();
    let res = BalloonHasher::from_memory(salt, memory);
    assert!(res.is_err())
}

#[test]
fn balloon_hasher_validate_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let balloon = BalloonHasher::new(salt, params).unwrap();
    let res = balloon.validate();
    assert!(res.is_ok())
}

#[test]
fn balloon_hasher_validate_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let mut balloon = BalloonHasher::new(salt, params).unwrap();
    balloon.params.delta = 2;
    let res = balloon.validate();
    assert!(res.is_err())
}

#[test]
fn balloon_hasher_hash_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let balloon = BalloonHasher::new(salt, params).unwrap();
    let msg = Random::bytes(100);
    let res = balloon.hash(msg.as_slice());
    assert!(res.is_ok())
}

#[test]
fn balloon_hasher_hash_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap();
    let s_cost = Random::u32_range(1..10).unwrap();
    let t_cost = Random::u32_range(1..10).unwrap();
    let delta = 3;
    let params = BalloonParams::new(s_cost, t_cost, delta).unwrap();
    let mut balloon = BalloonHasher::new(salt, params).unwrap();
    balloon.params.delta = 2;
    let msg = Random::bytes(100);
    let res = balloon.hash(msg.as_slice());
    assert!(res.is_err())
}
