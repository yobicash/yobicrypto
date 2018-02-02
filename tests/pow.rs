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

use yobicrypto::{Random, Digest, BalloonParams, PoWTarget, PoW};
use yobicrypto::{Validate, BinarySerialize};

#[test]
fn target_new_succ() {
    let bits = Random::u32_range(0..64).unwrap();
    let res = PoWTarget::new(bits);
    assert!(res.is_ok())
}

#[test]
fn target_new_fail() {
    let bits = 64;
    let res = PoWTarget::new(bits);
    assert!(res.is_err())
}

#[test]
fn target_bits_succ() {
    let bits = Random::u32_range(0..64).unwrap();
    let target = PoWTarget::new(bits).unwrap();
    let _bits = target.bits().unwrap();
    assert_eq!(bits, _bits);
}

#[test]
fn pow_new_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = Random::u32_range(3..64).unwrap();
    let res = PoW::new(salt, params, difficulty);
    assert!(res.is_ok())
}

#[test]
fn pow_new_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 64;
    let res = PoW::new(salt, params, difficulty);
    assert!(res.is_err())
}

#[test]
fn pow_memory_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 10;
    let pow_a = PoW::new(salt, params, difficulty).unwrap();
    let memory_a = pow_a.memory().unwrap();
    let one: BigUint = One::one();
    let memory_b = (&memory_a + &one).to_u32().unwrap();
    let pow_b = PoW::from_memory(salt, memory_b, difficulty).unwrap();
    let memory_c = pow_b.memory().unwrap();
    assert!(memory_c > memory_a)
}

#[test]
fn pow_memory_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let default_memory = params.memory().unwrap();
    let one: BigUint = One::one();
    let faulty_memory = (default_memory - one).to_u32().unwrap();
    let difficulty = 10;
    let res = PoW::from_memory(salt, faulty_memory, difficulty);
    assert!(res.is_err())
}

#[test]
fn pow_target_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = Random::u32_range(3..64).unwrap();
    let pow = PoW::new(salt, params, difficulty).unwrap();
    let res = pow.target();
    assert!(res.is_ok())
}

#[test]
fn pow_target_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = Random::u32_range(3..64).unwrap();
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    pow.difficulty = 64;
    let res = pow.target();
    assert!(res.is_err())
}

#[test]
fn pow_target_bits_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = Random::u32_range(3..64).unwrap();
    let pow = PoW::new(salt, params, difficulty).unwrap();
    let _difficulty = pow.target_bits().unwrap();
    assert_eq!(difficulty, _difficulty);
}

#[test]
fn pow_mine_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 3;
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    let res = pow.mine();
    assert!(res.is_ok())
}

#[test]
fn pow_mine_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = Random::u32_range(3..64).unwrap();
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    pow.difficulty = 64;
    let res = pow.mine();
    assert!(res.is_err())
}

#[test]
fn pow_verify_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 3;
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    pow.mine().unwrap();
    if pow.digest.is_some() {
        let verified = pow.verify().unwrap();
        assert!(verified);
    }
}


#[test]
fn pow_verify_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 3;
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    pow.mine().unwrap();
    pow.digest = None;
    pow.nonce = None;
    let verified = pow.verify().unwrap();
    assert!(!verified);
}

#[test]
fn pow_validate_succ() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 3;
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    pow.mine().unwrap();
    if pow.digest.is_some() {
        let res = pow.validate();
        assert!(res.is_ok());
    }
}

#[test]
fn pow_validate_fail() {
    let salt_buf = Random::bytes(64);
    let salt = Digest::from_bytes(salt_buf.as_slice()).unwrap(); 
    let params = BalloonParams::default();
    let difficulty = 3;
    let mut pow = PoW::new(salt, params, difficulty).unwrap();
    pow.mine().unwrap();
    pow.digest = None;
    pow.nonce = None;
    let res = pow.validate();
    assert!(res.is_err());
}
