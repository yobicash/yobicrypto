// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

extern crate yobicrypto;
extern crate hex;

use yobicrypto::Random;
use yobicrypto::{SecretKey, PublicKey, SharedKey};
use yobicrypto::{sym_encrypt, sym_decrypt};
use yobicrypto::{assym_encrypt, assym_decrypt};
use yobicrypto::HexSerialize;

fn test_vectors() -> Vec<(String, String, String)> {
    vec![
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
            "00112233445566778899aabbccddeeff".to_string(),
            "8ea2b7ca516745bfeafc49904b496089".to_string()
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".to_string(),
            "6bc1bee22e409f96e93d7e117393172a".to_string(),
            "f3eed1bdb5d2a03c064b5a7e3db181f8".to_string()
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".to_string(),
            "ae2d8a571e03ac9c9eb76fac45af8e51".to_string(),
            "591ccb10d410ed26dc5ba74a31362870".to_string()
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".to_string(),
            "30c81c46a35ce411e5fbc1191a0a52ef".to_string(),
            "b6ed21b99ca6f4f9f153e7b1beafed1d".to_string()
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".to_string(),
            "f69f2445df4f9b17ad2b417be66c3710".to_string(),
            "23304b7a39f9f3ff067d8d8f9e24ecc7".to_string()
        ),
    ]
}

#[test]
fn sym_encrypt_test_vectors() {
    for v in test_vectors() {
        let key = SharedKey::from_hex(&v.0).unwrap();
        let plain = hex::decode(v.1).unwrap();
        let res = sym_encrypt(key, &plain).unwrap();
        let cyph = hex::decode(v.2).unwrap();
        assert_eq!(res, cyph)
    }
}

#[test]
fn sym_decrypt_test_vectors() {
    for v in test_vectors() {
        let key = SharedKey::from_hex(&v.0).unwrap();
        let cyph = hex::decode(v.2).unwrap();
        let plain = hex::decode(v.1).unwrap();
        let size = plain.len() as u32;
        let res = sym_decrypt(key, &cyph, size).unwrap();
        assert_eq!(res, plain)
    }
}

#[test]
fn shared_key_succ() {
    let sk_a = SecretKey::random();
    let sk_b = SecretKey::random();
    let pk_a = sk_a.to_public();
    let pk_b = sk_b.to_public();
    let key_a = SharedKey::new(sk_a, pk_b).unwrap();
    let key_b = SharedKey::new(sk_b, pk_a).unwrap();
    assert_eq!(key_a, key_b)
}

#[test]
fn shared_key_fail() {
    let sk_a = SecretKey::random();
    let sk_other_a = SecretKey::random();
    let sk_b = SecretKey::random();
    let pk_other_a = PublicKey::new(sk_other_a);
    let pk_b = sk_b.to_public();
    let key_a = SharedKey::new(sk_a, pk_b).unwrap();
    let wrong_key_b = SharedKey::new(sk_b, pk_other_a).unwrap();
    assert_ne!(key_a, wrong_key_b)
}

#[test]
fn assym_encrypt_succ() {
    let sk_a = SecretKey::random();
    let sk_b = SecretKey::random();
    let pk_b = sk_b.to_public();
    let mut plain = [0u8; 16];
    Random::bytes_mut(&mut plain);
    let res = assym_encrypt(sk_a, pk_b, &plain[..]);
    assert!(res.is_ok())
}

#[test]
fn assym_decrypt_succ() {
    let sk_a = SecretKey::random();
    let sk_b = SecretKey::random();
    let pk_a = sk_a.to_public();
    let pk_b = sk_b.to_public();
    let size = Random::u32_range(1..100).unwrap();
    let plain_a = Random::bytes(size);
    let cyph = assym_encrypt(sk_a, pk_b, &plain_a).unwrap();
    let plain_b = assym_decrypt(sk_b, pk_a, &cyph, size).unwrap();
    assert_eq!(plain_a, plain_b)
}

#[test]
fn assym_decrypt_fail() {
    let sk_a = SecretKey::random();
    let sk_b = SecretKey::random();
    let pk_a = sk_a.to_public();
    let pk_b = sk_b.to_public();
    let size = Random::u32_range(1..100).unwrap();
    let plain_a = Random::bytes(size);
    let mut cyph = assym_encrypt(sk_a, pk_b, &plain_a).unwrap();
    cyph[0] ^= cyph[0];
    let plain_b = assym_decrypt(sk_b, pk_a, &cyph, size).unwrap();
    assert_ne!(plain_a, plain_b)
}
