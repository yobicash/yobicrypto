// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! Ctaes native bindings.

#[macro_use]
extern crate failure;
extern crate typenum;
extern crate generic_array;
extern crate libc;

use failure::Error;
use typenum::{U15, U32};
use generic_array::{GenericArray, ArrayLength};
use libc::c_uchar;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct AES_state {
    pub slice: [u16; 8],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct AES256_ctx {
    pub rk: [AES_state; 15],
}

#[link_name = "ctaes"]
extern "C" {
    pub fn AES256_init(ctx: *mut AES256_ctx, key32: *const c_uchar);

    pub fn AES256_encrypt(
        ctx: *const AES256_ctx,
        blocks: usize,
        cipher16: *mut c_uchar,
        plain16: *const c_uchar,
    );

    pub fn AES256_decrypt(
        ctx: *const AES256_ctx,
        blocks: usize,
        plain16: *mut c_uchar,
        cipher16: *const c_uchar,
    );
}

#[derive(Debug, Copy, Clone, Default)]
pub struct AESGCMState(pub [u16; 8]);

impl AESGCMState {
    fn as_c_repr(&self) -> AES_state {
        AES_state { slice: self.0 }
    }

    fn from_c_repr(repr: AES_state) -> AESGCMState {
        AESGCMState(repr.slice)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct AESGCM256(pub GenericArray<AESGCMState, U15>);

impl AESGCM256 {
    fn as_c_repr(&self) -> AES256_ctx {
        let mut arr = [AES_state::default(); 15];
        for i in 0..15 {
            arr[i] = self.0[i].as_c_repr();
        }
        AES256_ctx { rk: arr }
    }

    fn from_c_repr(repr: AES256_ctx) -> AESGCM256 {
        let mut arr = GenericArray::<AESGCMState, U15>::default();
        for i in 0..15 {
            arr[i] = AESGCMState::from_c_repr(repr.rk[i]);
        }
        AESGCM256(arr)
    }
}

pub trait AESGCMCipher {
    type Ctx;
    type KeySize: ArrayLength<u8>;
    fn new(key: GenericArray<u8, Self::KeySize>) -> Self;
    fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&mut self, ciph: &[u8]) -> Result<Vec<u8>, Error>;
}

pub type AES256GCMKey = GenericArray<u8, U32>;

impl AESGCMCipher for AESGCM256 {
    type Ctx = AESGCM256;
    type KeySize = U32;

    fn new(key: AES256GCMKey) -> Self {
        let mut ctx = AES256_ctx::default();
        unsafe {
            AES256_init(&mut ctx, key.as_slice().as_ptr());
        }
        AESGCM256::from_c_repr(ctx)
    }

    fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let ctx = self.as_c_repr();
        let len = plain.len();
        if len % 16 != 0 {
            return Err(format_err!("invalid length"));
        }
        let blocks = len / 16;
        let mut ciph = Vec::new();
        for _ in 0..blocks {
            ciph.extend_from_slice(&[0u8; 16][..]);
        }
        unsafe {
            AES256_encrypt(&ctx, blocks, ciph.as_mut_ptr(), plain.as_ptr());
        }
        Ok(ciph)
    }

    fn decrypt(&mut self, ciph: &[u8]) -> Result<Vec<u8>, Error> {
        let ctx = self.as_c_repr();
        let len = ciph.len();
        if len % 16 != 0 {
            return Err(format_err!("invalid length"));
        }
        let blocks = len / 16;
        let mut plain = Vec::new();
        for _ in 0..blocks {
            plain.extend_from_slice(&[0u8; 16][..]);
        }
        unsafe {
            AES256_decrypt(&ctx, blocks, plain.as_mut_ptr(), ciph.as_ptr());
        }
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;

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
    fn aes_gcm_encrypt_test_vectors() {
        for v in test_vectors() {
            let key = *AES256GCMKey::from_slice(hex::decode(v.0).unwrap().as_slice());
            let mut cipher = AESGCM256::new(key);
            let res = cipher.encrypt(hex::decode(v.1).unwrap().as_slice()).unwrap();
            let test = hex::decode(v.2).unwrap();
            assert_eq!(res, test.as_slice())
        }
    }

    #[test]
    fn aes_gcm_decrypt_test_vectors() {
        for v in test_vectors() {
            let key = *AES256GCMKey::from_slice(hex::decode(v.0).unwrap().as_slice());
            let mut cipher = AESGCM256::new(key);
            let res = cipher.decrypt(hex::decode(v.2).unwrap().as_slice()).unwrap();
            let test = hex::decode(v.1).unwrap();
            assert_eq!(res, test.as_slice())
        }
    }
}
