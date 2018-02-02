// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `encrypt` module provides encryption types, traits, and functions.

use typenum::U32;
use generic_array::GenericArray;
use digest::Digest;
use curve25519::scalar::Scalar as CurveScalar;
use sha2::Sha512Trunc256;
use ctaes_sys::*;
use hex;

use error::ErrorKind;
use result::Result;
use traits::Validate;
use traits::{JsonSerialize, BinarySerialize, HexSerialize, Serialize};
use scalar::Scalar;
use point::Point;

use std::fmt;

/// A secret key is a secret field scalar used for ECIES encryption.
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct SecretKey(Scalar);

impl SecretKey {
    /// Creates a `SecretKey` from a byte array.
    pub fn new(b: [u8; 32]) -> Result<SecretKey> {
        Ok(SecretKey(Scalar::new(b)?))
    }

    /// Creates a random `SecretKey`.
    pub fn random() -> SecretKey {
        SecretKey(Scalar::random())
    }

    /// Converts the `SecretKey` to a `PublicKey`.
    pub fn to_public(&self) -> PublicKey {
        PublicKey::new(*self)
    }
}

impl BinarySerialize for SecretKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes()
    }

    fn from_bytes(b: &[u8]) -> Result<SecretKey> {
        Ok(SecretKey(Scalar::from_bytes(b)?))
    }
}

impl HexSerialize for SecretKey {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<SecretKey> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl JsonSerialize for SecretKey {
    fn to_json(&self) -> Result<String> {
        self.to_hex()
    }

    fn from_json(s: &str) -> Result<SecretKey> {
        Self::from_hex(s)
    }
}

impl Serialize for SecretKey {}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}

/// A public key is a publicable ECC point used for ECIES encryption.
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct PublicKey(Point);

impl PublicKey {
    /// Creates a `PublicKey` from a `SecretKey`.
    pub fn new(sk: SecretKey) -> PublicKey {
        let _pk = &Point::default() * &sk.0;

        PublicKey(_pk)
    }
}

impl Validate for PublicKey {
    fn validate(&self) -> Result<()> {
        self.0.validate()
    }
}

impl BinarySerialize for PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes()
    }

    fn from_bytes(b: &[u8]) -> Result<PublicKey> {
        Ok(PublicKey(Point::from_bytes(b)?))
    }
}

impl HexSerialize for PublicKey {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<PublicKey> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl JsonSerialize for PublicKey {
    fn to_json(&self) -> Result<String> {
        self.to_hex()
    }

    fn from_json(s: &str) -> Result<PublicKey> {
        Self::from_hex(s)
    }
}

impl Serialize for PublicKey {}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}

/// An encryption key is a 32 bytes byte array used for encryption.
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct SharedKey(GenericArray<u8, U32>);

impl SharedKey {
    /// Creates a new `SharedKey` with x25519 Diffie-Hellman.
    pub fn new(sk: SecretKey, pk: PublicKey) -> Result<SharedKey> {
        pk.validate()?;

        if sk.to_public() == pk {
            return Err(ErrorKind::InvalidLength.into());
        }

        let _point = (pk.0).0.to_montgomery();
        let mut _sk = ((sk.0).0).to_bytes();

        // scrabbling?

        let s = CurveScalar::from_bits(_sk);

        let mut hasher = Sha512Trunc256::new();
        hasher.input(&(&_point * &s).compress().to_bytes()[..]);
        let _key = hasher.result();

        Ok(SharedKey(_key))
    }

    /// Converts to AES256GCMKey
    fn to_aes_key(&self) -> AES256GCMKey {
        self.0
    }
}

impl BinarySerialize for SharedKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.as_slice().to_owned())
    }

    fn from_bytes(b: &[u8]) -> Result<SharedKey> {
        let len = b.len();
        if len != 32 {
            return Err(ErrorKind::InvalidLength.into())
        }

        Ok(SharedKey(*GenericArray::from_slice(b)))
    }
}

impl HexSerialize for SharedKey {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<SharedKey> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl JsonSerialize for SharedKey {
    fn to_json(&self) -> Result<String> {
        self.to_hex()
    }

    fn from_json(s: &str) -> Result<SharedKey> {
        Self::from_hex(s)
    }
}

impl Serialize for SharedKey {}

impl fmt::Display for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}


/// Decrypts a plaintext with AESGMC256.
pub fn sym_encrypt(key: SharedKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut plain = Vec::new();
    plain.extend_from_slice(plaintext);

    let len = plaintext.len();
    
    let (blocks_rem, blocks_len) = if len % 16 != 0 {
        let rem = 16 - (len % 16);
        let len = (len / 16) + 1;
        (rem, len)
    } else {
        (0, len / 16)
    };

    for _ in 0..blocks_rem {
        plain.push(0);
    }

    let mut cyph = Vec::new();

    // TODO: permute key each time, to increase safety

    for i in 0..blocks_len {
        let start = 16*i;
        let stop = 16*(i+1);
        let mut encryptor = AESGCM256::new(key.to_aes_key());
        let cyphertext = encryptor.encrypt(&plain[start..stop])?;
        cyph.extend_from_slice(&cyphertext);
    }


    Ok(cyph)
}

/// Encrypts a plaintext with [STREAM](https://eprint.iacr.org/2015/189.pdf)
/// but generates the key with x25519.
pub fn assym_encrypt(sk: SecretKey, pk: PublicKey, plain: &[u8]) -> Result<Vec<u8>> {
    let key = SharedKey::new(sk, pk)?;

    sym_encrypt(key, plain)
}

/// Decrypts a cyphertext encrypted with AESGMC256.
pub fn sym_decrypt(key: SharedKey, cyph: &[u8], size: u32) -> Result<Vec<u8>> {
    if size > cyph.len() as u32 {
        return Err(ErrorKind::InvalidLength.into());
    }
    
    let mut plain = Vec::new();

    let blocks_len = cyph.len() / 16;

    // TODO: permute key each time, to increase safety

    for i in 0..blocks_len {
        let start = 16*i;
        let stop = 16*(i+1);
        let mut decryptor = AESGCM256::new(key.to_aes_key());
        let plaintext = decryptor.decrypt(&cyph[start..stop])?;
        plain.extend_from_slice(&plaintext);
    }

    plain = Vec::from(&plain[0..size as usize]);

    Ok(plain)
}

/// Decrypts a cyphertext encrypted with AESGMC256 and generates
/// the key with x25519.
pub fn assym_decrypt(sk: SecretKey, pk: PublicKey, cyph: &[u8], size: u32) -> Result<Vec<u8>> {
    let key = SharedKey::new(sk, pk)?;

    sym_decrypt(key, cyph, size)
}
