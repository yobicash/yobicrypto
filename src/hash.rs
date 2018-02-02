// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `hash` module provides types, traits, and methods for hashing.

use typenum::U64;
use generic_array::GenericArray;
use sha2::Digest as DigestTrait;
use sha2::Sha512;
use hex;

use error::ErrorKind;
use result::Result;
use traits::{JsonSerialize, BinarySerialize, HexSerialize, Serialize};

use std::fmt;

/// A digest is the result of a hashing operation.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Debug, Serialize, Deserialize)]
pub struct Digest(pub GenericArray<u8, U64>);

impl Digest {
    /// Hash with SHA3-512.
    pub fn hash(b: &[u8]) -> Digest {
        let mut hasher = Sha512::new();
        hasher.input(b);

        Digest(hasher.result())
    }
}

impl BinarySerialize for Digest {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.as_slice().to_owned())
    }

    fn from_bytes(b: &[u8]) -> Result<Digest> {
        let len = b.len();

        if len != 64 {
            return Err(ErrorKind::InvalidLength.into());
        }

        Ok(Digest(*GenericArray::from_slice(b)))
    }
}

impl HexSerialize for Digest {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<Digest> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl JsonSerialize for Digest {
    fn to_json(&self) -> Result<String> {
        self.to_hex()
    }

    fn from_json(s: &str) -> Result<Digest> {
        Self::from_hex(s)
    }
}

impl Serialize for Digest {}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}
