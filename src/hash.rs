// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `hash` module provides types and methods for hashing.

use typenum::U64;
use generic_array::GenericArray;
use sha2::Digest as DigestTrait;
use sha2::Sha512;
use hex;

use error::ErrorKind;
use result::Result;
use traits::{BinarySerialize, HexSerialize};

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

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}
