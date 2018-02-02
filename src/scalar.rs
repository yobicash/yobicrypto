// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `scalar` module provides types, traits, and methods for modular
//! arithmetics on the field of q = 2^255.

use rand::thread_rng;
use sha2::Sha512;
use curve25519::scalar::Scalar as CurveScalar;
use hex;

use error::ErrorKind;
use result::Result;
use traits::Validate;
use traits::{JsonSerialize, BinarySerialize, HexSerialize, Serialize};

use std::ops::{Add, Sub, Mul};
use std::fmt;

/// A scalar of the field Zq with q = 2^255 in canonical representation
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Scalar(pub CurveScalar);

impl Scalar {
    /// Creates a scalar from a byte array.
    pub fn new(b: [u8; 32]) -> Result<Scalar> {
        if let Some(_s) = CurveScalar::from_canonical_bytes(b) {
            Ok(Scalar(_s))
        } else {
            Err(ErrorKind::InvalidFormat.into())
        }
    }

    /// Creates a scalar from a `u64`.
    pub fn from_u64(n: u64) -> Result<Scalar> {
        let _s = CurveScalar::from_u64(n);

        let s = Scalar(_s);
        Ok(s)
    }

    /// Creates a random scalar.
    pub fn random() -> Scalar {
        let mut rng = thread_rng();
        let _scalar = CurveScalar::random(&mut rng);
        Scalar(_scalar)
    }

    /// Creates a scalar from the hash of a message.
    pub fn from_hash(message: &[u8]) -> Scalar {
        let _scalar = CurveScalar::hash_from_bytes::<Sha512>(message);
        Scalar(_scalar)
    }
}

impl Default for Scalar {
    fn default() -> Scalar {
        let b = [0u8; 32];
        Scalar::new(b).unwrap()
    }
}

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    fn add(self, other: &'b Scalar) -> Scalar {
        Scalar(self.0.add(&other.0))
    }
}

impl <'a, 'b> Sub<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    fn sub(self, other: &'b Scalar) -> Scalar {
        Scalar(self.0.sub(&other.0))
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    fn mul(self, other: &'b Scalar) -> Scalar {
        Scalar(self.0.mul(&other.0))
    }
}

impl Validate for Scalar {
    fn validate(&self) -> Result<()> {
        if !self.0.is_canonical() {
            Err(ErrorKind::InvalidFormat.into())
        } else {
            Ok(())
        }
    }
}

impl BinarySerialize for Scalar {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes()[..].to_owned())
    }

    fn from_bytes(b: &[u8]) -> Result<Scalar> {
        let len = b.len();
        if len != 32 {
            return Err(ErrorKind::InvalidLength.into())
        }

        let mut _scalar = [0u8; 32];

        (0..32).for_each(|i| _scalar[i] = b[i]);

        Scalar::new(_scalar)
    }
}

impl HexSerialize for Scalar {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<Scalar> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl JsonSerialize for Scalar {
    fn to_json(&self) -> Result<String> {
        self.to_hex()
    }

    fn from_json(s: &str) -> Result<Scalar> {
        Self::from_hex(s)
    }
}

impl Serialize for Scalar {}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}
