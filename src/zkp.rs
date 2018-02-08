// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `zkp` module provides Schnorr Algorithm types and methods.

use hex;

use error::ErrorKind;
use result::Result;
use traits::Validate;
use traits::{BinarySerialize, HexSerialize};
use scalar::Scalar;
use point::Point;

use std::io::Write;
use std::fmt;

/// The ZKP witness is the publicly known variable of the relation R(x, w)
/// in the language L of the statements of the type `w = g^x`, for g
/// a generator of an elliptic curve G. The receiver uses the Schnorr Protocol
/// to prove that she know an x that verifies w = g^x, without revealing the
/// value of x. In this way we can build a simple anonymous credential system.
///
/// See the `ZKPProof` type and the `output` module to see its usage.
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct ZKPWitness(pub Point);

impl ZKPWitness {
    /// Creates a new `ZKPWitness` from a secret instance.
    pub fn new(instance: Scalar) -> Result<ZKPWitness> {
        instance.validate()?;

        Ok(ZKPWitness(&Point::default() * &instance))
    }

    /// Creates a  new `ZKPWitness` from a `Point`.
    pub fn from_point(point: Point) -> Result<ZKPWitness> {
        point.validate()?;

        Ok(ZKPWitness(point))
    }

    /// Returns the underlying `Point`.
    pub fn to_point(&self) -> Point {
        self.0
    }
}

impl Validate for ZKPWitness {
    fn validate(&self) -> Result<()> {
        self.0.validate()
    }
}

impl BinarySerialize for ZKPWitness {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes()
    }

    fn from_bytes(b: &[u8]) -> Result<ZKPWitness> {
        Ok(ZKPWitness(Point::from_bytes(b)?))
    }
}

impl HexSerialize for ZKPWitness {
    fn to_hex(&self) -> Result<String> {
        self.0.to_hex()
    }

    fn from_hex(s: &str) -> Result<ZKPWitness> {
        Ok(ZKPWitness(Point::from_hex(s)?))
    }
}

impl fmt::Display for ZKPWitness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}

/// The ZKP proof is a non-interactive cryptographical proof of the knowledge
/// of a secret value `x` for wich `w = g^x` is true, where g is a generator
/// of the elliptic curve G.  
///
/// See the `input` module to see its usage.
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct ZKPProof {
    /// The public coin, a `Point` t = g^v, where v is a (pseudo-)random `Scalar` and g
    /// the base point.
    pub public_coin: Point,
    /// The challenge, a `Scalar` c = H(g, w, t), where g is the base point,
    /// w the witness Point, and t the public coin.
    pub challenge: Scalar,
    /// The response, a `Scalar` r = v - c*x, where v is the (pseudo-)random `Scalar`
    /// used to obtain the public coin, c is the challenge and x is the secret instance.
    pub response: Scalar, // r = v - cx mod q-1; accepts if t = (g^r)*(w^c) mod q
}

impl ZKPProof {
    /// Creates a zero-knowledge proof from a witness instance and a message. 
    pub fn new(instance: Scalar, message: &[u8]) -> Result<ZKPProof> {
        let g = Point::default();

        let witness = &g * &instance;
        let public_coin_scalar = Scalar::from_hash(message);
        let public_coin = &g * &public_coin_scalar;

        let mut buf = Vec::new();
        buf.write_all(&g.to_bytes()?)?;
        buf.write_all(&witness.to_bytes()?)?;
        buf.write_all(&public_coin.to_bytes()?)?;
        
        let challenge = Scalar::from_hash(&buf);

        let response = &public_coin_scalar - &(&challenge*&instance);

        Ok(ZKPProof {
            public_coin: public_coin,
            challenge: challenge,
            response: response,
        })
    }

    /// Verifies the zero-knowledge proof against a witness.
    pub fn verify(&self, witness: ZKPWitness) -> Result<bool> {
    // r = v - cx mod q-1; accepts if t = (g^r)*(w^c) mod q
        witness.validate()?;
        
        let g = Point::default();

        let gr = &g * &self.response;
        let wc = &witness.to_point() * &self.challenge;

        Ok(self.public_coin == &gr + &wc)
    }
}

impl Validate for ZKPProof {
    fn validate(&self) -> Result<()> {
        self.public_coin.validate()?;
        self.challenge.validate()?;
        self.response.validate()?;

        Ok(())
    }
}

impl BinarySerialize for ZKPProof {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.write_all(&self.public_coin.to_bytes()?)?;
        buf.write_all(&self.challenge.to_bytes()?)?;
        buf.write_all(&self.response.to_bytes()?)?;

        Ok(buf)
    }

    fn from_bytes(b: &[u8]) -> Result<ZKPProof> {
        if b.len() != 96 {
            return Err(ErrorKind::InvalidLength.into());
        }

        let public_coin = Point::from_bytes(&b[0..32])?;
        let challenge = Scalar::from_bytes(&b[32..64])?;
        let response = Scalar::from_bytes(&b[64..])?;

        Ok(ZKPProof {
            public_coin: public_coin,
            challenge: challenge,
            response: response,
        })
    }
}

impl HexSerialize for ZKPProof {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<ZKPProof> {
        Self::from_bytes(&hex::decode(s)?)
    }
}
