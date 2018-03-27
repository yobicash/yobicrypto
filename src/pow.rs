// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `pow` module provides types and methods for `PoW` mining.

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use hex;

use error::ErrorKind;
use result::Result;
use traits::Validate;
use traits::{BinarySerialize, HexSerialize};
use hash::Digest;
use memory::Memory;
use balloon::{BalloonParams, BalloonHasher};

use std::fmt;

/// Target digest used in `PoW`.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct PoWTarget(Digest);

impl PoWTarget {
    /// Creates a new `PoWTarget` from the number of bits that should be
    /// set to 0.
    pub fn new(bits: u32) -> Result<PoWTarget> {
        if bits > 63 {
            return Err(ErrorKind::OutOfBound.into());
        }

        let n = u64::max_value() >> (bits as usize);
        let mut b = Vec::new();
        b.write_u64::<BigEndian>(n)?;
        for _ in 0..56 {
            b.push(255u8);
        }
        let target = PoWTarget(Digest::from_bytes(&b[..])?);
        Ok(target)
    }

    /// Returns the bits set to 0 in `PoWTarget`.
    pub fn bits(&self) -> Result<u32> {
        let n = BigEndian::read_u64(&self.0.to_bytes()?);
        let bits = n.leading_zeros() as u32;
        Ok(bits)
    }

    /// Returns the underlying digest.
    pub fn digest(&self) -> Digest {
        self.0
    }
}

impl Default for PoWTarget {
    fn default() -> PoWTarget {
        PoWTarget::new(3).unwrap()
    }
}

impl Validate for PoWTarget {
    fn validate(&self) -> Result<()> {
        let bits = self.bits()?;

        if bits > 63 {
            return Err(ErrorKind::OutOfBound.into());
        }

        Ok(())
    }
}

impl BinarySerialize for PoWTarget {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes()
    }

    fn from_bytes(b: &[u8]) -> Result<PoWTarget> {
        Ok(PoWTarget(Digest::from_bytes(b)?))
    }
}

impl HexSerialize for PoWTarget {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<PoWTarget> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl fmt::Display for PoWTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}


/// The type used for Balloon hashing `PoW`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct PoW {
    /// The salt used by `BalloonHasher`.
    pub salt: Digest,
    /// The params of `BallonHasher`.
    pub params: BalloonParams,
    /// The `PoWTarget` bits.
    pub difficulty: u32,
    /// The nonce found, if any.
    pub nonce: Option<u64>,
    /// The digest found, if any.
    pub digest: Option<Digest>,
}

impl PoW {
    /// Creates a new `PoW`.
    pub fn new(salt: Digest, params: BalloonParams, difficulty: u32) -> Result<PoW> {
        if difficulty < 3 || difficulty > 63 {
            return Err(ErrorKind::OutOfBound.into());
        }
        
        params.validate()?;

        let pow = PoW {
            salt: salt,
            params: params,
            difficulty: difficulty,
            nonce: None,
            digest: None,
        };

        Ok(pow)
    }

    /// Creates a new `PoW` deriving the parameters from a memory target.
    pub fn from_memory(salt: Digest, memory: &Memory, difficulty: u32) -> Result<PoW> {
        let params = BalloonParams::from_memory(memory)?;

        PoW::new(salt, params, difficulty)
    }

    /// Returns the hasher of the `PoW`.
    pub fn hasher(&self) -> Result<BalloonHasher> {
        BalloonHasher::new(self.salt, self.params)
    }

    /// Returns the memory used per iteration by the `PoW`.
    pub fn memory(&self) -> Result<Memory> {
        let hasher = self.hasher()?;

        hasher.memory()
    }

    /// Returns the target of the `PoW`.
    pub fn target(&self) -> Result<PoWTarget> {
        let difficulty = self.difficulty;

        if difficulty < 3 || difficulty > 63 {
            return Err(ErrorKind::OutOfBound.into());
        }
        
        PoWTarget::new(difficulty)
    }

    /// Returns the target bits of the `PoW`.
    pub fn target_bits(&self) -> Result<u32> {
        self.target()?.bits()
    }
    
    /// Mine the `PoW`.
    pub fn mine(&mut self) -> Result<()> {
        let target_digest = self.target()?.digest();
        let mut nonce = 0;

        'mining: loop {
            let balloon = self.hasher()?;

            let mut digest_buf = Vec::new();
            digest_buf.extend_from_slice(&self.salt.to_bytes()?);
            digest_buf.write_u64::<BigEndian>(nonce)?;
            
            let digest = balloon.hash(&digest_buf)?;
            if digest < target_digest {
                self.nonce = Some(nonce);
                self.digest = Some(digest);
                break 'mining;
            } else {
                if nonce == u64::max_value() {
                    break 'mining;
                }
                nonce += 1;
            }
        }

        Ok(())
    }

    /// Verify if it is mined.
    pub fn verify(&self) -> Result<bool> {
        if let Some(digest) = self.digest {
            let target_digest = self.target()?.digest();
            if digest >= target_digest {
                return Err(ErrorKind::InvalidDigest.into());
            }
            
            if self.nonce.is_none() {
                return Ok(false);
            }

            let nonce = self.nonce.unwrap();
            let mut digest_buf = Vec::new();
            digest_buf.extend_from_slice(&self.salt.to_bytes()?);
            digest_buf.write_u64::<BigEndian>(nonce)?;

            let balloon = self.hasher()?;
            let _digest = balloon.hash(&digest_buf)?;
            if digest != _digest {
                return Err(ErrorKind::InvalidDigest.into());
            }
        } else {
            return Ok(false);
        }

        Ok(true)
    }
}

impl Validate for PoW {
    fn validate(&self) -> Result<()> {
        let mined = self.verify()?;
        
        if !mined {
            return Err(ErrorKind::NotFound.into());
        }

        Ok(())
    }
}
