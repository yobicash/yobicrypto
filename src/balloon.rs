// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `balloon` module provides types and methods for balloon hashing.

use byteorder::{BigEndian, WriteBytesExt};
use rmp_serde::encode as encode_msgpk;
use rmp_serde::decode as decode_msgpk;
use hex;

use error::ErrorKind;
use result::Result;
use traits::Validate;
use traits::{BinarySerialize, HexSerialize};
use hash::Digest;
use memory::Memory;

use std::fmt;

/// Params used in Balloon hashing.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct BalloonParams {
    /// The s_cost parameter used in Balloon hashing.
    pub s_cost: u32,
    /// The t_cost parameter used in Balloon hashing.
    pub t_cost: u32,
    /// The delta parameter used in Balloon hashing.
    pub delta: u32,
}

impl BalloonParams {
    /// Creates a new `BalloonParams`.
    pub fn new(s_cost: u32, t_cost: u32, delta: u32) -> Result<BalloonParams> {
        if s_cost == 0 {
            return Err(ErrorKind::InvalidArgument.into());
        }

        if t_cost == 0 {
            return Err(ErrorKind::InvalidArgument.into());
        }
        
        if delta < 3 {
            return Err(ErrorKind::InvalidArgument.into());
        }
        
        Ok(BalloonParams {
            s_cost: s_cost,
            t_cost: t_cost,
            delta: delta,
        })
    }

    /// Creates a new `BalloonParams` given a target memory.
    pub fn from_memory(target_memory: &Memory) -> Result<BalloonParams> {
        let mut params = BalloonParams::default();
        let default_memory = params.memory()?;
        
        if target_memory.clone() < default_memory {
            return Err(ErrorKind::InvalidArgument.into());
        }

        if target_memory.clone() == default_memory {
            return Ok(params);
        }

        loop {
            params.s_cost += 1 - (params.s_cost / u32::max_value());
            
            let test_memory = params.memory()?;

            if test_memory >= target_memory.clone() {
                return Ok(params);
            }
            
            params.t_cost += 1 - (params.t_cost / u32::max_value());
            
            let test_memory = params.memory()?;

            if test_memory >= target_memory.clone() {
                return Ok(params);
            }
            
            params.delta += 1 - (params.delta / u32::max_value());
            
            let test_memory = params.memory()?;

            if test_memory >= target_memory.clone() {
                return Ok(params);
            }

            if params.s_cost == u32::max_value() &&
                params.t_cost == u32::max_value() &&
                params.delta == u32::max_value() {
                break;
            }
        }


        Err(ErrorKind::NotFound.into())
    }

    /// Returns the memory that would be spent in the hashing operation.
    pub fn memory(&self) -> Result<Memory> {
        self.validate()?;

        let a = Memory::from(self.s_cost);
        let b = Memory::from(self.t_cost);
        let c = Memory::from(self.delta);

        let digest_size = Memory::from(64);
        let two = Memory::from(2);
        let one = Memory::from(1);

        let memory = digest_size * (a + (b - &one) * &(one.clone() + &(two * (c - &one))));

        Ok(memory)
    }
}

impl Default for BalloonParams {
    fn default() -> BalloonParams {
        BalloonParams {
            s_cost: 1,
            t_cost: 1,
            delta: 3,
        }
    }
}

impl Validate for BalloonParams {
    fn validate(&self) -> Result<()> {
        if self.s_cost == 0 {
            return Err(ErrorKind::InvalidArgument.into());
        }
        
        if self.t_cost == 0 {
            return Err(ErrorKind::InvalidArgument.into());
        }
        
        if self.delta < 3 {
            return Err(ErrorKind::InvalidArgument.into());
        }
        
        Ok(())
    }
}

impl BinarySerialize for BalloonParams {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_msgpk::to_vec(self)
            .map_err(|_| ErrorKind::SerializationFailure.into())
    }
    
    fn from_bytes(b: &[u8]) -> Result<BalloonParams> {
        use std::error::Error as StdError;

        decode_msgpk::from_slice(b)
            .map_err(|e| {
                    println!("des. error: {}", e.description());     
                    ErrorKind::DeserializationFailure.into()
            })
    }
}

impl HexSerialize for BalloonParams {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }
    
    fn from_hex(s: &str) -> Result<BalloonParams> {
        Self::from_bytes(hex::decode(s)?.as_slice())
    }
}

impl fmt::Display for BalloonParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}


/// Hasher implementing Balloon hashing.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BalloonHasher {
    pub salt: Digest,
    pub params: BalloonParams,
}

impl BalloonHasher {
    /// Creates a new `BalloonHasher`.
    pub fn new(salt: Digest, params: BalloonParams) -> Result<BalloonHasher> {
        params.validate()?;

        Ok(BalloonHasher {
            salt: salt,
            params: params,
        })
    }

    /// Creates a new `BalloonHasher` given a target memory.
    pub fn from_memory(salt: Digest, memory: &Memory) -> Result<BalloonHasher> {
        let params = BalloonParams::from_memory(memory)?;

        BalloonHasher::new(salt, params)
    }

    /// Returns the memory that would be spent in the hashing operation.
    pub fn memory(&self) -> Result<Memory> {
        self.validate()?;

        self.params.memory()
    }

    /// Hashes a message.
    pub fn hash(&self, msg: &[u8]) -> Result<Digest> {
        self.validate()?;

        let mut cnt = 0u32;
        let mut buf = Vec::new();

        for _ in 0..self.params.s_cost {
            buf.push(Digest::default())
        }

        let mut buf_0 = Vec::new();
        buf_0.write_u32::<BigEndian>(cnt)?;
        cnt += 1;
        buf_0.extend_from_slice(msg);
        buf_0.extend_from_slice(&self.salt.to_bytes()?);

        buf[0] = Digest::hash(&buf_0);

        for m in 1..self.params.s_cost as usize {

            let mut buf_m_1 = Vec::new();
            buf_m_1.write_u32::<BigEndian>(cnt)?;
            cnt += 1;
            buf_m_1.extend_from_slice(&buf[m-1].to_bytes()?);

            buf[m] = Digest::hash(&buf_m_1);
        }

        // TODO: fix the algo online, contact the guys (t > 0)
        for t in 0..(self.params.t_cost-1) as usize {
            // TODO: fix the algo online, contact the guys
            for m in 1..(self.params.s_cost-1) as usize {

                let prev = buf[(m-1 as usize) % self.params.s_cost as usize];
                let mut buf_m_2 = Vec::new();
                buf_m_2.write_u32::<BigEndian>(cnt)?;
                cnt += 1;
                buf_m_2.extend_from_slice(&prev.to_bytes()?);
                buf_m_2.extend_from_slice(&buf[m].to_bytes()?);

                buf[m] = Digest::hash(&buf_m_2);

                for i in 0..(self.params.delta-1) as usize {
                    // NB: block obtained by hashing
                    let mut buf_idx_block = Vec::new();
                    buf_idx_block.write_u32::<BigEndian>(t as u32)?;
                    buf_idx_block.write_u32::<BigEndian>(m as u32)?;
                    buf_idx_block.write_u32::<BigEndian>(i as u32)?;
                    let idx_block = Digest::hash(&buf_idx_block);

                    let mut buf_i_1 = Vec::new();
                    buf_i_1.write_u32::<BigEndian>(cnt)?;
                    cnt += 1;
                    buf_i_1.extend_from_slice(&self.salt.to_bytes()?);
                    buf_i_1.extend_from_slice(&idx_block.to_bytes()?);

                    // TODO: should we hear those guys even here?
                    let other_buf = Digest::hash(&buf_i_1).to_bytes()?;
                    let mut other: u32 = 0;
                    for i in other_buf.iter().take(64) {
                        other += u32::from(*i);
                    }
                    other %= self.params.s_cost;

                    let mut buf_i_2 = Vec::new();
                    buf_i_2.write_u32::<BigEndian>(cnt)?;
                    cnt += 1;
                    buf_i_2.extend_from_slice(&buf[m].to_bytes()?);
                    buf_i_2.extend_from_slice(&buf[other as usize].to_bytes()?);

                    buf[m] = Digest::hash(&buf_i_2);
                }
            }
        }

        Ok(buf[(self.params.s_cost-1) as usize])
    }
}

impl Validate for BalloonHasher {
    fn validate(&self) -> Result<()> {
        self.params.validate()
    }
}
