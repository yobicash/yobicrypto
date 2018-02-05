// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! Yobicrypto is the cryptographic toolkit used by the `Yobicash` cryptocurrency.
//! It implements symmetric and assymmetric encryption (AES256, x25519),
//! zero-knowledge proofs using the Schnorr Protocol (curve25519) made non-interactive
//! with the Fiat-Shamir Transform (SHA3-512), and proof-of-work through Balloon Hashing
//! ("such alpha, such CPU"). Caveat emptor.


extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rmp;
extern crate rmp_serde;
extern crate hex;
extern crate typenum;
extern crate generic_array;
extern crate digest;
extern crate sha2;
extern crate subtle;
extern crate curve25519_dalek as curve25519;
extern crate ctaes_sys;
extern crate rand;
extern crate rug;
extern crate byteorder;

pub mod error;
pub mod result;
pub mod traits;
pub mod random;
pub mod hash;
pub mod balloon;
pub mod pow;
pub mod scalar;
pub mod point;
pub mod zkp;
pub mod encrypt;

pub use self::error::*;
pub use self::result::*;
pub use self::traits::*;
pub use self::random::*;
pub use self::hash::*;
pub use self::balloon::*;
pub use self::pow::*;
pub use self::scalar::*;
pub use self::point::*;
pub use self::zkp::*;
pub use self::encrypt::*;
