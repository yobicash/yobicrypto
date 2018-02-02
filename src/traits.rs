// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `traits` module provides the traits used throughout `libyobicash`.

use result::Result;

/// Trait for types that can be validated.
pub trait Validate {
    /// Validate the object.
    fn validate(&self) -> Result<()>;
}

/// Trait for types that can be identified.
pub trait Identify {
    /// Type of the identifier.
    type ID;

    /// Return the `ID` of the implementor.
    fn id(&self) -> Result<Self::ID>;
    
    /// Return the binary representation of the `ID` of the object.
    fn binary_id(&self) -> Result<Vec<u8>> {
        Self::id_to_bytes(self.id()?)
    }

    /// Convert a byte array to an `ID`.
    fn id_from_bytes(b: &[u8]) -> Result<Self::ID>;
    
    /// Convert an `ID` to bytes.
    fn id_to_bytes(id: Self::ID) -> Result<Vec<u8>>;
}

/// Trait for object that can be serialized from and to binary.
pub trait BinarySerialize: Sized {
    /// Serialize to a binary.
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Deserialize from a binary.
    fn from_bytes(b: &[u8]) -> Result<Self>;
}

/// Trait for object that can be serialized from and to HEX.
pub trait HexSerialize: Sized {
    /// Serialize to a hex string.
    fn to_hex(&self) -> Result<String>;

    /// Deserialize from a hex string.
    fn from_hex(s: &str) -> Result<Self>;
}
