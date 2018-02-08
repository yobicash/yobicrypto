// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `point` module provides types and methods for ECC points on
//! Curve25519.

use curve25519::constants::ED25519_BASEPOINT_POINT;
use curve25519::edwards::CompressedEdwardsY;
use curve25519::edwards::ExtendedPoint as CurvePoint;
use curve25519::traits::Identity;
use subtle::Equal;
use hex;

use error::ErrorKind;
use result::Result;
use traits::Validate;
use traits::{BinarySerialize, HexSerialize};
use scalar::Scalar;

use std::ops::{Add, Sub, Mul};
use std::fmt;

/// A point is a ECC point on the Edwards form of Curve25519.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Point(pub CurvePoint);

impl Point {
    /// Creates a point from a byte array.
    pub fn new(b: [u8; 32]) -> Result<Point> {
        if let Some(_point) = CompressedEdwardsY(b).decompress() {
            Ok(Point(_point))
        } else {
            Err(ErrorKind::InvalidFormat.into())
        }
    }

    /// Creates a random `Point`.
    pub fn random() -> Result<Point> {
        let scalar = Scalar::random();
        let point = &Point::default() * &scalar;

        Ok(point)
    }
}

impl Default for Point {
    fn default() -> Point {
        let _point = ED25519_BASEPOINT_POINT;
        Point(_point)
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        self.0.ct_eq(&other.0) == 1
    }
}

impl Eq for Point {}

impl<'a, 'b> Add<&'b Point> for &'a Point {
    type Output = Point;

    fn add(self, other: &'b Point) -> Point {
        Point(self.0.add(&other.0))
    }
}

impl <'a, 'b> Sub<&'b Point> for &'a Point {
    type Output = Point;

    fn sub(self, other: &'b Point) -> Point {
        Point(self.0.sub(&other.0))
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Point {
    type Output = Point;

    fn mul(self, other: &'b Scalar) -> Point {
        Point(self.0.mul(&other.0))
    }
}

impl Identity for Point {
    fn identity() -> Point {
        Point(CurvePoint::identity())
    }
}

impl Validate for Point {
    fn validate(&self) -> Result<()> {
        if self.0.compress().decompress().is_none() {
            return Err(ErrorKind::InvalidFormat.into());
        }

        Ok(())
    }
}

impl BinarySerialize for Point {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok((&self.0.compress().to_bytes()[..]).to_owned())
    }

    fn from_bytes(b: &[u8]) -> Result<Point> {
        let len = b.len();
        if len != 32 {
            return Err(ErrorKind::InvalidLength.into());
        }

        let mut _point = [0u8; 32];

        (0..32).for_each(|i| _point[i] = b[i]);

        Point::new(_point)
    }
}

impl HexSerialize for Point {
    fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(&self.to_bytes()?))
    }

    fn from_hex(s: &str) -> Result<Point> {
        Self::from_bytes(&hex::decode(s)?)
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.to_hex().unwrap())
    }
}
