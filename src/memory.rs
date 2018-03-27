// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `memory` module provides the memory type and methods.

use rug::Integer;
use rug::ops::Pow;

use result::Result;

use std::fmt;
use std::cmp::Eq;
use std::convert::From;
use std::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Div, DivAssign};

/// Type used for memorys and balances.
#[derive(Clone, Ord, PartialOrd, Debug, Default, Serialize, Deserialize)]
pub struct Memory(Integer);

impl Memory {
    /// Creates a new `Memory`.
    pub fn new() -> Memory {
        Memory(Integer::new())
    }

    /// Returns the 0 Memory.
    pub fn zero() -> Memory {
        Memory::new()
    }

    /// Returns the 1 Memory.
    pub fn one() -> Memory {
        Memory(1u32.into())
    }

    /// Power operation on an Memory.
    pub fn pow(&self, exp: u32) -> Memory {
        Memory(self.0.clone().pow(exp))
    }

    /// Converts the `Memory` to u32.
    pub fn to_u32(&self) -> Option<u32> {
        self.0.to_u32()
    }

    /// Converts the `Memory` to u64.
    pub fn to_u64(&self) -> Option<u64> {
        self.0.to_u64()
    }

    /// Converts the `Memory` to f32.
    pub fn to_f32(&self) -> f32 {
        self.0.to_f32()
    }

    /// Converts the `Memory` to f64.
    pub fn to_f64(&self) -> f64 {
        self.0.to_f64()
    }

    /// Converts the `Memory` to string.
    pub fn to_string(&self) -> String {
        self.0.to_string_radix(10)
    }

    /// Creates an `Memory` from a string.
    pub fn from_string(s: &str) -> Result<Memory> {
        Ok(Memory(Integer::from_str_radix(s, 10)?))
    }
}

impl fmt::Display for Memory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for Memory {
    fn eq(&self, other: &Memory) -> bool {
        self.0.eq(&other.0) 
    }
}

impl Eq for Memory {}

impl From<u32> for Memory {
    fn from(n: u32) -> Memory {
        Memory(Integer::from_f32(n as f32).unwrap())
    }
}

impl From<u64> for Memory {
    fn from(n: u64) -> Memory {
        Memory(Integer::from_f64(n as f64).unwrap())
    }
}

impl From<i32> for Memory {
    fn from(n: i32) -> Memory {
        Memory(Integer::from_f32(n as f32).unwrap())
    }
}

impl From<i64> for Memory {
    fn from(n: i64) -> Memory {
        Memory(Integer::from_f64(n as f64).unwrap())
    }
}

impl From<f32> for Memory {
    fn from(n: f32) -> Memory {
        Memory(Integer::from_f32(n).unwrap())
    }
}

impl From<f64> for Memory {
    fn from(n: f64) -> Memory {
        Memory(Integer::from_f64(n).unwrap())
    }
}

impl Add for Memory {
    type Output = Memory;

    fn add(self, rhs: Memory) -> Memory {
        let mut output = self.0.clone();
        output += rhs.0.clone();

        Memory(output)
    }
}

impl<'a> Add<&'a Memory> for Memory {
    type Output = Memory;

    fn add(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output += rhs.0.clone();

        Memory(output)
    }
}

impl<'a, 'b> Add<&'b Memory> for &'a Memory {
    type Output = Memory;

    fn add(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output += rhs.0.clone();

        Memory(output)
    }
}

impl AddAssign<Memory> for Memory {
    fn add_assign(&mut self, rhs: Memory) {
        self.0 += rhs.0.clone()
    }
}

impl<'a> AddAssign<&'a Memory> for Memory {
    fn add_assign(&mut self, rhs: &Memory) {
        self.0 += rhs.0.clone()
    }
}

impl Sub for Memory {
    type Output = Memory;

    fn sub(self, rhs: Memory) -> Memory {
        let mut output = self.0.clone();
        output -= rhs.0.clone();

        Memory(output)
    }
}

impl<'a> Sub<&'a Memory> for Memory {
    type Output = Memory;

    fn sub(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output -= rhs.0.clone();

        Memory(output)
    }
}

impl<'a, 'b> Sub<&'b Memory> for &'a Memory {
    type Output = Memory;

    fn sub(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output -= rhs.0.clone();

        Memory(output)
    }
}

impl SubAssign for Memory {
    fn sub_assign(&mut self, rhs: Memory) {
        self.0 -= rhs.0.clone()
    }
}

impl<'a> SubAssign<&'a Memory> for Memory {
    fn sub_assign(&mut self, rhs: &Memory) {
        self.0 -= rhs.0.clone()
    }
}

impl Mul for Memory {
    type Output = Memory;

    fn mul(self, rhs: Memory) -> Memory {
        let mut output = self.0.clone();
        output *= rhs.0.clone();

        Memory(output)
    }
}

impl<'a> Mul<&'a Memory> for Memory {
    type Output = Memory;

    fn mul(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output *= rhs.0.clone();

        Memory(output)
    }
}

impl<'a, 'b> Mul<&'b Memory> for &'a Memory {
    type Output = Memory;

    fn mul(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output *= rhs.0.clone();

        Memory(output)
    }
}

impl MulAssign<Memory> for Memory {
    fn mul_assign(&mut self, rhs: Memory) {
        self.0 *= rhs.0.clone()
    }
}

impl<'a> MulAssign<&'a Memory> for Memory {
    fn mul_assign(&mut self, rhs: &Memory) {
        self.0 *= rhs.0.clone()
    }
}

impl Div for Memory {
    type Output = Memory;

    fn div(self, rhs: Memory) -> Memory {
        let mut output = self.0.clone();
        output /= rhs.0.clone();

        Memory(output)
    }
}

impl<'a> Div<&'a Memory> for Memory {
    type Output = Memory;

    fn div(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output /= rhs.0.clone();

        Memory(output)
    }
}

impl<'a, 'b> Div<&'b Memory> for &'a Memory {
    type Output = Memory;

    fn div(self, rhs: &Memory) -> Memory {
        let mut output = self.0.clone();
        output /= rhs.0.clone();

        Memory(output)
    }
}

impl DivAssign<Memory> for Memory {
    fn div_assign(&mut self, rhs: Memory) {
        self.0 /= rhs.0.clone()
    }
}

impl<'a> DivAssign<&'a Memory> for Memory {
    fn div_assign(&mut self, rhs: &Memory) {
        self.0 /= rhs.0.clone()
    }
}
