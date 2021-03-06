// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `random` module provides types and methods for generating random types.

use rand::{random, thread_rng};
use rand::seq::sample_iter;

use error::ErrorKind;
use result::Result;

use std::ops::Range;

/// The struct used to access to the the random functions.
pub struct Random;

impl Random {
    /// Generate a random `u32`.
    pub fn u32() -> u32 {
        random::<u32>()
    }

    /// Generate a random `u64`.
    pub fn u64() -> u64 {
        random::<u64>()
    }
    
    /// Generate a `u32` between `range`.
    pub fn u32_range(range: Range<u32>) -> Result<u32> {
        let mut rng = thread_rng();
        let sample: Result<Vec<u32>> = sample_iter(&mut rng, range, 1)
            .map_err(|_| ErrorKind::OutOfBound.into());
        Ok(sample?[0])
    }

    /// Generates a sequence of `n` random `u32` sampled from `range`.
    pub fn u32_sample(range: Range<u32>, n: u32) -> Result<Vec<u32>> {
        let mut rng = thread_rng();
        sample_iter(&mut rng, range, n as usize)
            .map_err(|_| ErrorKind::OutOfBound.into())
    }

    /// Generate a `u64` between `range`.
    pub fn u64_range(range: Range<u64>) -> Result<u64> {
        let mut rng = thread_rng();
        let sample: Result<Vec<u64>> = sample_iter(&mut rng, range, 1)
            .map_err(|_| ErrorKind::OutOfBound.into());
        Ok(sample?[0])
    }

    /// Generates a sequence of `n` random `u64` sampled from `range`.
    pub fn u64_sample(range: Range<u64>, n: u64) -> Result<Vec<u64>> {
        let mut rng = thread_rng();
        sample_iter(&mut rng, range, n as usize)
            .map_err(|_| ErrorKind::OutOfBound.into())
    }

    /// Fill a `Vec<u8>` with random bytes.
    pub fn bytes_mut(sl: &mut [u8]) {
        (0..sl.len()).for_each(|i| {
            sl[i] = random::<u8>();
        });
    }

    /// Generate a random `Vec<u8>` of predefined length.
    pub fn bytes(len: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..len {
            v.push(random::<u8>());
        }
        v
    }
}
