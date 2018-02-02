// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `result` module provides the `Result` type used throughout `libyobicash`.

use error::Error;

use std::result::Result as StdResult;

/// The `Result` alias type used in `libyobicash`.
pub type Result<T> = StdResult<T, Error>;
