// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `result` module provides the `Result` type used throughout `libyobicash`.

use error::Error;

use std::result::Result as StdResult;

/// The `Result` alias type used in `libyobicash`.
pub type Result<T> = StdResult<T, Error>;
