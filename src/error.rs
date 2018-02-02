// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! The `error` module provides the errors used throughout `libyobicash`.

use failure::{Fail, Context, Backtrace};
use failure::Error as FailureError;

use std::fmt::{self, Display};
use std::io::Error as IOError;

use hex::FromHexError;

/// The error type used in `libyobicash`.
#[derive(Debug)]
pub struct Error {
    /// Inner `Context` with the `Fail` implementor.
    inner: Context<ErrorKind>, 
}

/// The different types of errors used in `libyobicash`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display="Invalid argument")]
    InvalidArgument,
    #[fail(display="Already found")]
    AlreadyFound,
    #[fail(display="Not found")]
    NotFound,
    #[fail(display="Out of bound")]
    OutOfBound,
    #[fail(display="Invalid format")]
    InvalidFormat,
    #[fail(display="Not supported")]
    NotSupported,
    #[fail(display="Invalid length")]
    InvalidLength,
    #[fail(display="Invalid digest")]
    InvalidDigest,
    #[fail(display="From Failure")]
    FromFailure,
    #[fail(display="Failed serialization")]
    SerializationFailure,
    #[fail(display="Failed deserialization")]
    DeserializationFailure,
    #[fail(display="I/O failure")]
    IOFailure,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}
impl Error {
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { inner: Context::new(kind) }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner: inner }
    }
}

impl From<FailureError> for Error {
    fn from(e: FailureError) -> Error {
        Error { inner: e.context(ErrorKind::FromFailure) }
    }
}

impl From<IOError> for Error {
    fn from(_: IOError) -> Error {
        Error { inner: Context::new(ErrorKind::IOFailure) }
    }
}

impl From<FromHexError> for Error {
    fn from(_: FromHexError) -> Error {
        Error { inner: Context::new(ErrorKind::DeserializationFailure) }
    }
}
