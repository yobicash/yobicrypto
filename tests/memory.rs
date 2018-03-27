// Copyright 2018 Yobicash Ltd.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

//! Yobicrypto `memory` module tests.

extern crate yobicrypto;

use yobicrypto::memory::Memory;

#[test]
fn memory_from_string_succ() {
    let s = "10000000000000000000000000000";

    let res = Memory::from_string(s);
    assert!(res.is_ok())
}

#[test]
fn memory_from_string_fail() {
    let s = "blablabla";
    
    let res = Memory::from_string(s);
    assert!(res.is_err())
}

#[test]
fn memory_to_string_succ() {
    let n = 10.0;

    let memory_a: Memory = n.into();
    let s = memory_a.to_string();
    let memory_b = Memory::from_string(&s).unwrap();
    
    assert_eq!(memory_a, memory_b)
}

#[test]
fn memory_to_string_fail() {
    let n = 10.0;
    
    let memory_a: Memory = n.into();
    let mut s = memory_a.to_string();
    s.pop();
    let memory_b = Memory::from_string(&s).unwrap();
    
    assert_ne!(memory_a, memory_b)
}

#[test]
fn memory_add_succ() {
    let a = Memory::from(10);
    let b = Memory::from(7);
    let c = Memory::from(17);
    
    let sum = a + b;
    
    assert_eq!(sum, c)
}

#[test]
fn memory_add_assign_succ() {
    let a = Memory::from(10);
    let b = Memory::from(7);
    let c = Memory::from(17);
    
    let mut sum = a;
    sum += b;
    
    assert_eq!(sum, c)
}

#[test]
fn memory_sub_succ() {
    let a = Memory::from(10);
    let b = Memory::from(7);
    let c = Memory::from(3);
    
    let sub = a - b;
    
    assert_eq!(sub, c)
}

#[test]
fn memory_sub_assign_succ() {
    let a = Memory::from(10);
    let b = Memory::from(7);
    let c = Memory::from(3);
    
    let mut sub = a;
    sub -= b;
    
    assert_eq!(sub, c)
}

#[test]
fn memory_mul_succ() {
    let a = Memory::from(10);
    let b = Memory::from(7);
    let c = Memory::from(70);
    
    let sum = a * b;
    
    assert_eq!(sum, c)
}

#[test]
fn memory_mul_assign_succ() {
    let a = Memory::from(10);
    let b = Memory::from(7);
    let c = Memory::from(70);
    
    let mut sum = a;
    sum *= b;
    
    assert_eq!(sum, c)
}

#[test]
fn memory_div_succ() {
    let a = Memory::from(10);
    let b = Memory::from(5);
    let c = Memory::from(2);
    
    let div = a / b;
    
    assert_eq!(div, c)
}

#[test]
fn memory_div_assign_succ() {
    let a = Memory::from(10);
    let b = Memory::from(5);
    let c = Memory::from(2);
    
    let mut div = a;
    div /= b;
    
    assert_eq!(div, c)
}
