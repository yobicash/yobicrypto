// Copyright 2018 Yobicash Ltd. See the COPYRIGHT file at the top-level directory
// of this distribution.
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// and the Apache 2.0 license <LICENSE-APACHE or https://opensource.org/licenses/Apache-2.0>.
// This file may not be copied, modified, or distributed except according to those
// terms.

extern crate yobicrypto;

use yobicrypto::{Random, Scalar, ZKPWitness, ZKPProof};

#[test]
fn schnorr_protocol_verify_succ() {
    let instance = Scalar::random();
    let witness = ZKPWitness::new(instance);
    let message = Random::bytes(64);
    let proof = ZKPProof::new(instance, &message).unwrap();
    let verified = proof.verify(witness).unwrap();
    assert!(verified)
}

#[test]
fn schnorr_protocol_verify_fail() {
    let instance = Scalar::random();
    let message = Random::bytes(64);
    let proof = ZKPProof::new(instance, &message).unwrap();
    let faulty_instance = Scalar::random();
    let faulty_witness = ZKPWitness::new(faulty_instance);
    let verified = proof.verify(faulty_witness).unwrap();
    assert!(!verified)
}

