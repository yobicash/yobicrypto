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

