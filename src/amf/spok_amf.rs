//! Signature Proof of Knowledge for the AMF Relation
//!
//! Cf. Fig. 5 in [AMF]
//!
//! [AMF]: https://eprint.iacr.org/2019/565/20190527:092413
#![allow(non_snake_case)]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::pok::{
    and_proof::{AndProver, AndVerifier},
    chaum_pedersen::{
        ChaumPedersenProver, ChaumPedersenProverCommitment, ChaumPedersenVerifier,
        ChaumPedersenWitnessStatement,
    },
    fiat_shamir::FiatShamir,
    or_proof::{OrProver, OrProverResponse, OrVerifier, OrWitness},
    schnorr::{SchnorrProver, SchnorrVerifier},
};

pub type AMFSPoK = FiatShamir<
    (OrWitness<Scalar, Scalar>, OrWitness<Scalar, Scalar>),
    (
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenWitnessStatement, RistrettoPoint),
    ),
    (
        (RistrettoPoint, RistrettoPoint),
        (ChaumPedersenProverCommitment, RistrettoPoint),
    ),
    (
        OrProverResponse<Scalar, Scalar>,
        OrProverResponse<Scalar, Scalar>,
    ),
>;

impl AMFSPoK {
    pub fn new(
        sender_public_key: RistrettoPoint,
        judge_public_key: RistrettoPoint,
        J: RistrettoPoint,
        R: RistrettoPoint,
        E_J: RistrettoPoint,
    ) -> Self {
        // 0. Initialize Schnorr for the statement sender_public_key = g^t; cf. Fig 5 of [AMF]
        let s0_prover = SchnorrProver::new(sender_public_key);
        let s0_verifier = SchnorrVerifier::new(sender_public_key);

        // 1. Initialize Schnorr for the statement J = g^u; cf. Fig 5 of [AMF]
        let s1_prover = SchnorrProver::new(J);
        let s1_verifier = SchnorrVerifier::new(J);

        // 2. Combine the Schnorr proofs s0 and s1 into an OR proof or0
        let or0_prover = OrProver {
            s0_prover: Box::new(s0_prover),
            s0_verifier: Box::new(s0_verifier),
            s1_prover: Box::new(s1_prover),
            s1_verifier: Box::new(s1_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or0_verifier = OrVerifier {
            s0_verifier: Box::new(s0_verifier),
            s1_verifier: Box::new(s1_verifier),
        };

        // 3. Initialize Chaum-Pedersen for the statement (J = judge_public_key^v && E_j = g^v); cf. Fig 5 of [AMF]
        let s3_witness_statement = ChaumPedersenWitnessStatement {
            u: judge_public_key,
            v: E_J,
            w: J,
        };
        let s2_prover = ChaumPedersenProver::new(s3_witness_statement);
        let s2_verifier = ChaumPedersenVerifier::new(s3_witness_statement);

        // 4. Initialize Schnorr for the statement R = g^w; cf. Fig 5 of [AMF]
        let s3_prover = SchnorrProver::new(R);
        let s3_verifier = SchnorrVerifier::new(R);

        // 5. Combine the Chaum-Pedersen and Schnorr proofs s2 and s3 into an OR proof or1
        let or1_prover = OrProver {
            s0_prover: Box::new(s2_prover),
            s0_verifier: Box::new(s2_verifier),
            s1_prover: Box::new(s3_prover),
            s1_verifier: Box::new(s3_verifier),
            witness: None,
            per_verifier_secret: None,
        };
        let or1_verifier = OrVerifier {
            s0_verifier: Box::new(s2_verifier),
            s1_verifier: Box::new(s3_verifier),
        };

        // 6. Combine the OR proofs or0 and or1 into an AND proof and
        let and_prover = AndProver {
            s0_prover: Box::new(or0_prover),
            s1_prover: Box::new(or1_prover),
        };
        let and_verifier = AndVerifier {
            s0_verifier: Box::new(or0_verifier),
            s1_verifier: Box::new(or1_verifier),
        };

        // 7. Finally, create a Fiat-Shamir Signature Scheme from the AND proof and

        FiatShamir {
            prover: Box::from(and_prover),
            verifier: Box::from(and_verifier),
        }
    }
}
