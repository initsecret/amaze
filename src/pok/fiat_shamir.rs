//! Fiat-Shamir Heuristic for Turning a Sigma Protocol into a Signature Scheme
//!
//! Cf. Section 19.6.1 in [BS0.5]
//!
//! [BS0.5]: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::pok::linear_sigma::{SigmaProver, SigmaVerifier};

/// the verifier's challenge, denoted by c in Section 19.6.1 of [BS0.5]
type FiatShamirChallenge = Scalar;

/// the secret key, denoted by x in Section 19.6.1 of [BS0.5]
pub struct FiatShamirSecretKey<Witness> {
    pub witness: Witness,
}

/// the signature, denoted by sigma=(t,z) in Section 19.6.1 of [BS0.5]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FiatShamirSignature<ProverCommitment, ProverResponse> {
    pub prover_commitment: ProverCommitment,
    pub prover_response: ProverResponse,
}

pub struct FiatShamir<Witness, WitnessStatement, ProverCommitment, ProverResponse> {
    pub prover: Box<
        dyn SigmaProver<
            Witness,
            WitnessStatement,
            ProverCommitment,
            FiatShamirChallenge,
            ProverResponse,
        >,
    >,
    pub verifier: Box<
        dyn SigmaVerifier<
            Witness,
            WitnessStatement,
            ProverCommitment,
            FiatShamirChallenge,
            ProverResponse,
        >,
    >,
}

pub trait SignatureScheme<SecretKey, Signature> {
    fn sign(&mut self, secret_key: SecretKey, message: &[u8]) -> Signature;
    fn verify(&self, message: &[u8], signature: Signature) -> bool;
}

impl<Witness, WitnessStatement, ProverCommitment, ProverResponse>
    FiatShamir<Witness, WitnessStatement, ProverCommitment, ProverResponse>
{
    /// creates a simulated challenge by hashing the message and the commitment
    /// to a scalar.
    fn hash_message_and_commitment_to_scalar(
        &self,
        message: &[u8],
        prover_commitment: &ProverCommitment,
    ) -> Scalar {
        let serialized_commitment = self.prover.as_ref().serialize_commitment(prover_commitment);

        let mut hasher = Sha512::new();
        hasher.update(message);
        hasher.update(b"||");
        hasher.update(&serialized_commitment);

        Scalar::from_hash(hasher)
    }
}

impl<Witness, WitnessStatement, ProverCommitment, ProverResponse>
    SignatureScheme<
        FiatShamirSecretKey<Witness>,
        FiatShamirSignature<ProverCommitment, ProverResponse>,
    > for FiatShamir<Witness, WitnessStatement, ProverCommitment, ProverResponse>
{
    fn sign(
        &mut self,
        secret_key: FiatShamirSecretKey<Witness>,
        message: &[u8],
    ) -> FiatShamirSignature<ProverCommitment, ProverResponse> {
        let prover_commitment = self.prover.generate_commitment(secret_key.witness);

        let simulated_challenge =
            self.hash_message_and_commitment_to_scalar(message, &prover_commitment);

        let prover_response = self
            .prover
            .generate_response_to_challenge(simulated_challenge);

        FiatShamirSignature {
            prover_commitment,
            prover_response,
        }
    }

    fn verify(
        &self,
        message: &[u8],
        signature: FiatShamirSignature<ProverCommitment, ProverResponse>,
    ) -> bool {
        let simulated_challenge =
            self.hash_message_and_commitment_to_scalar(message, &signature.prover_commitment);

        self.verifier.verify_response_to_challenge(
            signature.prover_commitment,
            simulated_challenge,
            signature.prover_response,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable,
    };

    use crate::pok::{
        schnorr::{SchnorrProver, SchnorrVerifier},
        test_macros::test_fiat_shamir_signature,
    };

    use super::*;

    #[test]
    fn test_fiat_shamir_schnorr() {
        let mut rng = rand::thread_rng();
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);

        // 0. Fix a witness, and define the statement to prove
        let witness = Scalar::random(&mut rng);
        let witness_statement = witness * g;

        // 1. Initialize a Schnorr prover and verifier with the statement to prove
        let prover = SchnorrProver::new(witness_statement);
        let verifier = SchnorrVerifier::new(witness_statement);

        // 2. Create a Fiat-Shamir Signature Scheme
        let mut schnorr_fiat_shamir = FiatShamir {
            prover: Box::from(prover),
            verifier: Box::from(verifier),
        };

        test_fiat_shamir_signature!(witness, schnorr_fiat_shamir);
    }
}
