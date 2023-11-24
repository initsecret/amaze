//! Schnorr's Protocol for Proof of Knowledge of Discrete Log
//!
//! Cf. Section 19.1 in [BS0.5]
//!
//! [BS0.5]: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::pok::linear_sigma::{
    GenericSigmaProver, GenericSigmaVerifier, SigmaProver, SigmaVerifier,
};

/// the secret witness, denoted by alpha in Section 19.1 in [BS0.5]
pub type SchnorrWitness = Scalar;

/// the statement the witness is used to prove, denoted by u = g^alpha in Section 19.1 in [BS0.5]
pub type SchnorrWitnessStatement = RistrettoPoint;

/// the per verifier secret, denoted by alpha_t in Section 19.1 of [BS0.5]
pub type SchnorrPerVerifierSecret = Scalar;

/// the prover's commitment, denoted by u_t in Section 19.1 of [BS0.5]
pub type SchnorrProverCommitment = RistrettoPoint;

/// the verifier's challenge, denoted by c in Section 19.1 of [BS0.5]
pub type SchnorrVerifierChallenge = Scalar;

/// the prover's response, denoted by alpha_z in Section 19.1 of [BS0.5]
pub type SchnorrProverResponse = Scalar;

pub type SchnorrProver =
    GenericSigmaProver<SchnorrWitness, SchnorrWitnessStatement, SchnorrPerVerifierSecret>;

impl
    SigmaProver<
        SchnorrWitness,
        SchnorrWitnessStatement,
        SchnorrProverCommitment,
        SchnorrVerifierChallenge,
        SchnorrProverResponse,
    > for SchnorrProver
{
    fn generate_commitment(&mut self, witness: SchnorrWitness) -> SchnorrProverCommitment {
        let mut rng = rand::thread_rng();
        // Store the witness for future use
        self.witness = Some(witness);
        // Generate a new random commitment for this verifier
        let per_verifier_secret = Scalar::random(&mut rng);
        let per_verifier_commitment = per_verifier_secret * self.g;
        // Store the secret for future reference
        self.per_verifier_secret = Some(per_verifier_secret);
        // Return the commitment
        per_verifier_commitment
    }

    fn serialize_commitment(&self, commitment: &SchnorrProverCommitment) -> Vec<u8> {
        commitment.compress().as_bytes().to_vec()
    }

    fn generate_response_to_challenge(
        &mut self,
        random_challenge: SchnorrVerifierChallenge,
    ) -> SchnorrProverResponse {
        // Construct response using the per_verifier_secret and random_challenge
        self.per_verifier_secret.unwrap() + (self.witness.unwrap() * random_challenge)
    }
}

pub type SchnorrVerifier = GenericSigmaVerifier<SchnorrWitnessStatement>;

impl
    SigmaVerifier<
        SchnorrWitness,
        SchnorrWitnessStatement,
        SchnorrProverCommitment,
        SchnorrVerifierChallenge,
        SchnorrProverResponse,
    > for SchnorrVerifier
{
    fn generate_random_challenge(&mut self) -> SchnorrVerifierChallenge {
        let mut rng = rand::thread_rng();
        Scalar::random(&mut rng)
    }

    fn verify_response_to_challenge(
        &self,
        prover_commitment: SchnorrProverCommitment,
        random_challenge: SchnorrVerifierChallenge,
        prover_response_to_challenge: SchnorrProverResponse,
    ) -> bool {
        let left = prover_response_to_challenge * self.g;
        let right = prover_commitment + (random_challenge * self.witness_statement);
        left == right
    }

    fn simulate_prover_responses(
        &self,
        random_challenge: SchnorrVerifierChallenge,
    ) -> (SchnorrProverCommitment, SchnorrProverResponse) {
        let mut rng = rand::thread_rng();
        let simulated_prover_response = Scalar::random(&mut rng);
        let simulated_prover_commitment =
            (simulated_prover_response * self.g) - (random_challenge * self.witness_statement);
        (simulated_prover_commitment, simulated_prover_response)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable,
    };

    use crate::pok::test_macros::test_sigma_protocol;

    use super::*;

    #[test]
    fn test_schnorr() {
        let mut rng = rand::thread_rng();
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);

        // 0. Fix a witness, and define the statement to prove
        let witness = Scalar::random(&mut rng);
        let witness_statement = witness * g;

        // 1. Initialize a Schnorr prover and verifier with the statement to prove
        let mut prover = SchnorrProver::new(witness_statement);
        let mut verifier = SchnorrVerifier::new(witness_statement);

        // 2. Run tests with the verifier and prover
        test_sigma_protocol!(witness, verifier, prover);
    }
}
