//! The Chaum-Pedersen protocol for DH-triples
//!
//! Cf. Section 19.5.2 in [BS0.5]
//!
//! [BS0.5]: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

use crate::pok::linear_sigma::{
    GenericSigmaProver, GenericSigmaVerifier, SigmaProver, SigmaVerifier,
};

/// the secret witness, denoted by beta in Section 19.5.2 of [BS0.5]
pub type ChaumPedersenWitness = Scalar;

/// the statement the witness is used to prove, denoted by (u,v,w) in Section 19.5.2 of [BS0.5].
#[derive(Clone, Copy)]
pub struct ChaumPedersenWitnessStatement {
    pub u: RistrettoPoint,
    pub v: RistrettoPoint,
    pub w: RistrettoPoint,
}

/// the per verifier secret, denoted by beta_t in Section 19.5.2 of [BS0.5]
pub type ChaumPedersenPerVerifierSecret = Scalar;

/// cf.
/// the prover's commitment, denoted by u_t in Section 19.5.2 of [BS0.5]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChaumPedersenProverCommitment {
    pub(crate) v_t: RistrettoPoint,
    pub(crate) w_t: RistrettoPoint,
}

/// the verifier's challenge, denoted by c in Section 19.5.2 of [BS0.5]
pub type ChaumPedersenVerifierChallenge = Scalar;

/// the prover's response, denoted by beta_z in Section 19.5.2 of [BS0.5]
pub type ChaumPedersenProverResponse = Scalar;

pub type ChaumPedersenProver = GenericSigmaProver<
    ChaumPedersenWitness,
    ChaumPedersenWitnessStatement,
    ChaumPedersenPerVerifierSecret,
>;

impl
    SigmaProver<
        ChaumPedersenWitness,
        ChaumPedersenWitnessStatement,
        ChaumPedersenProverCommitment,
        ChaumPedersenVerifierChallenge,
        ChaumPedersenProverResponse,
    > for ChaumPedersenProver
{
    fn generate_commitment(
        &mut self,
        witness: ChaumPedersenWitness,
    ) -> ChaumPedersenProverCommitment {
        let mut rng = rand::thread_rng();

        // Store the witness for future use
        self.witness = Some(witness);

        // Generate a new random commitment for this verifier

        // per verifier secret, denoted by beta_t in Section 19.5.2 of [BS0.5]
        let per_verifier_secret = Scalar::random(&mut rng);
        // v_t and w_t as defined in Section 19.5.2 of [BS0.5]
        let per_verifier_v_t = per_verifier_secret * self.g;
        let per_verifier_w_t = per_verifier_secret * self.witness_statement.u;

        // Store the secret in a hashmap for future reference
        self.per_verifier_secret = Some(per_verifier_secret);

        // Return commitment
        ChaumPedersenProverCommitment {
            v_t: per_verifier_v_t,
            w_t: per_verifier_w_t,
        }
    }

    fn serialize_commitment(&self, commitment: &ChaumPedersenProverCommitment) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(commitment.v_t.compress().as_bytes());
        buf.extend(commitment.w_t.compress().as_bytes());
        buf
    }

    fn generate_response_to_challenge(
        &mut self,
        random_challenge: ChaumPedersenVerifierChallenge,
    ) -> ChaumPedersenProverResponse {
        // Construct response using the per_verifier_secret and random_challenge
        self.per_verifier_secret.unwrap() + (self.witness.unwrap() * random_challenge)
    }
}

pub type ChaumPedersenVerifier = GenericSigmaVerifier<ChaumPedersenWitnessStatement>;

impl
    SigmaVerifier<
        ChaumPedersenWitness,
        ChaumPedersenWitnessStatement,
        ChaumPedersenProverCommitment,
        ChaumPedersenVerifierChallenge,
        ChaumPedersenProverResponse,
    > for ChaumPedersenVerifier
{
    fn generate_random_challenge(&mut self) -> ChaumPedersenVerifierChallenge {
        let mut rng = rand::thread_rng();
        Scalar::random(&mut rng)
    }

    fn verify_response_to_challenge(
        &self,
        prover_commitment: ChaumPedersenProverCommitment,
        random_challenge: ChaumPedersenVerifierChallenge,
        prover_response_to_challenge: ChaumPedersenProverResponse,
    ) -> bool {
        // cf. Section 19.5.2 of [BS0.5]
        let left1 = prover_response_to_challenge * self.g;
        let right1 = prover_commitment.v_t + (random_challenge * self.witness_statement.v);

        let left2 = prover_response_to_challenge * self.witness_statement.u;
        let right2 = prover_commitment.w_t + (random_challenge * self.witness_statement.w);

        (left1 == right1) && (left2 == right2)
    }

    fn simulate_prover_responses(
        &self,
        random_challenge: ChaumPedersenVerifierChallenge,
    ) -> (ChaumPedersenProverCommitment, ChaumPedersenProverResponse) {
        let mut rng = rand::thread_rng();
        let simulated_prover_response = Scalar::random(&mut rng);
        let simulated_prover_commitment = ChaumPedersenProverCommitment {
            v_t: (simulated_prover_response * self.g)
                - (random_challenge * self.witness_statement.v),
            w_t: (simulated_prover_response * self.witness_statement.u)
                - (random_challenge * self.witness_statement.w),
        };
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
    fn test_chaum_pedersen() {
        let mut rng = rand::thread_rng();
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);

        // 0. Fix a witness and a statement to prove
        let witness = Scalar::random(&mut rng);
        let v = witness * g;
        let u = RistrettoPoint::random(&mut rng);
        let w = witness * u;
        let witness_statement = ChaumPedersenWitnessStatement { u, v, w };

        // 1. Initialize a Schnorr prover and verifier with the statement to prove
        let mut prover = ChaumPedersenProver::new(witness_statement);
        let mut verifier = ChaumPedersenVerifier::new(witness_statement);

        // 2. Run tests with the verifier and prover
        test_sigma_protocol!(witness, verifier, prover);
    }
}
