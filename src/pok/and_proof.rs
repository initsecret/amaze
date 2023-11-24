//! Sigma Protocol for The AND of Two Sigma Protocols.
//!
//! Cf. Section 19.7.1 in [BS0.5]
//!
//! [BS0.5]: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf

use curve25519_dalek::scalar::Scalar;

use crate::pok::linear_sigma::{SigmaProver, SigmaVerifier};

/// the secret witness, denoted by (y_0,y_1) in Section 19.7.1 in [BS0.5]
pub type AndWitness<S0Witness, S1Witness> = (S0Witness, S1Witness);

/// the statement the witness is used to prove, denoted by (R_0,R_1) in Section 19.7.1 in [BS0.5]
pub type AndWitnessStatement<S0WitnessStatement, S1WitnessStatement> =
    (S0WitnessStatement, S1WitnessStatement);

/// the prover's commitment, denoted by (t_0,t_1) in Section 19.7.1 of [BS0.5]
pub type AndProverCommitment<S0ProverCommitment, S1ProverCommitment> =
    (S0ProverCommitment, S1ProverCommitment);

/// the verifier's challenge, denoted by c in Section 19.7.1 of [BS0.5]
pub type AndVerifierChallenge = Scalar;

/// the prover's response, denoted by alpha_z in Section 19.7.1 of [BS0.5]
pub type AndProverResponse<S0ProverResponse, S1ProverResponse> =
    (S0ProverResponse, S1ProverResponse);

pub struct AndProver<
    S0Witness,
    S0WitnessStatement,
    S0ProverCommitment,
    S0ProverResponse,
    S1Witness,
    S1WitnessStatement,
    S1ProverCommitment,
    S1ProverResponse,
> {
    pub s0_prover: Box<
        dyn SigmaProver<
            S0Witness,
            S0WitnessStatement,
            S0ProverCommitment,
            AndVerifierChallenge,
            S0ProverResponse,
        >,
    >,
    pub s1_prover: Box<
        dyn SigmaProver<
            S1Witness,
            S1WitnessStatement,
            S1ProverCommitment,
            AndVerifierChallenge,
            S1ProverResponse,
        >,
    >,
}

impl<
        S0Witness,
        S0WitnessStatement,
        S0ProverCommitment,
        S0ProverResponse,
        S1Witness,
        S1WitnessStatement,
        S1ProverCommitment,
        S1ProverResponse,
    >
    SigmaProver<
        AndWitness<S0Witness, S1Witness>,
        AndWitnessStatement<S0WitnessStatement, S1WitnessStatement>,
        AndProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        AndVerifierChallenge,
        AndProverResponse<S0ProverResponse, S1ProverResponse>,
    >
    for AndProver<
        S0Witness,
        S0WitnessStatement,
        S0ProverCommitment,
        S0ProverResponse,
        S1Witness,
        S1WitnessStatement,
        S1ProverCommitment,
        S1ProverResponse,
    >
{
    fn generate_commitment(
        &mut self,
        witness: AndWitness<S0Witness, S1Witness>,
    ) -> AndProverCommitment<S0ProverCommitment, S1ProverCommitment> {
        let s0_commitment = self.s0_prover.as_mut().generate_commitment(witness.0);
        let s1_commitment = self.s1_prover.as_mut().generate_commitment(witness.1);
        (s0_commitment, s1_commitment)
    }

    fn serialize_commitment(
        &self,
        commitment: &AndProverCommitment<S0ProverCommitment, S1ProverCommitment>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.s0_prover.as_ref().serialize_commitment(&commitment.0));
        buf.extend(self.s1_prover.as_ref().serialize_commitment(&commitment.1));
        buf
    }

    fn generate_response_to_challenge(
        &mut self,
        random_challenge: AndVerifierChallenge,
    ) -> AndProverResponse<S0ProverResponse, S1ProverResponse> {
        let s0_response = self
            .s0_prover
            .as_mut()
            .generate_response_to_challenge(random_challenge);
        let s1_response = self
            .s1_prover
            .as_mut()
            .generate_response_to_challenge(random_challenge);
        (s0_response, s1_response)
    }
}

pub struct AndVerifier<
    S0Witness,
    S0WitnessStatement,
    S0ProverCommitment,
    S0ProverResponse,
    S1Witness,
    S1WitnessStatement,
    S1ProverCommitment,
    S1ProverResponse,
> {
    pub s0_verifier: Box<
        dyn SigmaVerifier<
            S0Witness,
            S0WitnessStatement,
            S0ProverCommitment,
            AndVerifierChallenge,
            S0ProverResponse,
        >,
    >,
    pub s1_verifier: Box<
        dyn SigmaVerifier<
            S1Witness,
            S1WitnessStatement,
            S1ProverCommitment,
            AndVerifierChallenge,
            S1ProverResponse,
        >,
    >,
}

impl<
        S0Witness,
        S0WitnessStatement,
        S0ProverCommitment,
        S0ProverResponse,
        S1Witness,
        S1WitnessStatement,
        S1ProverCommitment,
        S1ProverResponse,
    >
    SigmaVerifier<
        AndWitness<S0Witness, S1Witness>,
        AndWitnessStatement<S0WitnessStatement, S1WitnessStatement>,
        AndProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        AndVerifierChallenge,
        AndProverResponse<S0ProverResponse, S1ProverResponse>,
    >
    for AndVerifier<
        S0Witness,
        S0WitnessStatement,
        S0ProverCommitment,
        S0ProverResponse,
        S1Witness,
        S1WitnessStatement,
        S1ProverCommitment,
        S1ProverResponse,
    >
{
    fn generate_random_challenge(&mut self) -> AndVerifierChallenge {
        let mut rng = rand::thread_rng();
        Scalar::random(&mut rng)
    }

    fn verify_response_to_challenge(
        &self,
        prover_commitment: AndProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        random_challenge: AndVerifierChallenge,
        prover_response_to_challenge: AndProverResponse<S0ProverResponse, S1ProverResponse>,
    ) -> bool {
        let s0_verification_result = self.s0_verifier.as_ref().verify_response_to_challenge(
            prover_commitment.0,
            random_challenge,
            prover_response_to_challenge.0,
        );
        let s1_verification_result = self.s1_verifier.as_ref().verify_response_to_challenge(
            prover_commitment.1,
            random_challenge,
            prover_response_to_challenge.1,
        );
        s0_verification_result && s1_verification_result
    }

    fn simulate_prover_responses(
        &self,
        random_challenge: AndVerifierChallenge,
    ) -> (
        AndProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        AndProverResponse<S0ProverResponse, S1ProverResponse>,
    ) {
        let (s0_commitment, s0_response) = self
            .s0_verifier
            .as_ref()
            .simulate_prover_responses(random_challenge);
        let (s1_commitment, s1_response) = self
            .s1_verifier
            .as_ref()
            .simulate_prover_responses(random_challenge);
        ((s0_commitment, s1_commitment), (s0_response, s1_response))
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable,
    };

    use crate::pok::{
        schnorr::{SchnorrProver, SchnorrVerifier},
        test_macros::test_sigma_protocol,
    };

    use super::*;

    #[test]
    fn test_schnorr_and_schnorr() {
        let mut rng = rand::thread_rng();
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);

        // 0. Fix two witnesses, and define the statements to prove
        let witness0 = Scalar::random(&mut rng);
        let witness0_statement = witness0 * g;
        let witness1 = Scalar::random(&mut rng);
        let witness1_statement = witness1 * g;

        // 1. Initialize Schnorr provers and verifiers with the respective statements to prove
        let s0_prover = SchnorrProver::new(witness0_statement);
        let s1_prover = SchnorrProver::new(witness1_statement);
        let s0_verifier = SchnorrVerifier::new(witness0_statement);
        let s1_verifier = SchnorrVerifier::new(witness1_statement);

        // 2. Create an AND prover using the two schnorr provers
        let mut and_prover = AndProver {
            s0_prover: Box::new(s0_prover),
            s1_prover: Box::new(s1_prover),
        };

        // 3. Create an AND verifier using the two schnorr verifiers
        let mut and_verifier = AndVerifier {
            s0_verifier: Box::new(s0_verifier),
            s1_verifier: Box::new(s1_verifier),
        };

        // 4. Run tests with the verifier and prover
        test_sigma_protocol!((witness0, witness1), and_verifier, and_prover);
    }
}
