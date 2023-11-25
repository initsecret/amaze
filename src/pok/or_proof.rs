//! Sigma Protocol for The OR of Two Sigma Protocols.
//!
//! Cf. [CS97] and Section 19.7.2 in [BS0.5]
//!
//! [BS0.5]: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf
//! [CS97]: https://crypto.ethz.ch/publications/files/CamSta97b.pdf

use curve25519_dalek::scalar::Scalar;

use crate::pok::linear_sigma::{SigmaProver, SigmaVerifier};

/// if b == 0 / false: then the prover knows a witness (s0_witness) for R0
/// if b == 1 / true : then the prover knows a witness (s1_witness) for R1
/// cf. Section 19.7.2 in [BS0.5]
#[derive(Clone, Copy, Default)]
pub struct OrWitness<S0Witness, S1Witness> {
    pub b: bool,
    pub s0_witness: Option<S0Witness>,
    pub s1_witness: Option<S1Witness>,
}

/// the statement the witness is used to prove, denoted by (R_0,R_1) in Section 19.7.2 in [BS0.5]
pub type OrWitnessStatement<S0WitnessStatement, S1WitnessStatement> =
    (S0WitnessStatement, S1WitnessStatement);

/// the prover's commitment, denoted by (t_0,t_1) in Section 19.7.2 of [BS0.5]
pub type OrProverCommitment<S0ProverCommitment, S1ProverCommitment> =
    (S0ProverCommitment, S1ProverCommitment);

/// the verifier's challenge, denoted by c in Section 19.7.2 of [BS0.5]
pub type OrVerifierChallenge = Scalar;

/// the prover's response, denoted by (c_0,z_0,z_1) in Section 19.7.2 of [BS0.5]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct OrProverResponse<S0ProverResponse, S1ProverResponse> {
    pub(crate) c_0: OrVerifierChallenge,
    pub(crate) z_0: S0ProverResponse,
    pub(crate) z_1: S1ProverResponse,
}

/// the per verifier secret, denoted by c_d and z_d in Section 19.7.2 of [BS0.5]
#[derive(Default)]
pub struct OrPerVerifierSecret<S0ProverResponse, S1ProverResponse> {
    pub s0_challenge: Option<OrVerifierChallenge>,
    pub s1_challenge: Option<OrVerifierChallenge>,
    pub s0_prover_response: Option<S0ProverResponse>,
    pub s1_prover_response: Option<S1ProverResponse>,
}

pub struct OrProver<
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
            OrVerifierChallenge,
            S0ProverResponse,
        >,
    >,
    pub s0_verifier: Box<
        dyn SigmaVerifier<
            S0Witness,
            S0WitnessStatement,
            S0ProverCommitment,
            OrVerifierChallenge,
            S0ProverResponse,
        >,
    >,
    pub s1_prover: Box<
        dyn SigmaProver<
            S1Witness,
            S1WitnessStatement,
            S1ProverCommitment,
            OrVerifierChallenge,
            S1ProverResponse,
        >,
    >,
    pub s1_verifier: Box<
        dyn SigmaVerifier<
            S1Witness,
            S1WitnessStatement,
            S1ProverCommitment,
            OrVerifierChallenge,
            S1ProverResponse,
        >,
    >,
    pub witness: Option<OrWitness<S0Witness, S1Witness>>,
    pub per_verifier_secret: Option<OrPerVerifierSecret<S0ProverResponse, S1ProverResponse>>,
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
        OrWitness<S0Witness, S1Witness>,
        OrWitnessStatement<S0WitnessStatement, S1WitnessStatement>,
        OrProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        OrVerifierChallenge,
        OrProverResponse<S0ProverResponse, S1ProverResponse>,
    >
    for OrProver<
        S0Witness,
        S0WitnessStatement,
        S0ProverCommitment,
        S0ProverResponse,
        S1Witness,
        S1WitnessStatement,
        S1ProverCommitment,
        S1ProverResponse,
    >
where
    S0Witness: Copy,
    S1Witness: Copy,
    S0ProverResponse: Default + Copy,
    S1ProverResponse: Default + Copy,
{
    fn generate_commitment(
        &mut self,
        witness: OrWitness<S0Witness, S1Witness>,
    ) -> OrProverCommitment<S0ProverCommitment, S1ProverCommitment> {
        // This is a bit complicated, see Section 19.7.2 of [BS0.5]

        // Store the witness
        self.witness = Some(witness);
        if !self.witness.unwrap().b {
            // Generate a valid commitment for R0 using the witness
            let s0_commitment = self
                .s0_prover
                .as_mut()
                .generate_commitment(self.witness.unwrap().s0_witness.unwrap());
            // Simulate a commitment for R1
            let s1_challenge = self.s1_verifier.as_mut().generate_random_challenge();
            let (s1_simulated_commitment, s1_simulated_response) = self
                .s1_verifier
                .as_ref()
                .simulate_prover_responses(s1_challenge);
            // Store the simulated extra values for future use
            self.per_verifier_secret = Some(OrPerVerifierSecret {
                s0_challenge: None,
                s1_challenge: Some(s1_challenge),
                s0_prover_response: None,
                s1_prover_response: Some(s1_simulated_response),
            });
            (s0_commitment, s1_simulated_commitment)
        } else {
            // Simulate a commitment for R0
            let s0_challenge = self.s0_verifier.as_mut().generate_random_challenge();
            let (s0_simulated_commitment, s0_simulated_response) = self
                .s0_verifier
                .as_ref()
                .simulate_prover_responses(s0_challenge);
            // Store the simulated extra values for future use
            self.per_verifier_secret = Some(OrPerVerifierSecret {
                s0_challenge: Some(s0_challenge),
                s1_challenge: None,
                s0_prover_response: Some(s0_simulated_response),
                s1_prover_response: None,
            });
            // Generate a valid commitment for R1 using the witness
            let s1_commitment = self
                .s1_prover
                .as_mut()
                .generate_commitment(self.witness.unwrap().s1_witness.unwrap());
            (s0_simulated_commitment, s1_commitment)
        }
    }

    fn serialize_commitment(
        &self,
        commitment: &OrProverCommitment<S0ProverCommitment, S1ProverCommitment>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.s0_prover.as_ref().serialize_commitment(&commitment.0));
        buf.extend(self.s1_prover.as_ref().serialize_commitment(&commitment.1));
        buf
    }

    fn generate_response_to_challenge(
        &mut self,
        random_challenge: OrVerifierChallenge,
    ) -> OrProverResponse<S0ProverResponse, S1ProverResponse> {
        // This is a bit complicated, see Section 19.7.2 of [BS0.5]. We use scalar arithmetic
        // instead of XOR, as per [CS97].
        let per_verifier_secret = self.per_verifier_secret.as_ref().unwrap();
        // We consistently let c₁ = c₀ + chal
        if !self.witness.unwrap().b {
            let c_0 = per_verifier_secret.s1_challenge.unwrap() - random_challenge;
            let z_0 = self.s0_prover.as_mut().generate_response_to_challenge(c_0);
            OrProverResponse {
                c_0,
                z_0,
                z_1: per_verifier_secret.s1_prover_response.unwrap(),
            }
        } else {
            let c_1 = per_verifier_secret.s0_challenge.unwrap() + random_challenge;
            let z_1 = self.s1_prover.as_mut().generate_response_to_challenge(c_1);
            OrProverResponse {
                c_0: per_verifier_secret.s0_challenge.unwrap(),
                z_0: per_verifier_secret.s0_prover_response.unwrap(),
                z_1,
            }
        }
    }
}

pub struct OrVerifier<
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
            OrVerifierChallenge,
            S0ProverResponse,
        >,
    >,
    pub s1_verifier: Box<
        dyn SigmaVerifier<
            S1Witness,
            S1WitnessStatement,
            S1ProverCommitment,
            OrVerifierChallenge,
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
        OrWitness<S0Witness, S1Witness>,
        OrWitnessStatement<S0WitnessStatement, S1WitnessStatement>,
        OrProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        OrVerifierChallenge,
        OrProverResponse<S0ProverResponse, S1ProverResponse>,
    >
    for OrVerifier<
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
    fn generate_random_challenge(&mut self) -> OrVerifierChallenge {
        let mut rng = rand::thread_rng();
        Scalar::random(&mut rng)
    }

    fn verify_response_to_challenge(
        &self,
        prover_commitment: OrProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        random_challenge: OrVerifierChallenge,
        prover_response_to_challenge: OrProverResponse<S0ProverResponse, S1ProverResponse>,
    ) -> bool {
        // This is a bit complicated, see Section 19.7.2 of [BS0.5]. We use scalar arithmetic
        // instead of XOR, as per [CS97].
        let c_1 = prover_response_to_challenge.c_0 + random_challenge;
        let s0_verification_result = self.s0_verifier.as_ref().verify_response_to_challenge(
            prover_commitment.0,
            prover_response_to_challenge.c_0,
            prover_response_to_challenge.z_0,
        );
        let s1_verification_result = self.s1_verifier.as_ref().verify_response_to_challenge(
            prover_commitment.1,
            c_1,
            prover_response_to_challenge.z_1,
        );
        s0_verification_result && s1_verification_result
    }

    fn simulate_prover_responses(
        &self,
        random_challenge: OrVerifierChallenge,
    ) -> (
        OrProverCommitment<S0ProverCommitment, S1ProverCommitment>,
        OrProverResponse<S0ProverResponse, S1ProverResponse>,
    ) {
        // This is a bit complicated, see Section 19.7.2 of [BS0.5]. We use scalar arithmetic
        // instead of XOR, as per [CS97].
        let mut rng = rand::thread_rng();
        let c_0 = Scalar::random(&mut rng);
        let c_1 = c_0 + random_challenge;

        let (s0_commitment, s0_response) = self.s0_verifier.as_ref().simulate_prover_responses(c_0);
        let (s1_commitment, s1_response) = self.s1_verifier.as_ref().simulate_prover_responses(c_1);
        (
            (s0_commitment, s1_commitment),
            OrProverResponse {
                c_0,
                z_0: s0_response,
                z_1: s1_response,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_TABLE,
        ristretto::{RistrettoBasepointTable, RistrettoPoint},
    };

    use crate::pok::{
        chaum_pedersen::{
            ChaumPedersenProver, ChaumPedersenVerifier, ChaumPedersenWitnessStatement,
        },
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

        // 2. Create an OR prover using the two schnorr provers
        let mut or_prover = OrProver {
            s0_prover: Box::new(s0_prover),
            s0_verifier: Box::new(s0_verifier),
            s1_prover: Box::new(s1_prover),
            s1_verifier: Box::new(s1_verifier),
            witness: None,
            per_verifier_secret: None,
        };

        // 3. Create an OR verifier using the two schnorr verifiers
        let mut or_verifier = OrVerifier {
            s0_verifier: Box::new(s0_verifier),
            s1_verifier: Box::new(s1_verifier),
        };

        // 4. Run tests with the verifier and prover
        test_sigma_protocol!(
            OrWitness {
                b: false,
                s0_witness: Some(witness0),
                s1_witness: None,
            },
            or_verifier,
            or_prover
        );
        test_sigma_protocol!(
            OrWitness {
                b: true,
                s0_witness: None,
                s1_witness: Some(witness1),
            },
            or_verifier,
            or_prover
        );
    }

    #[test]
    fn test_schnorr_and_chaum_pedersen() {
        let mut rng = rand::thread_rng();
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);

        // 0. Fix two witnesses, and define the statements to prove
        let witness0 = Scalar::random(&mut rng);
        let witness0_statement = witness0 * g;
        let witness1 = Scalar::random(&mut rng);
        let v = witness1 * g;
        let u = RistrettoPoint::random(&mut rng);
        let w = witness1 * u;
        let witness1_statement = ChaumPedersenWitnessStatement { u, v, w };

        // 1. Initialize Schnorr provers and verifiers with the respective statements to prove
        let s0_prover = SchnorrProver::new(witness0_statement);
        let s1_prover = ChaumPedersenProver::new(witness1_statement);
        let s0_verifier = SchnorrVerifier::new(witness0_statement);
        let s1_verifier = ChaumPedersenVerifier::new(witness1_statement);

        // 2. Create an OR prover using the two schnorr provers
        let mut or_prover = OrProver {
            s0_prover: Box::new(s0_prover),
            s0_verifier: Box::new(s0_verifier),
            s1_prover: Box::new(s1_prover),
            s1_verifier: Box::new(s1_verifier),
            witness: None,
            per_verifier_secret: None,
        };

        // 3. Create an OR verifier using the two schnorr verifiers
        let mut or_verifier = OrVerifier {
            s0_verifier: Box::new(s0_verifier),
            s1_verifier: Box::new(s1_verifier),
        };

        // 4. Run tests with the verifier and prover
        test_sigma_protocol!(
            OrWitness {
                b: false,
                s0_witness: Some(witness0),
                s1_witness: None,
            },
            or_verifier,
            or_prover
        );
        test_sigma_protocol!(
            OrWitness {
                b: true,
                s0_witness: None,
                s1_witness: Some(witness1),
            },
            or_verifier,
            or_prover
        );
    }
}
