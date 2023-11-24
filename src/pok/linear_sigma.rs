//! Generic Sigma Protocol for Linear Relations
//!
//! Adapted from Section 19.5.3 in [BS0.5]
//!
//! [BS0.5]: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
};

pub trait SigmaProver<
    Witness,
    WitnessStatement,
    ProverCommitment,
    VerifierChallenge,
    ProverResponse,
>
{
    fn generate_commitment(&mut self, witness: Witness) -> ProverCommitment;
    fn serialize_commitment(&self, commitment: &ProverCommitment) -> Vec<u8>;
    fn generate_response_to_challenge(
        &mut self,
        random_challenge: VerifierChallenge,
    ) -> ProverResponse;
}

pub trait SigmaVerifier<
    Witness,
    WitnessStatement,
    ProverCommitment,
    VerifierChallenge,
    ProverResponse,
>
{
    fn generate_random_challenge(&mut self) -> VerifierChallenge;
    fn verify_response_to_challenge(
        &self,
        prover_commitment: ProverCommitment,
        random_challenge: VerifierChallenge,
        prover_response_to_challenge: ProverResponse,
    ) -> bool;
    fn simulate_prover_responses(
        &self,
        random_challenge: VerifierChallenge,
    ) -> (ProverCommitment, ProverResponse);
}

//
// Generic structs that capture Schnorr and Chaum-Pedersen proofs.
//
#[derive(Clone, Copy)]
pub struct GenericSigmaProver<Witness, WitnessStatement, PerVerifierSecret> {
    /// g is the Ristretto basepoint/generator
    pub g: RistrettoPoint,
    /// denoted by (alpha_1,...,alpha_n) in Section 19.5.3 in [BS0.5]
    pub witness: Option<Witness>,
    /// denoted by phi in Section 19.5.3 in [BS0.5]
    pub witness_statement: WitnessStatement,
    /// stores the secret generated for the verifier to create the commitment;
    /// denoted by alpha_tj in Section 19.5.3 in [BS0.5]
    pub per_verifier_secret: Option<PerVerifierSecret>,
}
#[derive(Clone, Copy)]
pub struct GenericSigmaVerifier<WitnessStatement> {
    /// g is the Ristretto basepoint/generator
    pub g: RistrettoPoint,
    /// denoted by phi in Section 19.5.3 in [BS0.5]
    pub witness_statement: WitnessStatement,
}

impl<Witness, WitnessStatement, PerVerifierSecret>
    GenericSigmaProver<Witness, WitnessStatement, PerVerifierSecret>
{
    pub fn new(witness_statement: WitnessStatement) -> Self {
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
        Self {
            g,
            witness: None,
            witness_statement,
            per_verifier_secret: None,
        }
    }
}

impl<WitnessStatement> GenericSigmaVerifier<WitnessStatement> {
    pub fn new(witness_statement: WitnessStatement) -> Self {
        let g = RistrettoBasepointTable::basepoint(&RISTRETTO_BASEPOINT_TABLE);
        Self {
            g,
            witness_statement,
        }
    }
}
