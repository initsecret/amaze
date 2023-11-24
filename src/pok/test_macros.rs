#![allow(unused_macros, unused_imports)]
// These macros are used in other files to test.

macro_rules! test_sigma_protocol {
    ($witness:expr, $verifier:expr, $prover:expr) => {

    // 1. Verifier asks the prover for a commitment
    //    The prover is given the witness so they can respond correctly.
    let prover_commitment = $prover.generate_commitment($witness);

    // 2. Verifier generates a random challenge and sends it to the prover
    let random_challenge = $verifier.generate_random_challenge();
    let prover_response_to_challenge =
        $prover.generate_response_to_challenge(random_challenge);

    // 3. Verifier verifies the response
    let result_from_prover = $verifier.verify_response_to_challenge(
        prover_commitment,
        random_challenge,
        prover_response_to_challenge,
    );
    assert!(result_from_prover);

    //----------------------------------------------------------------------
    // 4. As usual, since this is a zero-knowledge proof, the verifier can also generate valid prover responses without knowing the witness, and verify that they are valid.
    let random_challenge = $verifier.generate_random_challenge();
    let (prover_commitment, prover_response_to_challenge) =
        $verifier.simulate_prover_responses(random_challenge);
    let result_from_simulator = $verifier.verify_response_to_challenge(
        prover_commitment,
        random_challenge,
        prover_response_to_challenge,
    );
    assert!(result_from_simulator);

    };
}

macro_rules! test_fiat_shamir_signature {
    ($witness:expr, $fiat_shamir:expr) => {
        // 1. Pick a random message
        let mut rng = rand::thread_rng();
        let mut message = [0u8; 128];
        rng.fill_bytes(&mut message);

        // 2. Sign the message
        let signature = $fiat_shamir.sign(FiatShamirSecretKey { witness: $witness }, &message);

        // 3. Verify the signature
        let verification_result = $fiat_shamir.verify(&message, signature);
        assert!(verification_result);
    };
}

pub(crate) use test_fiat_shamir_signature;
pub(crate) use test_sigma_protocol;
