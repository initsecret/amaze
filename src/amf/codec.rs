//! Serializable codec for exposed AMF structs.
//!
//! A series of hacks to compensate for Scalar and RistrettoPoint not being serializable.
#![allow(non_snake_case)]

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use serde::{Deserialize, Serialize};

use crate::pok::{chaum_pedersen::ChaumPedersenProverCommitment, or_proof::OrProverResponse};

use super::{AMFInternalSignature, AMFPublicKey, AMFRole, AMFSecretKey, AMFSignature};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct SerializableRistrettoPoint {
    point_as_bytes: [u8; 32],
}
impl From<RistrettoPoint> for SerializableRistrettoPoint {
    fn from(point: RistrettoPoint) -> Self {
        SerializableRistrettoPoint {
            point_as_bytes: *point.compress().as_bytes(),
        }
    }
}
impl From<SerializableRistrettoPoint> for RistrettoPoint {
    fn from(serialized_point: SerializableRistrettoPoint) -> Self {
        CompressedRistretto::from_slice(&serialized_point.point_as_bytes)
            .unwrap()
            .decompress()
            .unwrap()
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct SerializableRistrettoScalar {
    scalar_as_bytes: [u8; 32],
}
impl From<Scalar> for SerializableRistrettoScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableRistrettoScalar {
            scalar_as_bytes: *scalar.as_bytes(),
        }
    }
}
impl From<SerializableRistrettoScalar> for Scalar {
    fn from(serialized_scalar: SerializableRistrettoScalar) -> Self {
        Scalar::from_bytes_mod_order(serialized_scalar.scalar_as_bytes)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SerializableAMFPublicKey {
    role: AMFRole,
    public_key: SerializableRistrettoPoint,
}
impl From<AMFPublicKey> for SerializableAMFPublicKey {
    fn from(public_key: AMFPublicKey) -> Self {
        SerializableAMFPublicKey {
            role: public_key.role,
            public_key: public_key.public_key.into(),
        }
    }
}
impl From<SerializableAMFPublicKey> for AMFPublicKey {
    fn from(serializable_public_key: SerializableAMFPublicKey) -> Self {
        AMFPublicKey {
            role: serializable_public_key.role,
            public_key: serializable_public_key.public_key.into(),
        }
    }
}

impl Serialize for AMFPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serializable_public_key = SerializableAMFPublicKey::from(*self);
        serializable_public_key.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for AMFPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serializable_public_key = SerializableAMFPublicKey::deserialize(deserializer)?;
        let public_key = AMFPublicKey::from(serializable_public_key);
        Ok(public_key)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO: Think about actually doing this in-place?
        let serializable_public_key = SerializableAMFPublicKey::deserialize(deserializer)?;
        *place = AMFPublicKey::from(serializable_public_key);
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SerializableAMFSecretKey {
    role: AMFRole,
    secret_key: SerializableRistrettoScalar,
}
impl From<AMFSecretKey> for SerializableAMFSecretKey {
    fn from(secret_key: AMFSecretKey) -> Self {
        SerializableAMFSecretKey {
            role: secret_key.role,
            secret_key: secret_key.secret_key.into(),
        }
    }
}
impl From<SerializableAMFSecretKey> for AMFSecretKey {
    fn from(serializable_secret_key: SerializableAMFSecretKey) -> Self {
        AMFSecretKey {
            role: serializable_secret_key.role,
            secret_key: serializable_secret_key.secret_key.into(),
        }
    }
}

impl Serialize for AMFSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serializable_secret_key = SerializableAMFSecretKey::from(*self);
        serializable_secret_key.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for AMFSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serializable_secret_key = SerializableAMFSecretKey::deserialize(deserializer)?;
        let secret_key = AMFSecretKey::from(serializable_secret_key);
        Ok(secret_key)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO: Think about actually doing this in-place?
        let serializable_secret_key = SerializableAMFSecretKey::deserialize(deserializer)?;
        *place = AMFSecretKey::from(serializable_secret_key);
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SerializableChaumPedersenProverCommitment {
    v_t: SerializableRistrettoPoint,
    w_t: SerializableRistrettoPoint,
}
impl From<ChaumPedersenProverCommitment> for SerializableChaumPedersenProverCommitment {
    fn from(commitment: ChaumPedersenProverCommitment) -> Self {
        SerializableChaumPedersenProverCommitment {
            v_t: commitment.v_t.into(),
            w_t: commitment.w_t.into(),
        }
    }
}
impl From<SerializableChaumPedersenProverCommitment> for ChaumPedersenProverCommitment {
    fn from(serialized_commitment: SerializableChaumPedersenProverCommitment) -> Self {
        ChaumPedersenProverCommitment {
            v_t: serialized_commitment.v_t.into(),
            w_t: serialized_commitment.w_t.into(),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SerializableOrProverResponse {
    c_0: SerializableRistrettoScalar,
    z_0: SerializableRistrettoScalar,
    z_1: SerializableRistrettoScalar,
}
impl From<OrProverResponse<Scalar, Scalar>> for SerializableOrProverResponse {
    fn from(response: OrProverResponse<Scalar, Scalar>) -> Self {
        SerializableOrProverResponse {
            c_0: response.c_0.into(),
            z_0: response.z_0.into(),
            z_1: response.z_1.into(),
        }
    }
}
impl From<SerializableOrProverResponse> for OrProverResponse<Scalar, Scalar> {
    fn from(serialized_response: SerializableOrProverResponse) -> Self {
        OrProverResponse {
            c_0: serialized_response.c_0.into(),
            z_0: serialized_response.z_0.into(),
            z_1: serialized_response.z_1.into(),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SerializableAMFInternalSignature {
    or_prover_commitment_0: (SerializableRistrettoPoint, SerializableRistrettoPoint),
    or_prover_commitment_1: (
        SerializableChaumPedersenProverCommitment,
        SerializableRistrettoPoint,
    ),
    or_prover_response_0: SerializableOrProverResponse,
    or_prover_response_1: SerializableOrProverResponse,
}
impl From<AMFInternalSignature> for SerializableAMFInternalSignature {
    fn from(signature: AMFInternalSignature) -> Self {
        SerializableAMFInternalSignature {
            or_prover_commitment_0: (
                signature.prover_commitment.0 .0.into(),
                signature.prover_commitment.0 .1.into(),
            ),
            or_prover_commitment_1: (
                signature.prover_commitment.1 .0.into(),
                signature.prover_commitment.1 .1.into(),
            ),
            or_prover_response_0: signature.prover_response.0.into(),
            or_prover_response_1: signature.prover_response.1.into(),
        }
    }
}
impl From<SerializableAMFInternalSignature> for AMFInternalSignature {
    fn from(serialized_signature: SerializableAMFInternalSignature) -> Self {
        AMFInternalSignature {
            prover_commitment: (
                (
                    serialized_signature.or_prover_commitment_0.0.into(),
                    serialized_signature.or_prover_commitment_0.1.into(),
                ),
                (
                    serialized_signature.or_prover_commitment_1.0.into(),
                    serialized_signature.or_prover_commitment_1.1.into(),
                ),
            ),
            prover_response: (
                serialized_signature.or_prover_response_0.into(),
                serialized_signature.or_prover_response_1.into(),
            ),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct SerializableAMFSignature {
    pi: SerializableAMFInternalSignature,
    J: SerializableRistrettoPoint,
    R: SerializableRistrettoPoint,
    E_J: SerializableRistrettoPoint,
    E_R: SerializableRistrettoPoint,
}
impl From<AMFSignature> for SerializableAMFSignature {
    fn from(amf_signature: AMFSignature) -> Self {
        SerializableAMFSignature {
            pi: amf_signature.pi.into(),
            J: amf_signature.J.into(),
            R: amf_signature.R.into(),
            E_J: amf_signature.E_J.into(),
            E_R: amf_signature.E_R.into(),
        }
    }
}
impl From<SerializableAMFSignature> for AMFSignature {
    fn from(serialized_amf_signature: SerializableAMFSignature) -> Self {
        AMFSignature {
            pi: serialized_amf_signature.pi.into(),
            J: serialized_amf_signature.J.into(),
            R: serialized_amf_signature.R.into(),
            E_J: serialized_amf_signature.E_J.into(),
            E_R: serialized_amf_signature.E_R.into(),
        }
    }
}

impl Serialize for AMFSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serializable_amf_signature = SerializableAMFSignature::from(*self);
        serializable_amf_signature.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for AMFSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serializable_amf_signature = SerializableAMFSignature::deserialize(deserializer)?;
        let amf_signature = AMFSignature::from(serializable_amf_signature);
        Ok(amf_signature)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO: Think about actually doing this in-place?
        let serializable_amf_signature = SerializableAMFSignature::deserialize(deserializer)?;
        *place = AMFSignature::from(serializable_amf_signature);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::amf::{frank, keygen};

    use super::*;

    #[test]
    fn test_public_key_codec() {
        let (public_key, _secret_key) = keygen(AMFRole::Sender);

        let encoded_public_key = bincode::serialize(&public_key).unwrap();
        let decoded_public_key: AMFPublicKey =
            bincode::deserialize(&encoded_public_key[..]).unwrap();
        assert_eq!(public_key, decoded_public_key);

        println!(
            "encoded amf public key length: {:?} bytes",
            encoded_public_key.len()
        );
    }

    #[test]
    fn test_secret_key_codec() {
        let (_public_key, secret_key) = keygen(AMFRole::Sender);

        let encoded_secret_key = bincode::serialize(&secret_key).unwrap();
        let decoded_secret_key: AMFSecretKey =
            bincode::deserialize(&encoded_secret_key[..]).unwrap();
        assert_eq!(secret_key, decoded_secret_key);

        println!(
            "encoded amf secret key length: {:?} bytes",
            encoded_secret_key.len()
        );
    }

    #[test]
    fn test_signature_codec() {
        // 0. Initialize a Sender
        let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
        // 1. Initialize a Recipient
        let (recipient_public_key, _recipient_secret_key) = keygen(AMFRole::Recipient);
        // 2. Initialize a Judge
        let (judge_public_key, _judge_secret_key) = keygen(AMFRole::Judge);

        // 3. Initialize a message
        let message = b"hello world!";

        // 4. Frank the message
        let amf_signature = frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            judge_public_key,
            message,
        );

        // 5. Test serializing the amf_signature
        let encoded_amf_signature = bincode::serialize(&amf_signature).unwrap();
        let decoded_amf_signature: AMFSignature =
            bincode::deserialize(&encoded_amf_signature[..]).unwrap();
        assert_eq!(amf_signature, decoded_amf_signature);

        println!(
            "encoded amf signature length: {:?} bytes",
            encoded_amf_signature.len()
        );
    }
}
