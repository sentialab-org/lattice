use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn generate_private_key() -> [u8; 32] {
    SigningKey::generate(&mut OsRng).to_bytes()
}

pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes()
}

pub fn encode_bytes(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub fn decode_bytes(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| error.to_string())
}

pub fn encode_key(key: &[u8]) -> String {
    encode_bytes(key)
}

pub fn decode_key<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode_bytes(value)?
        .try_into()
        .map_err(|_| format!("expected {N} bytes"))
}

pub fn sign<T: Serialize>(private_key: &[u8; 32], value: &T) -> Result<String, String> {
    let payload = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let signing_key = SigningKey::from_bytes(private_key);
    Ok(encode_bytes(&signing_key.sign(&payload).to_bytes()))
}

pub fn verify<T: Serialize>(
    public_key_value: &str,
    signature_value: &str,
    value: &T,
) -> Result<(), String> {
    let public_key_bytes = decode_key::<32>(public_key_value)?;
    let signature_bytes = decode_key::<64>(signature_value)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|error| error.to_string())?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|error| error.to_string())
}

pub fn fingerprint(public_key_value: &str) -> Result<String, String> {
    let key = decode_key::<32>(public_key_value)?;
    let digest = Sha256::digest(key);
    Ok(digest
        .chunks(2)
        .map(hex_chunk)
        .collect::<Vec<_>>()
        .join(":"))
}

fn hex_chunk(chunk: &[u8]) -> String {
    chunk
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Payload {
        node_id: String,
        value: u64,
    }

    #[test]
    fn signs_and_verifies_payload() {
        let private_key = generate_private_key();
        let public_key_value = encode_key(&public_key(&private_key));
        let payload = Payload {
            node_id: "node-test".to_string(),
            value: 42,
        };
        let signature = sign(&private_key, &payload).unwrap();
        verify(&public_key_value, &signature, &payload).unwrap();
    }

    #[test]
    fn rejects_modified_payload() {
        let private_key = generate_private_key();
        let public_key_value = encode_key(&public_key(&private_key));
        let payload = Payload {
            node_id: "node-test".to_string(),
            value: 42,
        };
        let signature = sign(&private_key, &payload).unwrap();
        let changed = Payload {
            node_id: "node-test".to_string(),
            value: 43,
        };
        assert!(verify(&public_key_value, &signature, &changed).is_err());
    }
}
