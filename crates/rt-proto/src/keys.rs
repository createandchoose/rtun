use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::errors::KeyError;

pub fn parse_private_key(value: &str) -> Result<[u8; 32], KeyError> {
    decode_key(value)
}

pub fn parse_public_key(value: &str) -> Result<[u8; 32], KeyError> {
    decode_key(value)
}

fn decode_key(value: &str) -> Result<[u8; 32], KeyError> {
    let trimmed = value.trim();
    let decoded = STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))?;
    if decoded.len() != 32 {
        return Err(KeyError::Length(decoded.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

pub fn generate_private_key() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let encoded = STANDARD.encode(bytes);
    bytes.zeroize();
    encoded
}

pub fn public_key_from_private(private: &str) -> Result<String, KeyError> {
    let mut bytes = parse_private_key(private)?;
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    let public = PublicKey::from(&secret);
    Ok(STANDARD.encode(public.as_bytes()))
}

pub fn derive_public_key(private: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    *PublicKey::from(&secret).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_roundtrip() {
        let private = generate_private_key();
        let public = public_key_from_private(&private).unwrap();
        assert_eq!(parse_private_key(&private).unwrap().len(), 32);
        assert_eq!(parse_public_key(&public).unwrap().len(), 32);
        assert_ne!(private, public);
    }

    #[test]
    fn accepts_unpadded_base64() {
        let private = generate_private_key();
        let unpadded = private.trim_end_matches('=');
        assert_eq!(
            parse_private_key(&private).unwrap(),
            parse_private_key(unpadded).unwrap()
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let short = STANDARD.encode([1u8; 31]);
        assert!(matches!(
            parse_private_key(&short),
            Err(KeyError::Length(31))
        ));
    }

    #[test]
    fn public_key_is_deterministic() {
        let private = generate_private_key();
        let a = public_key_from_private(&private).unwrap();
        let b = public_key_from_private(&private).unwrap();
        assert_eq!(a, b);
    }
}
