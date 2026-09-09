use crate::header::HEADER;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, Payload};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

type Result<T> = std::result::Result<T, FunctionsError>;
const ENCRYPTION_DECRYPTION_INFO: &[u8] = "RUSTY_RACHET_CHACHA_POLY1305_ENCRYPTION_DECRYPTION".as_bytes();
type HkdfSha256 = Hkdf<Sha256>;
type HmacSha256 = Hmac<Sha256>;


#[derive(Debug, thiserror::Error)]
pub enum FunctionsError {
    #[error("Failed to encrypt: {err}")]
    FailedToEncrypt {
        err: String,
    },

    #[error("Failed to decrypt: {err}")]
    FailedToDecrypt {
        err: String,
    },
}

#[derive(PartialEq, Debug)]
pub struct EncryptedPayload {
    payload: Vec<u8>,
    mk: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct DecryptedPayload {
    payload: Vec<u8>,
    mk: Vec<u8>,
}

pub fn generate_dh() -> Result<StaticSecret> {
    Ok(StaticSecret::random())
}

pub fn dh(
    dh_pair: StaticSecret,
    dh_pub: PublicKey,
) -> Result<SharedSecret>{
    let shared_secret = dh_pair.diffie_hellman(&dh_pub);
    Ok(shared_secret)
}

pub fn kdf_rk(
    rk: &[u8],
    dh_out: SharedSecret,
) -> Result<([u8; 32], [u8; 32])> {
    let info = "RUSTY_RACHET_KDF_RK_SHA512".as_bytes();

    let hkdf = HkdfSha256::new(
        Some(rk.as_ref()),
        dh_out.as_ref()
    );

    let mut keys = [0u8; 64];
    hkdf.expand(
        &info,
        &mut keys
    ).expect("64 should be a valid length here");

    let rk: [u8; 32] = keys[0..32].try_into().expect("32 bytes");
    let ck: [u8; 32] = keys[32..64].try_into().expect("32 bytes");
    Ok((rk, ck))
}

pub fn kdf_ck(_ck: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut mac = HmacSha256::new_from_slice(_ck)
        .expect("HMAC can take a key of any length");
    mac.update(&[1u8]);
    let mk = mac.finalize().into_bytes().0;

    let mut mac = HmacSha256::new_from_slice(_ck)
        .expect("HMAC can take a key of any length");
    mac.update(&[2u8]);
    let ck= mac.finalize().into_bytes().0;

    Ok((ck, mk))
}


pub fn encrypt(
    mk: [u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedPayload> {
    let salt = [0u8; 80];

    let hkdf = HkdfSha256::new(
        Some(salt.as_ref()),
        mk.as_ref()
    );

    let mut outputs = [0u8; 80];
    hkdf.expand(
        &ENCRYPTION_DECRYPTION_INFO,
        &mut outputs
    ).expect("80 should be a valid length here");

    let key: [u8; 32] = outputs[0..32].try_into().expect("32 bytes");
    // let authentication_key = outputs[32..64].try_into().expect("32 bytes");
    let nonce = outputs[64..76].try_into().expect("12 bytes");

    let payload = Payload {
        msg: &plaintext,
        aad: associated_data
    };

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .expect("ChaCha20Poly1305::new_from_slice failed");

    match cipher.encrypt(&nonce, payload) {
        Ok(ciphertext) => Ok(EncryptedPayload {
            payload: ciphertext,
            mk: key.to_vec(),
        }),
        Err(e) => Err(FunctionsError::FailedToEncrypt { err: e.to_string() }),
    }
}

pub fn decrypt(
    mk: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<DecryptedPayload> {
    let salt = [0u8; 80];

    let hkdf = HkdfSha256::new(
        Some(salt.as_ref()),
        mk.as_ref()
    );

    let mut outputs = [0u8; 80];
    hkdf.expand(
        &ENCRYPTION_DECRYPTION_INFO,
        &mut outputs
    ).expect("80 should be a valid length here");

    let key: [u8; 32] = outputs[0..32].try_into().expect("32 bytes");
    // let authentication_key = outputs[32..64].try_into().expect("32 bytes");
    let nonce = outputs[64..76].try_into().expect("12 bytes");

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .expect("ChaCha20Poly1305::new_from_slice failed");

    let payload = Payload {
        msg: &ciphertext,
        aad: associated_data
    };

    match cipher.decrypt(&nonce, payload) {
        Ok(ciphertext) => Ok(DecryptedPayload {
            payload: ciphertext,
            mk: key.to_vec(),
        }),
        Err(e) => Err(FunctionsError::FailedToDecrypt { err: e.to_string() }),
    }
}

pub fn concat(
    ad: &[u8],
    header: HEADER,
) -> Result<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();

    bytes.extend(ad);

    let serialized_header = header.serialize()
        .expect("header should be serializable");

    bytes.extend(serialized_header);
    Ok(bytes)
}

#[test]
fn test_generate_dh() {
    let alice_keypair = generate_dh().unwrap();
    let bob_keypair = generate_dh().unwrap();

    let alice_public_key = PublicKey::from(&alice_keypair);
    let bob_public_key = PublicKey::from(&bob_keypair);

    let alice_ss = dh(alice_keypair, bob_public_key).unwrap();
    let bob_ss = dh(bob_keypair, alice_public_key).unwrap();

    assert_eq!(alice_ss.as_bytes(), bob_ss.as_bytes());
}

#[test]
fn test_encryption_decryption() {
    let mk: [u8; 32] = rand::rng().random();
    let plaintext: [u8; 32] = rand::rng().random();
    let ad: [u8; 32] = rand::rng().random();

    let encrypted_payload = encrypt(
        mk,
        plaintext.as_ref(),
        ad.as_ref(),
    ).unwrap();

    let decrypted_payload = decrypt(
        mk.as_ref(),
        encrypted_payload.payload.as_ref(),
        ad.as_ref(),
    ).unwrap();

    assert_eq!(decrypted_payload.payload, plaintext.as_ref());
}
