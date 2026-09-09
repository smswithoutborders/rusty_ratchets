use std::collections::HashMap;
use std::sync::Arc;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use crate::functions::{dh, generate_dh, kdf_ck, kdf_rk, EncryptedPayload, encrypt, concat};
use crate::header::{HeaderError, HEADER};
use crate::states::{RustyState, States};

type Result<T> = std::result::Result<T, RatchetsError>;

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum RatchetsError {
    #[error("Ratchet init failed for Alice")]
    RatchetInitFailedForAlice,
    #[error("Ratchet init failed for Bob")]
    RatchetInitFailedForBob,
}

#[uniffi::export]
pub fn ratchet_init_alice(
    state: Arc<RustyState>,
    sk: &[u8],
    bob_dh_public_key: &[u8],
) -> Result<RustyState>{
    let mut state: States = match Arc::into_inner(state) {
        Some(state) => state.try_into().expect("Ratchet State wrong"),
        None => return Err(RatchetsError::RatchetInitFailedForAlice)
    };

    state.dhs = generate_dh().expect("Failed to generate DH keys");
    let bob_dh_public_key: [u8; 32] = bob_dh_public_key.try_into()
        .expect("Invalid public key");
    state.dhr = Some(PublicKey::from(bob_dh_public_key));
    let (rk, cks) = kdf_rk(
        sk,
        dh(
            state.dhs.clone(),
            state.dhr.clone().expect("Failed to generate DH keys"),
        ).expect("Failed to derive key")
    ).expect("Failed to derive key");
    state.rk = rk;
    state.cks = Some(cks);
    state.ckr = None;
    state.ns = 0;
    state.nr = 0;
    state.pn = 0;
    state.mk_skipped = HashMap::new();

    Ok(state.try_into().expect("Ratchet State wrong"))
}


#[uniffi::export]
pub fn ratchet_init_bob(
    state: Arc<RustyState>,
    sk: &[u8],
    bob_dh_key_pair: &[u8],
) -> Result<RustyState>{
    let mut state: States = match Arc::into_inner(state) {
        Some(state) => state.try_into().expect("Ratchet State wrong"),
        None => return Err(RatchetsError::RatchetInitFailedForBob)
    };

    let bob_dh_key_pair: [u8; 32] = bob_dh_key_pair.try_into().expect("Invalid public key");
    let bob_dh_key_pair = StaticSecret::from(bob_dh_key_pair);

    state.dhs = bob_dh_key_pair;
    state.dhr = None;
    state.rk = sk.try_into().expect("sk wrong");
    state.cks = None;
    state.ckr = None;
    state.ns = 0;
    state.nr = 0;
    state.pn = 0;
    state.mk_skipped = HashMap::new();

    Ok(state.try_into().expect("Ratchet State wrong"))
}

fn ratchet_send_key(mut state: States) -> Result<(States, u16, [u8; 32])> {
    let (cks, mk) = kdf_ck(state.cks.expect("chain key should be present").as_slice())
        .expect("Chain key should be present");
    state.cks = Some(cks);
    let ns = state.ns;
    state.ns += 1;
    Ok((state, ns, mk))
}


#[derive(Debug, uniffi::Object)]
struct RatchetEncryptedPayload {
    state: RustyState,
    header: HEADER,
    payload: EncryptedPayload,
}

#[uniffi::export]
fn ratchet_encrypt(
    state: Arc<RustyState>,
    plaintext: &[u8],
    ad: &[u8]
) -> Result<Arc<RatchetEncryptedPayload>>{
    let state: States = match Arc::into_inner(state) {
        Some(state) => state.try_into().expect("Ratchet State wrong"),
        None => return Err(RatchetsError::RatchetInitFailedForBob)
    };
    let (state, ns, mk) = ratchet_send_key(state.clone())
        .expect("Failed to ratchet encrypt key");
    let header = HEADER::new(state.dhs.as_ref(), state.pn, ns)
        .expect("Failed to ratchet encrypt header");
    let ciphertext = encrypt(
        mk,
        plaintext,
        concat(ad, header.clone()).expect("values should concat").as_ref()
    ).expect("Plaintext should be encrypted");

    Ok(Arc::new(RatchetEncryptedPayload {
        state: state.try_into().expect("State should be RustyState"),
        header,
        payload: ciphertext,
    }))
}
