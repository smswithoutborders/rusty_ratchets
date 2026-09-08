use std::collections::HashMap;
use std::sync::Arc;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use crate::functions::{dh, generate_dh, kdf_rk};
use crate::header::HeaderError;
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
fn ratchet_init_alice(
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
    (state.rk, state.cks) = kdf_rk(
        sk,
        dh(
            state.dhs.clone(),
            state.dhr.clone().expect("Failed to generate DH keys"),
        ).expect("Failed to derive key")
    ).expect("Failed to derive key");
    state.ckr = None;
    state.ns = 0;
    state.nr = 0;
    state.pn = 0;
    state.mk_skipped = HashMap::new();

    Ok(state.try_into().expect("Ratchet State wrong"))
}


#[uniffi::export]
fn ratchet_init_bob(
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
