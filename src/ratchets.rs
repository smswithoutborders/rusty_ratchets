use crate::functions::{concat, decrypt, dh, encrypt, generate_dh, kdf_ck, kdf_rk, EncryptedPayload, DecryptedPayload};
use crate::header::HEADER;
use crate::states::States;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

type Result<T> = std::result::Result<T, RatchetsError>;

#[derive(Debug)]
pub enum RatchetsError {
    RatchetInitFailedForAlice,
    RatchetInitFailedForBob,
    ExceededMaxSkipMessages,
}

#[derive(Debug)]
pub struct RatchetEncryptedPayload {
    state: States,
    header: HEADER,
    payload: EncryptedPayload,
}

#[derive(Debug)]
pub struct RatchetDecryptedPayload {
    state: States,
    payload: DecryptedPayload,
}

const MAX_SKIP: u8 = 255u8;


pub fn ratchet_init_alice(
    mut state: States,
    sk: &[u8],
    bob_dh_public_key: &[u8],
) -> Result<States>{
    state.dhs = generate_dh().expect("Failed to generate DH keys");
    let bob_dh_public_key: [u8; 32] = bob_dh_public_key.try_into()
        .expect("Invalid public key");
    state.dhr = Some(PublicKey::from(bob_dh_public_key));
    let (rk, cks) = kdf_rk(
        sk.try_into().expect("Should be 32 bytes"),
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


pub fn ratchet_init_bob(
    state: States,
    sk: &[u8],
    bob_dh_key_pair: &[u8],
) -> Result<States>{
    let mut state: States = state.try_into().expect("Ratchet State wrong");
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


pub fn ratchet_encrypt(
    state: States,
    plaintext: &[u8],
    ad: &[u8]
) -> Result<RatchetEncryptedPayload>{
    let state: States = state.try_into().expect("Ratchet State wrong");
    let (state, ns, mk) = ratchet_send_key(state.clone())
        .expect("Failed to ratchet encrypt key");
    let public_key = PublicKey::from(&state.dhs);
    let header = HEADER::new(public_key, state.pn, ns)
        .expect("Failed to ratchet encrypt header");
    let ciphertext = encrypt(
        mk,
        plaintext,
        concat(ad, header.clone()).expect("values should concat").as_ref()
    ).expect("Plaintext should be encrypted");

    Ok(RatchetEncryptedPayload {
        state: state.try_into().expect("State should be RustyState"),
        header,
        payload: ciphertext,
    })
}

fn try_skipped_message_keys(mut state: States, header: HEADER) -> Result<(States, Option<[u8; 32]>)>{
    match state.mk_skipped.get(&(header.dh, header.n)) {
        None => { Ok((state, None)) }
        Some(_) => {
            let mk = state.mk_skipped[&(header.dh, header.n)];
            state.mk_skipped.remove(&(header.dh, header.n));
            Ok((state, Some(mk)))
        }
    }
}

fn skip_message_keys(mut state: States, until: u16) -> Result<States>{
    if (state.nr + MAX_SKIP as u16) < until {
        return Err(RatchetsError::ExceededMaxSkipMessages);
    }

    if state.ckr.is_some() {
        while state.nr < until {
            let (cks, mk) = kdf_ck(state.ckr
                .expect("chain key should be present")
                .as_slice())
                .expect("Chain key should be present");
            state.ckr = Some(cks);
            state.mk_skipped.insert(
                (state.dhr.expect("Public key should be presetn"), state.nr),
                mk
            );
            state.nr += 1;
        }
    }

    Ok(state)
}

fn dh_ratchet(mut state: States, header: HEADER) -> Result<States>{
    state.pn = state.ns;
    state.ns = 0;
    state.nr = 0;
    state.dhr = Some(header.dh);
    let (rk, ckr) = kdf_rk(
        state.rk,
        dh(state.dhs, state.dhr.expect("Chain key should be present"))
            .expect("Failed to derive key")
    ).expect("Failed to derive key");
    state.rk = rk;
    state.ckr = Some(ckr);
    state.dhs = generate_dh().expect("Failed to generate DH keys");
    let (rk, ckr) = kdf_rk(
        state.rk,
        dh(state.dhs.clone(), state.dhr.expect("Chain key should be present"))
            .expect("Failed to derive key")
    ).expect("Failed to derive key");
    state.rk = rk;
    state.cks = Some(ckr);

    Ok(state)
}

fn ratchet_receive_key(state: States, header: HEADER) -> Result<(States, [u8; 32])> {
    let (mut state, mk) = try_skipped_message_keys(state.clone(), header.clone())
        .expect("Failed to skip message keys");
    if mk.is_some() { return Ok((state, mk.unwrap())) }

    if header.dh != state.dhr.expect("DH key should be present") {
        state = skip_message_keys(state.clone(), header.pn).expect("should be state");
        state = dh_ratchet(state.clone(), header.clone()).expect("should be state");
    }
    state = skip_message_keys(state.clone(), header.n).expect("should be state");
    let (ckr, mk) = kdf_ck(state.ckr.expect("chain key should be present").as_slice())
        .expect("Chain key should be present");
    state.ckr = Some(ckr);
    state.nr += 1;
    Ok((state, mk))
}

pub fn ratchet_decrypt(state: States, header: HEADER, ciphertext: &[u8], ad: &[u8]) -> Result<RatchetDecryptedPayload>{
    let (state, mk) = ratchet_receive_key(state, header.clone()).expect("Failed to ratchet receive key");
    let decrypted_payload = decrypt(mk, ciphertext, concat(ad, header).expect("should concat").as_ref())
        .expect("Ciphertext should be decrypted");

    Ok(RatchetDecryptedPayload {
        state,
        payload: decrypted_payload,
    })
}