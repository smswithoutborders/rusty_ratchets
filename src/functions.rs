use std::sync::Arc;
use hkdf::{GenericHkdf, Hkdf};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
// use sha2::digest::{KeyInit, Mac};
use sha2::Sha512;
use hmac::{Hmac, KeyInit, Mac};
// Imports both required traits

#[derive(Debug)]
pub enum FunctionsError {

}

type Result<T> = std::result::Result<T, FunctionsError>;


#[derive(Debug)]
pub struct KdfRkOutput {
    rk: Vec<u8>,
    ck: Vec<u8>,
}

#[derive(Debug)]
pub struct KdfCkOutput {
    ck: Vec<u8>,
    mk: Vec<u8>,
}

fn generate_dh() -> Result<StaticSecret> {
    Ok(StaticSecret::random())
}

fn dh(
    dh_pair: StaticSecret,
    dh_pub: PublicKey,
) -> Result<SharedSecret>{
    let shared_secret = dh_pair.diffie_hellman(&dh_pub);
    Ok(shared_secret)
}

type HkdfSha512 = Hkdf<Sha512>;
type HmacSha512 = Hmac<Sha512>;

fn kdf_rk(
    rk: &[u8],
    dh_out: &[u8],
) -> Result<KdfRkOutput>{
    let mut keys = [0u8; 64];
    let info = "RUSTY_RACHET_KDF_RK_SHA512".as_bytes();

    let hkdf = HkdfSha512::new(
        Some(rk.as_ref()),
        dh_out.as_ref()
    );

    hkdf.expand(
        &info,
        &mut keys
    ).expect("64 should be a valid length here");

    Ok(KdfRkOutput {
        rk: keys[0..32].to_vec(),
        ck: keys[32..64].to_vec(),
    })
}

fn kdf_ck(ck: &[u8]) -> Result<KdfCkOutput> {
    let mut mac = HmacSha512::new_from_slice(ck)
        .expect("HMAC can take a key of any length");

    mac.update(b"RUSTY_RACHET_KDF_CK");
    mac.update(b"RUSTY_RACHET_KDF_CK");
    let keys = mac.finalize().into_bytes(); // 64-byte GenericArray

    Ok(KdfCkOutput {
        ck: keys[0..32].to_vec(),
        mk: keys[32..64].to_vec(),
    })
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