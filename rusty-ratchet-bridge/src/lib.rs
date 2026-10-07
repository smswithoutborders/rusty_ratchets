mod states;

use std::panic::catch_unwind;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, jstring};
use rusty_ratchet::states::States;
use zeroize::Zeroizing;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_initAlice<'local>(
    _env: JNIEnv<'local >,
    _class: JClass<'local>,
    handle: jlong,
    sk: JByteArray<'local>,
    bob_dh_public_key: JByteArray<'local>,
) -> jlong {
    let state = unsafe { &*(handle as *const States) };

    let sk: Zeroizing<Vec<u8>> = Zeroizing::new(_env
        .convert_byte_array(&sk)
        .expect("I should get a vector")
    );

    let bob_dh_public_key: Vec<u8> = _env
        .convert_byte_array(&bob_dh_public_key)
        .expect("I should get a vector");

    let state = rusty_ratchet::ratchets::ratchet_init_alice(
        state.clone(),
        sk.as_slice(),
        bob_dh_public_key.as_slice(),
    );

    let state = Box::new(state);
    Box::into_raw(state) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_initBob<'local>(
    _env: JNIEnv<'local >,
    _class: JClass<'local>,
    handle: jlong,
    sk: JByteArray<'local>,
    bob_keypair: JByteArray<'local>,
) -> jlong {
    let state = unsafe { &*(handle as *const States) };

    let sk: Zeroizing<Vec<u8>> = Zeroizing::new(_env
        .convert_byte_array(&sk)
        .expect("I should get a vector")
    );

    let bob_keypair: Vec<u8> = _env
        .convert_byte_array(&bob_keypair)
        .expect("I should get a vector");

    let state = rusty_ratchet::ratchets::ratchet_init_bob(
        state.clone(),
        sk.as_slice(),
        bob_keypair.as_slice()
    );

    let state = Box::new(state);
    Box::into_raw(state) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_encrypt<'local>(
    _env: JNIEnv<'local >,
    _class: JClass<'local>,
    handle: jlong,
    plaintext: JByteArray<'local>,
    ad: JByteArray<'local>,
) -> jlong {
    let state = unsafe { &*(handle as *const States) };

    let plaintext: Vec<u8> = _env
        .convert_byte_array(&plaintext)
        .expect("I should get a vector");

    let ad: Vec<u8> = _env
        .convert_byte_array(&ad)
        .expect("I should get a vector");

    let encrypted_payload = rusty_ratchet::ratchets::ratchet_encrypt(
        state.clone(),
        plaintext.as_slice(),
        ad.as_slice(),
    );

    let state = Box::new(state);
    Box::into_raw(state) as jlong
}
