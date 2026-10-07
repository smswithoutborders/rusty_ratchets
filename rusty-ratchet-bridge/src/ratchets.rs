use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::jlong;
use rusty_ratchet::states::States;
use zeroize::Zeroizing;

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
    ).expect("I should initialize a ratchet state");

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
    ).expect("I should get a state");

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
) -> (jlong, JByteArray<'local>, JByteArray<'local>) {
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
    ).expect("I should have an encrypted payload");

    let state = Box::new(encrypted_payload.state.clone());
    let payload = encrypted_payload.payload.clone();
    let header = encrypted_payload.header
        .serialize()
        .expect("I should get a header");
    (
        Box::into_raw(state) as jlong,
        _env.byte_array_from_slice(&payload).expect("I should get a vector"),
        _env.byte_array_from_slice(&header).expect("I should get a vector"),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_decrypt<'local>(
    _env: JNIEnv<'local >,
    _class: JClass<'local>,
    handle: jlong,
    ciphertext: JByteArray<'local>,
    header: JByteArray<'local>,
    ad: JByteArray<'local>,
) -> (jlong, JByteArray<'local>) {
    let state = unsafe { &*(handle as *const States) };

    let header= _env
        .convert_byte_array(&header)
        .expect("I should get a vector");

    let header = rusty_ratchet::header::HEADER::deserialize(header.as_slice())
        .expect("I should get a header");

    let ciphertext: Vec<u8> = _env
        .convert_byte_array(&ciphertext)
        .expect("I should get a vector");

    let ad: Vec<u8> = _env
        .convert_byte_array(&ad)
        .expect("I should get a vector");

    let decrypted_payload = rusty_ratchet::ratchets::ratchet_decrypt(
        state.clone(),
        header,
        ciphertext.as_slice(),
        ad.as_slice(),
    ).expect("I should have a decrypted payload");

    let state = Box::new(decrypted_payload.state.clone());
    let payload = decrypted_payload.payload.clone();
    (
        Box::into_raw(state) as jlong,
        _env.byte_array_from_slice(&payload).expect("I should get a vector"),
    )
}
