use std::panic::{catch_unwind, AssertUnwindSafe};
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JObjectArray};
use jni::sys::jlong;
use rusty_ratchet::states::States;
use zeroize::Zeroizing;

enum RatchetsError {
    RatchetInitFailedForAlice(String),
    RatchetInitFailedForBob(String),
    ExceededMaxSkipMessages(String),
    FailedToSerializeState(String),
    FailedToDeserializeState(String),
    Jni(jni::errors::Error),
}

impl From<jni::errors::Error> for RatchetsError {
    fn from(e: jni::errors::Error) -> Self { RatchetsError::Jni(e) }
}

fn throw(env: &mut JNIEnv, err: RatchetsError) {
    match err {
        RatchetsError::RatchetInitFailedForAlice(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/RatchetInitFailedForAlice", m); }
        RatchetsError::RatchetInitFailedForBob(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/RatchetInitFailedForBob", m); }
        RatchetsError::ExceededMaxSkipMessages(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/ExceededMaxSkipMessages", m); }
        RatchetsError::FailedToDeserializeState(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToDeserializeState", m); }
        RatchetsError::FailedToSerializeState(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToSerializeState", m); }
        RatchetsError::Jni(jni::errors::Error::JavaException) => {}
        RatchetsError::Jni(e) =>
            { let _ = env.throw_new("java/lang/RuntimeException", e.to_string()); }
    }
}

fn run<'local, T>(
    env: &mut JNIEnv<'local>,
    default: T,
    f: impl FnOnce(&mut JNIEnv<'local>) -> Result<T, RatchetsError>,
) -> T {
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => { throw(env, e); default }
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "native panic");
            default
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_deku_rust_RustyRatchetBridge_initAlice<'local>(
    mut env: JNIEnv<'local >,
    _class: JClass<'local>,
    state: JByteArray<'local>,
    sk: JByteArray<'local>,
    bob_dh_public_key: JByteArray<'local>,
) -> JByteArray<'local> {
    run(&mut env, JByteArray::from(JObject::null()), |env| {
        let sk: Zeroizing<Vec<u8>> = Zeroizing::new(env
            .convert_byte_array(&sk)
            .expect("I should get a vector")
        );

        let bob_dh_public_key: Vec<u8> = env
            .convert_byte_array(&bob_dh_public_key)
            .expect("I should get a vector");

        let state: Vec<u8> = env
            .convert_byte_array(&state)
            .expect("I should get a vector");

        let state = States::deserialize(state.as_slice())
            .map_err(|e| RatchetsError::FailedToDeserializeState(format!("{e:?}")))?;

        let state = rusty_ratchet::ratchets::ratchet_init_alice(
            state,
            sk.as_slice(),
            bob_dh_public_key.as_slice(),
        ).map_err(|e| RatchetsError::RatchetInitFailedForAlice(format!("{e:?}")))?;

        Ok(
            env.byte_array_from_slice(
                state.serialize()
                    .expect("Should be a serialized state")
                    .as_slice()
            ).map_err(|e| RatchetsError::FailedToSerializeState(format!("{e:?}")))?
        )
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_deku_rust_RustyRatchetBridge_initBob<'local>(
    _env: JNIEnv<'local >,
    _class: JClass<'local>,
    state: JByteArray<'local>,
    sk: JByteArray<'local>,
    bob_keypair: JByteArray<'local>,
) -> JByteArray<'local> {
    // let state = unsafe { &*(handle as *const States) };

    let sk: Zeroizing<Vec<u8>> = Zeroizing::new(_env
        .convert_byte_array(&sk)
        .expect("I should get a vector")
    );

    let bob_keypair: Vec<u8> = _env
        .convert_byte_array(&bob_keypair)
        .expect("I should get a vector");

    let state: Vec<u8> = _env
        .convert_byte_array(&state)
        .expect("I should get a vector");

    let state = States::deserialize(state.as_slice())
        .expect("I should have a state object");

    let state = rusty_ratchet::ratchets::ratchet_init_bob(
        state,
        sk.as_slice(),
        bob_keypair.as_slice()
    ).expect("I should get a state");

    _env.byte_array_from_slice(
        state.serialize()
            .expect("Should be a serialized state")
            .as_slice()
    ).expect("Is valid byte array")
}


#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_deku_rust_RustyRatchetBridge_encrypt<'local>(
    mut env: JNIEnv<'local >,
    _class: JClass<'local>,
    state: JByteArray<'local>,
    plaintext: JByteArray<'local>,
    ad: JByteArray<'local>,
) -> JObjectArray<'local>{
    let plaintext: Vec<u8> = env
        .convert_byte_array(&plaintext)
        .expect("I should get a vector");

    let ad: Vec<u8> = env
        .convert_byte_array(&ad)
        .expect("I should get a vector");

    let state: Vec<u8> = env
        .convert_byte_array(&state)
        .expect("I should get a vector");

    let state = States::deserialize(state.as_slice())
        .expect("I should have a state object");

    let encrypted_payload = rusty_ratchet::ratchets::ratchet_encrypt(
        state,
        plaintext.as_slice(),
        ad.as_slice(),
    ).expect("I should have an encrypted payload");

    let state = Box::new(encrypted_payload.state.clone())
        .serialize()
        .expect("I should serialize state");
    let payload = encrypted_payload.payload.clone();
    let header = encrypted_payload.header
        .serialize()
        .expect("I should get a header");

    let result = env
        .new_object_array(3, "[B", JObject::null())
        .expect("I should create a new object array");

    for (i, bytes) in [state, payload, header].iter().enumerate() {
        let arr = env.byte_array_from_slice(bytes)
            .expect("I should have alloc of byte[]");
        env.set_object_array_element(&result, i as i32, arr)
            .expect("I should set the new array");
    }
    result
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_deku_rust_RustyRatchetBridge_decrypt<'local>(
    mut env: JNIEnv<'local >,
    _class: JClass<'local>,
    state: JByteArray<'local>,
    ciphertext: JByteArray<'local>,
    header: JByteArray<'local>,
    ad: JByteArray<'local>,
) -> JObjectArray<'local> {
    // let state = unsafe { &*(handle as *const States) };

    let header= env
        .convert_byte_array(&header)
        .expect("I should get a vector");

    let header = rusty_ratchet::header::HEADER::deserialize(header.as_slice())
        .expect("I should get a header");

    let ciphertext: Vec<u8> = env
        .convert_byte_array(&ciphertext)
        .expect("I should get a vector");

    let ad: Vec<u8> = env
        .convert_byte_array(&ad)
        .expect("I should get a vector");

    let state: Vec<u8> = env
        .convert_byte_array(&state)
        .expect("I should get a vector");

    let state = States::deserialize(state.as_slice())
        .expect("I should have a state object");

    let decrypted_payload = rusty_ratchet::ratchets::ratchet_decrypt(
        state,
        header,
        ciphertext.as_slice(),
        ad.as_slice(),
    ).expect("I should have a decrypted payload");

    let payload = decrypted_payload.payload.clone();
    let state = Box::new(decrypted_payload.state.clone())
        .serialize()
        .expect("I should serialize state");

    let result = env
        .new_object_array(3, "[B", JObject::null())
        .expect("I should create a new object array");

    for (i, bytes) in [state, payload].iter().enumerate() {
        let arr = env.byte_array_from_slice(bytes)
            .expect("I should have alloc of byte[]");
        env.set_object_array_element(&result, i as i32, arr)
            .expect("I should set the new array");
    }
    result
}
