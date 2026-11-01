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
    FailedToEncryptPayload(String),
    FailedToSerializeHeader(String),
    FailedToStoreFinalEncryptionValues(String),
    FailedToStoreFinalDecryptionValues(String),
    FailedToDecryptPayload(String),
    FailedToDeserializeHeader(String),
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
        RatchetsError::FailedToEncryptPayload(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToEncryptPayload", m); }
        RatchetsError::FailedToSerializeHeader(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToSerializeHeader", m); }
        RatchetsError::FailedToStoreFinalEncryptionValues(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToStoreFinalEncryptionValues", m); }
        RatchetsError::FailedToStoreFinalDecryptionValues(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToStoreFinalDecryptionValues", m); }
        RatchetsError::FailedToDecryptPayload(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToDecryptPayload", m); }
        RatchetsError::FailedToDeserializeHeader(m) =>
            { let _ = env.throw_new("com/afkanerd/lib/FailedToDeserializeHeader", m); }
        RatchetsError::Jni(jni::errors::Error::JavaException) => {}
        RatchetsError::Jni(e) =>
            { let _ = env.throw_new("java/lang/RuntimeException", e.to_string()); }
    }
}

fn panic_msg(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() { s.to_string() }
    else if let Some(s) = p.downcast_ref::<String>() { s.clone() }
    else { "unknown panic".into() }
}

fn run<'local, T>(
    env: &mut JNIEnv<'local>,
    default: T,
    f: impl FnOnce(&mut JNIEnv<'local>) -> Result<T, RatchetsError>,
) -> T {
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => { throw(env, e); default }
        Err(p) => {
            let msg = panic_msg(&p);
            log::error!("native panic: {msg}");
            let _ = env.throw_new("java/lang/RuntimeException", format!("native panic: {msg}"));
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
    mut env: JNIEnv<'local >,
    _class: JClass<'local>,
    state: JByteArray<'local>,
    sk: JByteArray<'local>,
    bob_keypair: JByteArray<'local>,
) -> JByteArray<'local> {
    // let state = unsafe { &*(handle as *const States) };
    run(&mut env, JByteArray::from(JObject::null()), |env| {
        let sk: Zeroizing<Vec<u8>> = Zeroizing::new(env
            .convert_byte_array(&sk)
            .expect("I should get a vector")
        );

        let bob_keypair: Vec<u8> = env
            .convert_byte_array(&bob_keypair)
            .expect("I should get a vector");

        let state: Vec<u8> = env
            .convert_byte_array(&state)
            .expect("I should get a vector");

        let state = States::deserialize(state.as_slice())
            .map_err(|e| RatchetsError::FailedToDeserializeState(format!("{e:?}")))?;

        let state = rusty_ratchet::ratchets::ratchet_init_bob(
            state,
            sk.as_slice(),
            bob_keypair.as_slice()
        ).map_err(|e| RatchetsError::RatchetInitFailedForBob(format!("{e:?}")))?;

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
pub extern "system" fn Java_com_afkanerd_deku_rust_RustyRatchetBridge_encrypt<'local>(
    mut env: JNIEnv<'local >,
    _class: JClass<'local>,
    state: JByteArray<'local>,
    plaintext: JByteArray<'local>,
    ad: JByteArray<'local>,
) -> JObjectArray<'local>{
    run(&mut env, JObjectArray::from(JObject::null()), |env| {
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
            .map_err(|e| RatchetsError::FailedToDeserializeState(format!("{e:?}")))?;

        let encrypted_payload = rusty_ratchet::ratchets::ratchet_encrypt(
            state,
            plaintext.as_slice(),
            ad.as_slice(),
        ).map_err(|e| RatchetsError::FailedToEncryptPayload(format!("{e:?}")))?;

        let state = encrypted_payload.state.clone()
            .serialize()
            .expect("I should serialize state");

        let payload = encrypted_payload.payload.clone();
        let header = encrypted_payload.header
            .serialize()
            .map_err(|e| RatchetsError::FailedToSerializeHeader(format!("{e:?}")))?;

        let result = env
            .new_object_array(3, "[B", JObject::null())
            .expect("I should create a new object array");

        for (i, bytes) in [state, payload, header].iter().enumerate() {
            let arr = env.byte_array_from_slice(bytes)
                .expect("I should have alloc of byte[]");
            env.set_object_array_element(&result, i as i32, arr)
                .map_err(|e| RatchetsError::FailedToStoreFinalEncryptionValues(format!("{e:?}")))?;
        }
        Ok(result)
    })
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
    run(&mut env, JObjectArray::from(JObject::null()), |env| {
        let header= env
            .convert_byte_array(&header)
            .expect("I should get a vector");

        let header = rusty_ratchet::header::HEADER::deserialize(header.as_slice())
            .map_err(|e| RatchetsError::FailedToDeserializeHeader(format!("{e:?}")))?;

        let ciphertext: Vec<u8> = env
            .convert_byte_array(&ciphertext)
            .expect("I should get a vector");

        let ad: Vec<u8> = env
            .convert_byte_array(&ad)
            .expect("I should get a vector");

        let state: Vec<u8> = env
            .convert_byte_array(&state)
            .map_err(|e| RatchetsError::FailedToDeserializeState(format!("{e:?}")))?;


        let state = States::deserialize(state.as_slice())
            .map_err(|e| RatchetsError::FailedToDeserializeState(format!("{e:?}")))?;

        let decrypted_payload = rusty_ratchet::ratchets::ratchet_decrypt(
            state,
            header,
            ciphertext.as_slice(),
            ad.as_slice(),
        ).map_err(|e| RatchetsError::FailedToDecryptPayload(format!("{e:?}")))?;

        let payload = decrypted_payload.payload.clone();
        let state = decrypted_payload.state.clone()
            .serialize()
            .map_err(|e| RatchetsError::FailedToSerializeState(format!("{e:?}")))?;

        let result = env
            .new_object_array(2, "[B", JObject::null())
            .expect("I should create a new object array");

        for (i, bytes) in [state, payload].iter().enumerate() {
            let arr = env.byte_array_from_slice(bytes)
                .expect("I should have alloc of byte[]");
            env.set_object_array_element(&result, i as i32, arr)
                .map_err(|e| RatchetsError::FailedToStoreFinalDecryptionValues(format!("{e:?}")))?;
        }
        Ok(result)
    })
}
