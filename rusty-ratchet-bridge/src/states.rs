use std::panic::catch_unwind;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::jlong;
use rusty_ratchet::states::States;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_newState<'local>(
    _env: JNIEnv<'local>,
    _class: JClass,
) -> JByteArray<'local> {
    let state = States::default();
    _env.byte_array_from_slice(
        state.serialize()
            .expect("Should be a serialized state")
            .as_slice()
    ).expect("Is valid byte array")
}