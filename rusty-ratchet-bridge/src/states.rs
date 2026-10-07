use std::panic::catch_unwind;
use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jlong;
use rusty_ratchet::states::States;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_newState(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let state = Box::new(States::default());
    Box::into_raw(state) as jlong
}


#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_afkanerd_dekusms_rust_RustyRatchetBridge_freeState(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr == 0 {
        return;
    }
    let _ = catch_unwind(|| {
        // Reconstruct the Box so Rust safely drops and deallocates it
        let _ = unsafe { Box::from_raw(ptr as *mut States) };
    });
}
