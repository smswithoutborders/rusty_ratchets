mod states;
mod ratchets;

use std::panic::catch_unwind;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, jstring};
use rusty_ratchet::states::States;
use zeroize::Zeroizing;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}


