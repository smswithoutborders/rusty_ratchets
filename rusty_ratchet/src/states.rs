use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use x25519_dalek::{PublicKey, StaticSecret};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum StatesError {
    FailedToDeserialize,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct States {
    pub dhs: Option<Vec<u8>>,
    pub dhr: Option<Vec<u8>>,
    pub rk: [u8; 32],
    pub cks: Option<[u8; 32]>,
    pub ckr: Option<[u8; 32]>,
    pub ns: u16,
    pub nr: u16,
    pub pn: u16,
    pub mk_skipped: HashMap<(Vec<u8>, u16), [u8; 32]>,
}

impl States {

    pub fn serialize(&self) -> Result<Vec<u8>, StatesError> {
        let json_string = serde_json::to_vec(self)
            .expect("It should be a json string");
        Ok(json_string)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<States, StatesError> {
        let state = serde_json::from_slice(bytes)
            .expect("It should be a state object");
        Ok(state)
    }
}

impl fmt::Debug for States {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("States")
            .field("dhs", &"<redacted>")
            .field("dhr", &self.dhr)
            .field("rk", &self.rk)
            .field("cks", &self.cks)
            .field("ckr", &self.ckr)
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("mk_skipped", &self.mk_skipped)
            .finish()
    }
}

#[test]
fn test_serialization_deserialization() {
    let state = States::default();

    let serialized = state.serialize().unwrap();
    let deserialized = States::deserialize(&serialized).unwrap();
    assert_eq!(state, deserialized);
}