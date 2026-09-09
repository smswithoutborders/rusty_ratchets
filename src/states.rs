use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub enum StatesError {
    FailedToDeserialize,
}

#[derive(Clone)]
pub struct States {
    pub dhs: StaticSecret,
    pub dhr: Option<PublicKey>,
    pub rk: [u8; 32],
    pub cks: Option<[u8; 32]>,
    pub ckr: Option<[u8; 32]>,
    pub ns: u16,
    pub nr: u16,
    pub pn: u16,
    pub mk_skipped: HashMap<(PublicKey, u16), [u8; 32]>,
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