use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use crate::header::HeaderError;
use crate::states::StatesError::FailedToDeserialize;

type Result<T> = std::result::Result<T, StatesError>;

#[derive(Debug, uniffi::Error)]
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
    pub mk_skipped: HashMap<PublicKey, i32>
}


#[derive(Debug, uniffi::Object, Deserialize, Serialize)]
struct DHs {
    public_key: Vec<u8>,
    private_key: Vec<u8>
}

#[derive(Debug, uniffi::Object, Deserialize, Serialize)]
pub struct RustyState {
    dhs: DHs,
    dhr: Option<Vec<u8>>,
    rk: Vec<u8>,
    cks: Option<Vec<u8>>,
    ckr: Option<Vec<u8>>,
    ns: u16,
    nr: u16,
    pn: u16,
    mk_skipped: HashMap<Vec<u8>, i32>
}

impl TryFrom<States> for RustyState {
    type Error = StatesError;

    fn try_from(value: States) -> std::result::Result<Self, Self::Error> {
        let public_key = PublicKey::from(&value.dhs).as_bytes().to_vec();
        let private_key = value.dhs.as_bytes().to_vec();

        let mut mk_skipped: HashMap<Vec<u8>, i32> = HashMap::new();
        for (pk, n) in value.mk_skipped {
            let pk: Vec<u8> = pk.as_bytes().to_vec();
            mk_skipped.insert(pk, n);
        }

        Ok( RustyState {
            dhs: DHs {
                public_key,
                private_key
            },
            dhr: match value.dhr {
                Some(dhr) => Some(dhr.as_bytes().to_vec()),
                None => None
            },
            rk: value.rk.to_vec(),
            cks: match value.cks {
                Some(cks) => Some(cks.to_vec()),
                None => None
            },
            ckr: match value.ckr {
                Some(ckr) => Some(ckr.to_vec()),
                None => None
            },
            ns: value.ns,
            nr: value.nr,
            pn: value.pn,
            mk_skipped
        })
    }
}

impl TryFrom<RustyState> for States {
    type Error = StatesError;
    fn try_from(value: RustyState) -> Result<Self> {
        let pk : [u8; 32] = value.dhs.private_key.try_into().expect("Should be 32 bytes");
        let dhs = StaticSecret::from(pk);

        let mut mk_skipped: HashMap<PublicKey, i32> = HashMap::new();
        for (pk, n) in value.mk_skipped {
            let pk : [u8; 32] = pk.try_into().expect("Should be 32 bytes");
            let pub_key = PublicKey::from(pk);
            mk_skipped.insert(pub_key, n);
        }

        Ok(
            States {
                dhs,
                dhr: match value.dhr {
                    Some(dhr) =>  {
                        let pk: [u8; 32] = dhr.try_into().expect("Should be 32 bytes");
                        Some(PublicKey::from(pk))
                    },
                    None => None
                },
                rk: value.rk.try_into().expect("Should be 32 bytes"),
                cks: match value.cks {
                    Some(cks) => Some(cks.try_into().expect("Should be 32 bytes")),
                    None => None
                },
                ckr: match value.ckr {
                    Some(ckr) => Some(ckr.try_into().expect("Should be 32 bytes")),
                    None => None
                },
                ns: value.ns,
                nr: value.nr,
                pn: value.pn,
                mk_skipped,
            }
        )
    }
}
