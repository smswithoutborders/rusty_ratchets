use std::sync::Arc;
use x25519_dalek::StaticSecret;
use crate::functions::FunctionsError;

type Result<T> = std::result::Result<T, HeaderError>;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HeaderError {
    // #[error("Failed to encrypt: {err}")]
    // FailedToEncrypt {
    //     err: String,
    // },
}

#[derive(PartialEq, Debug, uniffi::Record)]
pub struct HEADER {
    dh_pair: Vec<u8>,
    pn: u16,
    n: u16
}

#[uniffi::export]
impl HEADER {
    #[uniffi::constructor]
    pub fn new(
        dh_pair: Vec<u8>,
        pn: u16,
        n: u16,
    ) -> Result<Self>{
        Ok(Self {
            dh_pair,
            pn,
            n
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(self.dh_pair.clone());
        bytes.extend(self.pn.to_le_bytes());
        bytes.extend(self.n.to_le_bytes());

        Ok(bytes)
    }

    #[uniffi::constructor]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let dh_pair = data[0..32].to_vec();
        let pn = u16::from_le_bytes(data[32..34].try_into().expect("2 bytes"));
        let n = u16::from_le_bytes(data[34..36].try_into().expect("2 bytes"));

        Ok(HEADER {
            dh_pair,
            pn,
            n
        })
    }
}