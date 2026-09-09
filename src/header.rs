use x25519_dalek::PublicKey;

type Result<T> = std::result::Result<T, HeaderError>;

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    // #[error("Failed to encrypt: {err}")]
    // FailedToEncrypt {
    //     err: String,
    // },
}

#[derive(Debug, Clone)]
pub struct HEADER {
    pub dh: PublicKey,
    pub pn: u16,
    pub n: u16
}

impl HEADER {
    pub fn new(
        dh_pair: PublicKey,
        pn: u16,
        n: u16,
    ) -> Result<Self>{
        Ok(Self {
            dh: dh_pair,
            pn,
            n
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(self.dh.to_bytes());
        bytes.extend(self.pn.to_le_bytes());
        bytes.extend(self.n.to_le_bytes());

        Ok(bytes)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let dh_pair: [u8; 32] = data[0..32].try_into().expect("dh_pair should be 32 bytes");
        let pn = u16::from_le_bytes(data[32..34].try_into().expect("2 bytes"));
        let n = u16::from_le_bytes(data[34..36].try_into().expect("2 bytes"));

        Ok(HEADER {
            dh: PublicKey::from(dh_pair),
            pn,
            n
        })
    }
}