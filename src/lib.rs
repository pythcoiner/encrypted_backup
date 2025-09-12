use std::str::FromStr;

use descriptor::descr_to_dpks;

pub use ll::Content;
use miniscript::{
    bitcoin::{bip32::DerivationPath, secp256k1},
    Descriptor, DescriptorPublicKey,
};

#[cfg(all(feature = "miniscript_12_0", feature = "miniscript_12_3_5"))]
compile_error!("A single miniscript version must be selected");

#[cfg(not(any(feature = "miniscript_12_0", feature = "miniscript_12_3_5")))]
compile_error!("A miniscript version must be selected with feature flag");
#[cfg(feature = "tokio")]
pub use tokio;

#[cfg(feature = "miniscript_12_0")]
pub use mscript_12_0 as miniscript;
#[cfg(feature = "miniscript_12_3_5")]
pub use mscript_12_3_5 as miniscript;

use num_enum::{FromPrimitive, IntoPrimitive};

pub mod descriptor;
pub mod ll;
#[cfg(feature = "devices")]
pub mod signing_devices;

pub trait ToPayload {
    fn to_payload(&self) -> Result<Vec<u8>, Error>;
    fn content_type(&self) -> Content;
    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error>;
    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error>;
}

impl ToPayload for Vec<u8> {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        Ok(self.clone())
    }
    fn content_type(&self) -> Content {
        Content::Unknown
    }
    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error> {
        Ok(vec![])
    }
    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        Ok(vec![])
    }
}

impl ToPayload for Descriptor<DescriptorPublicKey> {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        Ok(self.to_string().as_bytes().to_vec())
    }

    fn content_type(&self) -> Content {
        Content::Bip380
    }

    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error> {
        let dpks = descr_to_dpks(self)?;
        let (_, p) = descriptor::dpks_to_derivation_keys_paths(&dpks);
        Ok(p)
    }

    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        let dpks = descr_to_dpks(self)?;
        let (k, _) = descriptor::dpks_to_derivation_keys_paths(&dpks);
        Ok(k)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decrypted {
    Descriptor(Descriptor<DescriptorPublicKey>),
    Policy,
    Labels,
    WalletBackup(Vec<u8>),
    Raw(Vec<u8>),
}

#[derive(Debug)]
pub enum Payload {
    None,
    Encrypt {
        payload: Vec<u8>,
    },
    DecryptV1 {
        cyphertext: Vec<u8>,
        individual_secrets: Vec<[u8; 32]>,
        nonce: [u8; 12],
    },
}

impl Payload {
    pub fn is_none(&self) -> bool {
        matches!(self, Payload::None)
    }
}

#[derive(Debug)]
pub struct EncryptedBackup {
    version: Version,
    content: Content,
    encryption: Encryption,
    derivation_paths: Vec<DerivationPath>,
    keys: Vec<secp256k1::PublicKey>,
    payload: Payload,
}

impl Default for EncryptedBackup {
    fn default() -> Self {
        Self {
            version: Version::max(),
            content: Content::Unknown,
            encryption: Encryption::AesGcm256,
            derivation_paths: vec![],
            keys: vec![],
            payload: Payload::None,
        }
    }
}

impl EncryptedBackup {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn get_derivation_paths(&self) -> Vec<DerivationPath> {
        self.derivation_paths.clone()
    }
    pub fn get_keys(&self) -> Vec<secp256k1::PublicKey> {
        self.keys.clone()
    }
    pub fn get_content(&self) -> Content {
        self.content.clone()
    }
    pub fn set_keys(mut self, keys: Vec<secp256k1::PublicKey>) -> Self {
        self.keys = keys;
        self
    }
    pub fn set_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }
    pub fn set_content_type(mut self, content_type: Content) -> Self {
        self.content = content_type;
        self
    }
    pub fn set_encryption(mut self, encryption: Encryption) -> Self {
        self.encryption = encryption;
        self
    }
    pub fn set_derivation_paths(mut self, derivation_paths: Vec<DerivationPath>) -> Self {
        self.derivation_paths = derivation_paths;
        self
    }
    pub fn set_payload<T: ToPayload>(mut self, payload: &T) -> Result<Self, Error> {
        self.payload = Payload::Encrypt {
            payload: payload.to_payload()?,
        };
        if payload.content_type().is_known() {
            self.content = payload.content_type();
        };
        self.derivation_paths
            .append(&mut payload.derivation_paths()?);
        self.keys.append(&mut payload.keys()?);
        Ok(self)
    }
    pub fn encrypt(self) -> Result<Vec<u8>, Error> {
        if self.content == Content::Unknown {
            return Err(Error::UnknownContent);
        }
        if !self.encryption.is_defined() {
            return Err(Error::EncryptionUndefined);
        }
        if !self.version.is_valid() {
            return Err(Error::InvalidVersion);
        }
        let bytes = if let Payload::Encrypt { payload } = &self.payload {
            payload.clone()
        } else {
            return Err(Error::WrongPayload);
        };

        match (self.encryption, self.version) {
            (Encryption::AesGcm256, Version::V0 | Version::V1) => Ok(ll::encrypt_aes_gcm_256_v1(
                self.derivation_paths,
                self.content.clone(),
                self.keys,
                &bytes,
            )?),
            _ => Err(Error::NotImplemented),
        }
    }
    pub fn set_encrypted_payload(mut self, bytes: &[u8]) -> Result<Self, Error> {
        let version: Version = ll::decode_version(bytes).map(|v| v.into())?;
        match version {
            Version::V0 | Version::V1 => {
                let (derivation_paths, individual_secrets, encryption_type, nonce, cyphertext) =
                    ll::decode_v1(bytes)?;
                self.derivation_paths = derivation_paths;
                self.encryption = encryption_type.into();
                self.payload = Payload::DecryptV1 {
                    cyphertext,
                    individual_secrets,
                    nonce,
                }
            }
            _ => return Err(Error::NotImplemented),
        }
        Ok(self)
    }
    pub fn extract(content: Content, bytes: Vec<u8>) -> Result<Decrypted, Error> {
        match content {
            Content::Unknown => Ok(Decrypted::Raw(bytes)),
            Content::Bip380 => {
                let descr_str = String::from_utf8(bytes).map_err(|_| Error::Utf8)?;
                let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descr_str)
                    .map_err(|_| Error::Descriptor)?;
                Ok(Decrypted::Descriptor(descriptor))
            }
            Content::None
            | Content::BIP(_)
            | Content::Proprietary(_)
            | Content::Bip329
            | Content::Bip388 => Err(Error::NotImplemented),
        }
    }
    pub fn decrypt(&self) -> Result<Decrypted, Error> {
        match self.version {
            Version::V0 | Version::V1 => match &self.payload {
                Payload::None | Payload::Encrypt { .. } => Err(Error::WrongPayload),
                Payload::DecryptV1 {
                    cyphertext,
                    individual_secrets,
                    nonce,
                } => {
                    for key in &self.keys {
                        if let Ok((content, bytes)) = ll::decrypt_aes_gcm_256_v1(
                            *key,
                            &individual_secrets.clone(),
                            cyphertext.clone(),
                            *nonce,
                        ) {
                            return Self::extract(content, bytes);
                        }
                    }
                    Err(Error::WrongKey)
                }
            },
            Version::Unknown => Err(Error::UnknownVersion),
        }
    }
}

#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum Encryption {
    Undefined,
    AesGcm256,
    #[num_enum(default)]
    Unknown = 0xFF,
}

impl Encryption {
    pub fn is_defined(&self) -> bool {
        match self {
            Encryption::Undefined | Encryption::Unknown => false,
            Encryption::AesGcm256 => true,
        }
    }
}

#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum Version {
    V0,
    V1,
    #[num_enum(default)]
    Unknown = 0xFF,
}

impl Version {
    fn max() -> Self {
        Version::V1
    }
    pub fn is_valid(&self) -> bool {
        match self {
            Version::Unknown => false,
            Version::V0 | Version::V1 => true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    Ll(ll::Error),
    Utf8,
    Descriptor,
    NotImplemented,
    UnknownContent,
    EncryptionUndefined,
    InvalidVersion,
    WrongPayload,
    UnknownVersion,
    WrongKey,
    DescriptorHasNoKeys,
    String(Box<String>),
}

impl From<ll::Error> for Error {
    fn from(value: ll::Error) -> Self {
        Error::Ll(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_encrypted_descriptor() {
        let descriptor = descriptor::tests::descr_1();
        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        let bytes = backp.encrypt().unwrap();
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_encryption_to_u8() {
        let mut u: u8 = Encryption::AesGcm256.into();
        assert_eq!(0x01, u);
        u = Encryption::Undefined.into();
        assert_eq!(0x00, u);
        u = Encryption::Unknown.into();
        assert_eq!(0xFF, u);
    }

    #[test]
    fn test_u8_to_encryption() {
        let mut e: Encryption = 0x00u8.into();
        assert_eq!(e, Encryption::Undefined);
        e = 0x01u8.into();
        assert_eq!(e, Encryption::AesGcm256);

        for i in 0x02..0xFFu8 {
            e = i.into();
            assert_eq!(e, Encryption::Unknown);
        }
    }

    #[test]
    fn test_version_to_u8() {
        let mut u: u8 = Version::V0.into();
        assert_eq!(0x00, u);
        u = Version::V0.into();
        assert_eq!(0x00, u);
        u = Version::Unknown.into();
        assert_eq!(0xFF, u);
    }

    #[test]
    fn test_u8_to_version() {
        let mut v: Version = 0x00u8.into();
        assert_eq!(v, Version::V0);
        v = 0x01u8.into();
        assert_eq!(v, Version::V1);

        for i in 0x02..0xFFu8 {
            v = i.into();
            assert_eq!(v, Version::Unknown);
        }
    }
}
