use std::collections::HashSet;
use std::str::FromStr;

use miniscript::{
    Descriptor, DescriptorPublicKey, ForEachKey,
    bitcoin::{
        self,
        bip32::{DerivationPath, Xpub},
    },
};

mod ll;

#[derive(Debug)]
pub enum Error {
    Ll(ll::Error),
    Utf8,
    Descriptor,
}

fn dpk_to_pk(key: &DescriptorPublicKey) -> bitcoin::secp256k1::PublicKey {
    match key {
        DescriptorPublicKey::Single(key) => match key.key {
            miniscript::descriptor::SinglePubKey::FullKey(pk) => pk.inner,
            miniscript::descriptor::SinglePubKey::XOnly(pk) => {
                // FIXME: is there any good reason to choose one parity over the other?
                pk.public_key(bitcoin::key::Parity::Even)
            }
        },
        DescriptorPublicKey::XPub(key) => key.xkey.public_key,
        DescriptorPublicKey::MultiXPub(key) => key.xkey.public_key,
    }
}

fn dpk_to_deriv_path(key: &DescriptorPublicKey) -> Option<DerivationPath> {
    match key {
        DescriptorPublicKey::Single(key) => key.origin.clone().map(|(_, p)| p),
        DescriptorPublicKey::XPub(key) => key.origin.clone().map(|(_, p)| p),
        DescriptorPublicKey::MultiXPub(key) => key.origin.clone().map(|(_, p)| p),
    }
}

pub fn encrypt(descriptor: Descriptor<DescriptorPublicKey>) -> Result<Vec<u8>, Error> {
    let payload = descriptor.to_string().as_bytes().to_vec();
    let mut raw_keys = Vec::new();
    let mut derivation_paths = HashSet::new();
    let mut keys = HashSet::new();
    descriptor.for_each_key(|k| {
        raw_keys.push(k.clone());
        true
    });
    for k in raw_keys {
        keys.insert(dpk_to_pk(&k));
        if let Some(path) = dpk_to_deriv_path(&k) {
            derivation_paths.insert(path);
        }
    }

    let keys = keys.into_iter().collect();
    let derivation_paths = derivation_paths.into_iter().collect();
    ll::encrypt(keys, payload, derivation_paths).map_err(Error::Ll)
}

pub fn decrypt(
    key: Xpub,
    encrypted_data: Vec<u8>,
) -> Result<Descriptor<DescriptorPublicKey>, Error> {
    let key = key.public_key;
    let descr_bytes = ll::decrypt(key, encrypted_data).map_err(Error::Ll)?;
    let descr_str = String::from_utf8(descr_bytes).map_err(|_| Error::Utf8)?;
    Descriptor::<DescriptorPublicKey>::from_str(&descr_str).map_err(|_| Error::Descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_descriptor() {
        let descr_str = "wsh(or_d(pk([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*),and_v(v:pkh([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*),older(52596))))#pggrcdd0";

        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let xpub = Xpub::from_str("tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw").unwrap();

        let encrypted_descriptor = encrypt(descriptor).unwrap();

        let (_, deriv_paths) = ll::extract_paths(&encrypted_descriptor).unwrap();

        assert_eq!(
            vec![DerivationPath::from_str("48'/1'/0'/2'").unwrap()],
            deriv_paths
        );

        let decrypted = decrypt(xpub, encrypted_descriptor).unwrap();
        assert_eq!(&decrypted.to_string(), descr_str);
    }

    #[test]
    fn test_encrypt_several_deriv_path() {
        let descr_str = "wsh(or_d(pk([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*),and_v(v:pkh([58b7f8dc/48'/0/0/0]tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*),older(52596))))";

        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let encrypted_descriptor = encrypt(descriptor).unwrap();

        let (_, deriv_paths) = ll::extract_paths(&encrypted_descriptor).unwrap();

        assert_eq!(
            vec![
                DerivationPath::from_str("48'/0/0/0").unwrap(),
                DerivationPath::from_str("48'/1'/0'/2'").unwrap()
            ],
            deriv_paths
        );
    }
}
