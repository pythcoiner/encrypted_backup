use miniscript::{ForEachKey, bitcoin::secp256k1};
use std::collections::{BTreeSet, HashSet};

use miniscript::{
    Descriptor, DescriptorPublicKey,
    bitcoin::{self, bip32::DerivationPath},
};

use crate::Error;

fn dpk_to_pk(key: &DescriptorPublicKey) -> bitcoin::secp256k1::PublicKey {
    match key {
        DescriptorPublicKey::Single(key) => match key.key {
            miniscript::descriptor::SinglePubKey::FullKey(pk) => pk.inner,
            miniscript::descriptor::SinglePubKey::XOnly(pk) => {
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

pub fn descr_to_dpks(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<Vec<DescriptorPublicKey>, Error> {
    let mut keys = BTreeSet::new();
    descriptor.for_each_key(|k| {
        keys.insert(k.clone());
        true
    });
    let keys: Vec<_> = keys.into_iter().collect();

    if keys.is_empty() {
        Err(Error::DescriptorHasNoKeys)
    } else {
        Ok(keys)
    }
}

pub fn dpks_to_derivation_keys_paths(
    dpks: &Vec<DescriptorPublicKey>,
) -> (Vec<secp256k1::PublicKey>, Vec<DerivationPath>) {
    let mut derivation_paths = HashSet::new();
    let mut keys = HashSet::new();
    for k in dpks {
        keys.insert(dpk_to_pk(k));
        if let Some(path) = dpk_to_deriv_path(k) {
            derivation_paths.insert(path);
        }
    }
    let deriv = derivation_paths.into_iter().collect();
    let keys = keys.into_iter().collect();
    (keys, deriv)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::str::FromStr;

    use miniscript::{Descriptor, DescriptorPublicKey};

    pub fn descr_1() -> Descriptor<DescriptorPublicKey> {
        let descr_str = "wsh(or_d(pk([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*),and_v(v:pkh([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*),older(52596))))#pggrcdd0";

        Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap()
    }

    fn dpk_1() -> DescriptorPublicKey {
        let dpk_str = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*";
        DescriptorPublicKey::from_str(dpk_str).unwrap()
    }

    fn dpk_2() -> DescriptorPublicKey {
        let dpk_str = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*";
        DescriptorPublicKey::from_str(dpk_str).unwrap()
    }

    fn dpk_3() -> DescriptorPublicKey {
        let dpk_str = "tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*";
        DescriptorPublicKey::from_str(dpk_str).unwrap()
    }
    pub fn pk() -> secp256k1::PublicKey {
        let raw = [
            3, 235, 210, 82, 202, 8, 119, 170, 224, 155, 157, 5, 130, 25, 104, 39, 117, 170, 60,
            188, 208, 73, 193, 47, 7, 131, 47, 44, 246, 163, 181, 23, 8,
        ];
        secp256k1::PublicKey::from_slice(&raw).unwrap()
    }

    #[test]
    fn test_dpk_to_pk() {
        let expected = pk();
        let pk = dpk_to_pk(&dpk_1());
        assert_eq!(pk, expected);
        let pk = dpk_to_pk(&dpk_2());
        assert_eq!(pk, expected);
    }

    #[test]
    fn test_dpk_to_deriv() {
        let deriv_1 = dpk_to_deriv_path(&dpk_1()).unwrap();
        assert_eq!(deriv_1, DerivationPath::from_str("48'/1'/0'/2'").unwrap());
        let deriv_2 = dpk_to_deriv_path(&dpk_2()).unwrap();
        assert_eq!(deriv_2, DerivationPath::from_str("48'/1'/0'/2'").unwrap());
        let deriv_3 = dpk_to_deriv_path(&dpk_3());
        assert!(deriv_3.is_none());
    }

    #[test]
    fn test_descript_to_dpk() {
        let dpks = descr_to_dpks(&descr_1()).unwrap();
        let expected = vec![dpk_1(), dpk_2()];
        assert_eq!(dpks, expected);
    }

    #[test]
    fn test_dpks_to_deriv_paths() {
        let dpks = vec![dpk_1(), dpk_2()];
        let pks = vec![pk()];
        let deriv = vec![DerivationPath::from_str("48'/1'/0'/2'").unwrap()];
        let res = dpks_to_derivation_keys_paths(&dpks);
        assert_eq!(res, (pks, deriv));
    }
}
