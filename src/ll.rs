use std::collections::HashSet;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use miniscript::bitcoin::{
    self,
    bip32::{ChildNumber, DerivationPath},
    hashes::{Hash, HashEngine, sha256},
    secp256k1,
};

const DECRYPTION_SECRET: &str = "BIPXXXX_DECRYPTION_SECRET";
const INDIVIDUAL_SECRET: &str = "BIPXXXX_INDIVIDUAL_SECRET";
const MAGIC: &str = "BIPXXXX";
const NONCE: &str = "BIPXXXX_NONCE";
const VERSION: u8 = 0;

#[derive(Debug)]
pub enum Error {
    KeyCount,
    DerivPathCount,
    DerivPathLength,
    DerivPathEmpty,
    DataLength,
    Encrypt,
    Decrypt,
    Corrupted,
    Version,
    Magic,
    VarInt,
    WrongKey,
}

pub fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn nonce(secret: &[u8; 32]) -> [u8; 12] {
    let mut engine = sha256::HashEngine::default();
    engine.input(NONCE.as_bytes());
    engine.input(secret);
    sha256::Hash::from_engine(engine).as_byte_array()[..12]
        .try_into()
        .expect("has 12 bytes")
}

pub fn decryption_secret(keys: &[[u8; 33]]) -> sha256::Hash {
    let mut engine = sha256::HashEngine::default();
    engine.input(DECRYPTION_SECRET.as_bytes());
    keys.iter().for_each(|k| engine.input(k));
    sha256::Hash::from_engine(engine)
}

pub fn individual_secret(secret: &sha256::Hash, key: &[u8; 33]) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(INDIVIDUAL_SECRET.as_bytes());
    engine.input(key);
    let si = sha256::Hash::from_engine(engine);
    xor(secret.as_byte_array(), si.as_byte_array())
}

pub fn individual_secrets(secret: &sha256::Hash, keys: &[[u8; 33]]) -> Vec<[u8; 32]> {
    keys.iter()
        .map(|k| individual_secret(secret, k))
        .collect::<Vec<_>>()
}

pub fn inner_encrypt(secret: sha256::Hash, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let nonce = Nonce::from(nonce(secret.as_byte_array()));

    let key = Key::<Aes256Gcm>::from_slice(secret.as_byte_array());
    let cipher = Aes256Gcm::new(key);

    let mut plaintext = vec![];
    plaintext.append(&mut data);

    cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| Error::Encrypt)
}

pub fn encode_derivation_paths(derivation_paths: Vec<DerivationPath>) -> Result<Vec<u8>, Error> {
    let mut encoded_paths = vec![derivation_paths.len() as u8];
    for path in derivation_paths {
        let childs = path.to_u32_vec();
        let len = childs.len();
        if len > u8::MAX as usize {
            return Err(Error::DerivPathLength);
        }
        encoded_paths.push(len as u8);
        for c in childs {
            encoded_paths.append(&mut c.to_le_bytes().to_vec());
        }
    }
    Ok(encoded_paths)
}

pub fn encode(
    mut encrypted_data: Vec<u8>,
    individual_secrets: Vec<[u8; 32]>,
    mut derivation_paths: Vec<u8>,
) -> Vec<u8> {
    let mut magic = MAGIC.as_bytes().to_vec();
    let version = VERSION;
    let keys_len = individual_secrets.len() as u8;
    let data_len = bitcoin::VarInt(encrypted_data.len() as u64);

    let mut out = Vec::new();
    out.append(&mut magic);
    out.push(version);
    out.append(&mut derivation_paths);
    out.push(keys_len);
    for is in individual_secrets {
        out.append(&mut is.to_vec());
    }
    out.push(data_len.size() as u8);
    out.append(&mut bitcoin::consensus::serialize(&data_len));
    out.append(&mut encrypted_data);
    out
}

pub fn decode(
    encrypted_data: Vec<u8>,
) -> Result<
    (
        Vec<[u8; 32]>, /* individual secrets */
        Vec<u8>,       /* encrypted data */
    ),
    Error,
> {
    let (mut offset, _) = extract_paths(&encrypted_data)?;

    // Get number of keys
    if offset >= encrypted_data.len() {
        return Err(Error::Corrupted);
    }
    let keys_len = encrypted_data[offset];
    offset += 1;

    // Extract individual secrets
    let mut individual_secrets = Vec::new();
    for _ in 0..keys_len {
        if offset + 32 > encrypted_data.len() {
            return Err(Error::Corrupted);
        }
        let secret: [u8; 32] = encrypted_data[offset..offset + 32]
            .try_into()
            .map_err(|_| Error::Corrupted)?;
        individual_secrets.push(secret);
        offset += 32;
    }

    // Get data length size
    if offset >= encrypted_data.len() {
        return Err(Error::Corrupted);
    }
    let data_len_size = encrypted_data[offset] as usize;
    offset += 1;

    // Decode VarInt for data length
    if offset + data_len_size > encrypted_data.len() {
        return Err(Error::Corrupted);
    }
    let data_len = bitcoin::consensus::deserialize(&encrypted_data[offset..offset + data_len_size])
        .map_err(|_| Error::VarInt)?;
    let data_len = match data_len {
        bitcoin::VarInt(n) => n as usize,
    };
    offset += data_len_size;

    // Extract encrypted data
    if offset + data_len > encrypted_data.len() {
        return Err(Error::Corrupted);
    }
    let data = encrypted_data[offset..offset + data_len].to_vec();

    Ok((individual_secrets, data))
}

pub fn encrypt(
    keys: Vec<secp256k1::PublicKey>,
    data: Vec<u8>,
    derivation_paths: Vec<DerivationPath>,
) -> Result<Vec<u8>, Error> {
    if keys.len() > u8::MAX as usize || keys.is_empty() {
        return Err(Error::KeyCount);
    }
    if derivation_paths.len() > u8::MAX as usize {
        return Err(Error::DerivPathCount);
    }
    if data.len() > u64::MAX as usize {
        // TODO: check the max data length in aes-gcm
        return Err(Error::DataLength);
    }

    let mut raw_keys = keys.into_iter().map(|k| k.serialize()).collect::<Vec<_>>();
    raw_keys.sort();

    let secret = decryption_secret(&raw_keys);
    let individual_secrets = individual_secrets(&secret, raw_keys.as_slice());
    let derivation_paths = encode_derivation_paths(derivation_paths)?;

    let encrypted_data = inner_encrypt(secret, data)?;

    Ok(encode(encrypted_data, individual_secrets, derivation_paths))
}

pub fn try_decrypt(encrypted_data: &Vec<u8>, secret: &[u8; 32]) -> Option<Vec<u8>> {
    let nonce = Nonce::from(nonce(secret));

    let key = Key::<Aes256Gcm>::from_slice(secret);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(&nonce, encrypted_data.as_slice()).ok()
}

pub fn inner_decrypt(
    key: secp256k1::PublicKey,
    individual_secrets: Vec<[u8; 32]>,
    encrypted_data: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let raw_key = key.serialize();

    let mut engine = sha256::HashEngine::default();
    engine.input(INDIVIDUAL_SECRET.as_bytes());
    engine.input(&raw_key);
    let si = sha256::Hash::from_engine(engine);

    for ci in individual_secrets {
        let secret = xor(si.as_byte_array(), &ci);
        if let Some(out) = try_decrypt(&encrypted_data, &secret) {
            return Ok(out);
        }
    }

    Err(Error::WrongKey)
}

pub fn decrypt(key: secp256k1::PublicKey, encrypted_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let (individual_secrets, encrypted_data) = match decode(encrypted_data) {
        Ok(r) => r,
        Err(e) => {
            println!("fail to decode: {e:?}");
            return Err(e);
        }
    };
    inner_decrypt(key, individual_secrets, encrypted_data)
}

pub fn extract_paths(
    encrypted_data: &[u8],
) -> Result<(usize /* offset */, Vec<DerivationPath>), Error> {
    let magic = MAGIC.as_bytes();
    let mut offset = 0;

    // Check magic bytes
    if encrypted_data.len() < magic.len() || &encrypted_data[0..magic.len()] != magic {
        return Err(Error::Magic);
    }
    offset += magic.len();

    // Check version
    if offset >= encrypted_data.len() {
        return Err(Error::Corrupted);
    }
    let version = encrypted_data[offset];
    if version > VERSION {
        return Err(Error::Version);
    }
    offset += 1;

    // Get derivation paths
    let mut derivation_paths = HashSet::new();
    if offset >= encrypted_data.len() {
        return Err(Error::Corrupted);
    }
    let deriv_path_count = encrypted_data[offset];
    offset += 1;
    if deriv_path_count != 0 {
        for _ in 0..deriv_path_count {
            if offset >= encrypted_data.len() {
                return Err(Error::Corrupted);
            }
            let deriv_path_len = encrypted_data[offset];
            if deriv_path_len == 0 {
                return Err(Error::DerivPathEmpty);
            } else {
                let mut childs = vec![];
                offset += 1;
                for _ in 0..deriv_path_len {
                    if (offset + 4) >= encrypted_data.len() {
                        return Err(Error::Corrupted);
                    }
                    let raw_child: [u8; 4] = encrypted_data[offset..(offset + 4)]
                        .try_into()
                        .expect("verified");
                    let child = u32::from_le_bytes(raw_child);
                    let child = ChildNumber::from(child);
                    childs.push(child);
                    offset += 4;
                }
                derivation_paths.insert(DerivationPath::from(childs));
            }
        }
    }

    let derivation_paths = derivation_paths.into_iter().collect();

    Ok((offset, derivation_paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_basic_encrypt_decrypt() {
        let pk1 = secp256k1::PublicKey::from_str(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap();
        let pk2 = secp256k1::PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07",
        )
        .unwrap();
        let pk3 = secp256k1::PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb000000a437826defc5b2568bde81f07",
        )
        .unwrap();
        let keys = vec![pk2, pk1];
        let data = "test".as_bytes().to_vec();
        let encrypted = encrypt(keys, data, vec![]).unwrap();

        let (_, deriv_paths) = extract_paths(&encrypted).unwrap();
        assert!(deriv_paths.is_empty());

        let decrypted_1 = decrypt(pk1, encrypted.clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted_1).unwrap(), "test".to_string());
        let decrypted_2 = decrypt(pk2, encrypted.clone()).unwrap();
        assert_eq!(String::from_utf8(decrypted_2).unwrap(), "test".to_string());
        let decrypt_3 = decrypt(pk3, encrypted);
        assert!(decrypt_3.is_err());
    }

    #[test]
    fn test_decrypt_wrong_secret() {
        let mut engine = sha256::HashEngine::default();
        engine.input("secret".as_bytes());
        let secret = sha256::Hash::from_engine(engine);

        let mut engine = sha256::HashEngine::default();
        engine.input("wrong_secret".as_bytes());
        let wrong_secret = sha256::Hash::from_engine(engine);

        let payload = "payload".as_bytes().to_vec();
        let ciphertext = inner_encrypt(secret, payload).unwrap();
        // decrypting with secret success
        let _ = try_decrypt(&ciphertext, secret.as_byte_array()).unwrap();
        // decrypting with wrong secret fails
        let fails = try_decrypt(&ciphertext, wrong_secret.as_byte_array());
        assert!(fails.is_none());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let mut engine = sha256::HashEngine::default();
        engine.input("secret".as_bytes());
        let secret = sha256::Hash::from_engine(engine);

        let payload = "payload".as_bytes().to_vec();
        let mut ciphertext = inner_encrypt(secret, payload).unwrap();
        // decrypting with secret success
        let _ = try_decrypt(&ciphertext, secret.as_byte_array()).unwrap();

        // corrupting the ciphertext
        let offset = ciphertext.len() - 10;
        for i in offset..offset + 5 {
            *ciphertext.get_mut(i).unwrap() = 0;
        }

        // decryption must then fails
        let fails = try_decrypt(&ciphertext, secret.as_byte_array());
        assert!(fails.is_none());
    }
}
