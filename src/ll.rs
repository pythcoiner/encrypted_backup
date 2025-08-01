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
use rand::{TryRngCore, rngs::OsRng};

const DECRYPTION_SECRET: &str = "BIPXXXX_DECRYPTION_SECRET";
const INDIVIDUAL_SECRET: &str = "BIPXXXX_INDIVIDUAL_SECRET";
const MAGIC: &str = "BIPXXXX";
const VERSION: u8 = 0x00;
const AESGCM256: u8 = 0x01;

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
    IndividualSecretsEmpty,
    CypherTextEmpty,
    CypherTextLength,
    Content,
    Encryption,
    OffsetOverflow,
}

pub fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

pub fn nonce() -> [u8; 12] {
    let mut rng = OsRng;
    let mut nonce = [0u8; 12];
    rng.try_fill_bytes(&mut nonce)
        .expect("os rng must not fail");
    nonce
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

pub fn inner_encrypt(
    secret: sha256::Hash,
    mut data: Vec<u8>,
) -> Result<([u8; 12], Vec<u8>), Error> {
    let nonce = nonce();

    let key = Key::<Aes256Gcm>::from_slice(secret.as_byte_array());
    let cipher = Aes256Gcm::new(key);

    let mut plaintext = vec![];
    plaintext.append(&mut data);

    cipher
        .encrypt(&Nonce::from(nonce), plaintext.as_slice())
        .map(|c| (nonce, c))
        .map_err(|_| Error::Encrypt)
}

/// Encode following this format:
/// <LENGTH><DERIVATION_PATH_1><DERIVATION_PATH_2><..><DERIVATION_PATH_N>
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

/// Encode following this format:
/// <LENGTH><INDIVIDUAL_SECRET_1><INDIVIDUAL_SECRET_2><..><INDIVIDUAL_SECRET_N>
pub fn encode_individual_secrets(individual_secrets: Vec<[u8; 32]>) -> Result<Vec<u8>, Error> {
    if individual_secrets.is_empty() {
        return Err(Error::IndividualSecretsEmpty);
    }
    let len = individual_secrets.len() as u8;
    let mut out = Vec::with_capacity(1 + (individual_secrets.len() * 32));
    out.push(len);
    for is in individual_secrets {
        out.append(&mut is.to_vec());
    }
    Ok(out)
}

/// Encode following this format:
/// <TYPE><NONCE><LENGTH><CYPHERTEXT>
pub fn encode_encrypted_payload(nonce: [u8; 12], cyphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if cyphertext.is_empty() {
        return Err(Error::CypherTextEmpty);
    }
    let mut out = Vec::new();
    out.append(&mut nonce.as_slice().to_vec());
    let len = bitcoin::VarInt(cyphertext.len() as u64);
    out.append(&mut bitcoin::consensus::serialize(&len));
    out.append(&mut cyphertext.to_vec());

    Ok(out)
}

/// Encode following this format
/// <MAGIC><VERSION><DERIVATION_PATHS><INDIVIDUAL_SECRETS><CONTENT><ENCRYPTION><ENCRYPTED_PAYLOAD>
pub fn encode(
    version: u8,
    mut derivation_paths: Vec<u8>,
    mut individual_secrets: Vec<u8>,
    content: u8,
    encryption: u8,
    mut encrypted_payload: Vec<u8>,
) -> Vec<u8> {
    // <MAGIC>
    let mut out = MAGIC.as_bytes().to_vec();
    // <VERSION>
    out.push(version);
    // <DERIVATION_PATHS>
    out.append(&mut derivation_paths);
    // <INDIVIDUAL_SECRETS>
    out.append(&mut individual_secrets);
    // <CONTENT>
    out.push(content);
    // <ENCRYPTION>
    out.push(encryption);
    // <ENCRYPTED_PAYLOAD>
    out.append(&mut encrypted_payload);
    out
}

pub fn check_offset(offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() <= offset {
        Err(Error::Corrupted)
    } else {
        Ok(())
    }
}

pub fn check_offset_lookahead(offset: usize, bytes: &[u8], lookahead: usize) -> Result<(), Error> {
    if bytes.len() <= offset + lookahead {
        Err(Error::Corrupted)
    } else {
        Ok(())
    }
}

pub fn init_offset(bytes: &[u8], value: usize) -> Result<usize, Error> {
    check_offset(value, bytes)?;
    Ok(value)
}

pub fn increment_offset(bytes: &[u8], offset: usize, incr: usize) -> Result<usize, Error> {
    check_offset(offset, bytes)?;
    offset.checked_add(incr).ok_or(Error::OffsetOverflow)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><..>
pub fn decode_version(bytes: &[u8]) -> Result<u8, Error> {
    // <MAGIC>
    let offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (_, version) = parse_version(&bytes[offset..])?;
    Ok(version)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><DERIVATION_PATHS><..>
pub fn decode_derivation_paths(bytes: &[u8]) -> Result<Vec<DerivationPath>, Error> {
    // <MAGIC>
    let mut offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (incr, _) = parse_version(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <DERIVATION_PATHS>
    let (_, derivation_paths) = parse_derivation_paths(&bytes[offset..])?;
    Ok(derivation_paths)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><DERIVATION_PATHS><INDIVIDUAL_SECRETS><CONTENT><ENCRYPTION><ENCRYPTED_PAYLOAD><..>
#[allow(clippy::type_complexity)]
pub fn decode_v1(
    bytes: Vec<u8>,
) -> Result<
    (
        Vec<[u8; 32]>, /* individual_secrets */
        u8,            /* content */
        u8,            /* encryption_type */
        [u8; 12],      /* nonce */
        Vec<u8>,       /* cyphertext */
    ),
    Error,
> {
    // <MAGIC>
    let mut offset = init_offset(&bytes, parse_magic_byte(&bytes)?)?;
    // <VERSION>
    let (incr, _) = parse_version(&bytes[offset..])?;
    offset = increment_offset(&bytes, offset, incr)?;
    // <DERIVATION_PATHS>
    let (incr, _) = parse_derivation_paths(&bytes[offset..])?;
    offset = increment_offset(&bytes, offset, incr)?;
    // <INDIVIDUAL_SECRETS>
    let (incr, individual_secrets) = parse_individual_secrets(&bytes[offset..])?;
    offset = increment_offset(&bytes, offset, incr)?;
    // <CONTENT>
    let (incr, content) = parse_content(&bytes[offset..])?;
    offset = increment_offset(&bytes, offset, incr)?;
    // <ENCRYPTION>
    let (incr, encryption_type) = parse_encryption(&bytes[offset..])?;
    offset = increment_offset(&bytes, offset, incr)?;
    // <ENCRYPTED_PAYLOAD>
    let (nonce, cyphertext) = parse_encrypted_payload(&bytes[offset..])?;

    Ok((
        individual_secrets,
        content,
        encryption_type,
        nonce,
        cyphertext,
    ))
}

pub fn encrypt_aes_gcm_256(
    derivation_paths: Vec<DerivationPath>,
    content: u8,
    keys: Vec<secp256k1::PublicKey>,
    data: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    if keys.len() > u8::MAX as usize || keys.is_empty() {
        return Err(Error::KeyCount);
    }
    if derivation_paths.len() > u8::MAX as usize {
        return Err(Error::DerivPathCount);
    }
    // FIXME: should we stick a u32::MAX as 32bits systems usize is 32 bits?
    if data.len() > u64::MAX as usize {
        // TODO: check the max data length in aes-gcm
        return Err(Error::DataLength);
    }

    let mut raw_keys = keys.into_iter().map(|k| k.serialize()).collect::<Vec<_>>();
    raw_keys.sort();

    let secret = decryption_secret(&raw_keys);
    let individual_secrets =
        encode_individual_secrets(individual_secrets(&secret, raw_keys.as_slice()))?;
    let derivation_paths = encode_derivation_paths(derivation_paths)?;

    let (nonce, cyphertext) = inner_encrypt(secret, data)?;
    let encrypted_payload = encode_encrypted_payload(nonce, cyphertext.as_slice())?;

    Ok(encode(
        VERSION,
        derivation_paths,
        individual_secrets,
        content,
        AESGCM256,
        encrypted_payload,
    ))
}

pub fn try_decrypt_aes_gcm_256(
    cyphertext: &[u8],
    secret: &[u8; 32],
    nonce: [u8; 12],
) -> Option<Vec<u8>> {
    let nonce = Nonce::from(nonce);

    let key = Key::<Aes256Gcm>::from_slice(secret);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(&nonce, cyphertext).ok()
}

pub fn decrypt_aes_gcm_256(
    key: secp256k1::PublicKey,
    individual_secrets: Vec<[u8; 32]>,
    cyphertext: Vec<u8>,
    nonce: [u8; 12],
) -> Result<Vec<u8>, Error> {
    let raw_key = key.serialize();

    let mut engine = sha256::HashEngine::default();
    engine.input(INDIVIDUAL_SECRET.as_bytes());
    engine.input(&raw_key);
    let si = sha256::Hash::from_engine(engine);

    for ci in individual_secrets {
        let secret = xor(si.as_byte_array(), &ci);
        if let Some(out) = try_decrypt_aes_gcm_256(&cyphertext, &secret, nonce) {
            return Ok(out);
        }
    }

    Err(Error::WrongKey)
}

pub fn parse_magic_byte(bytes: &[u8]) -> Result<usize /* offset */, Error> {
    let magic = MAGIC.as_bytes();

    if bytes.len() < magic.len() || &bytes[..magic.len()] != magic {
        return Err(Error::Magic);
    }
    Ok(magic.len())
}

pub fn parse_version(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Version);
    }
    let version = bytes[0];
    if version != VERSION {
        return Err(Error::Version);
    }
    Ok((1, version))
}

pub fn parse_content(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Content);
    }
    let content = bytes[0];
    Ok((1, content))
}

pub fn parse_encryption(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Content);
    }
    let encryption = bytes[0];
    Ok((1, encryption))
}

/// Expects to parse a payload of the form:
/// <COUNT>
/// <CHILD_COUNT><CHILD><..><CHILD>
/// <..>
/// <CHILD_COUNT><CHILD><..><CHILD>
/// <..>
pub fn parse_derivation_paths(
    bytes: &[u8],
) -> Result<(usize /* offset */, Vec<DerivationPath>), Error> {
    let mut offset = init_offset(bytes, 0).map_err(|_| Error::DerivPathEmpty)?;
    let mut derivation_paths = HashSet::new();

    // <COUNT>
    let count = bytes[0];
    offset = increment_offset(bytes, offset, 1)?;

    if count != 0 {
        for _ in 0..count {
            check_offset(offset, bytes)?;
            // <CHILD_COUNT>
            let child_count = bytes[offset];
            if child_count == 0 {
                return Err(Error::DerivPathEmpty);
            } else {
                let mut childs = vec![];
                offset += 1;
                for _ in 0..child_count {
                    check_offset_lookahead(offset, bytes, 4)?;
                    // <CHILD>
                    let raw_child: [u8; 4] =
                        bytes[offset..(offset + 4)].try_into().expect("verified");
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

/// Expects to parse a payload of the form:
/// <COUNT>
/// <INDIVIDUAL_SECRET>
/// <..>
/// <INDIVIDUAL_SECRET>
/// <..>
pub fn parse_individual_secrets(
    bytes: &[u8],
) -> Result<(usize /* offset */, Vec<[u8; 32]>), Error> {
    let mut offset = init_offset(bytes, 0).map_err(|_| Error::IndividualSecretsEmpty)?;
    // <COUNT>
    let count = bytes[offset];
    offset = increment_offset(bytes, offset, 1)?;
    if count < 1 {
        return Err(Error::IndividualSecretsEmpty);
    }

    let mut individual_secrets = Vec::new();
    for _ in 0..count {
        check_offset_lookahead(offset, bytes, 32)?;
        // <INDIVIDUAL_SECRET>
        let secret: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| Error::Corrupted)?;
        individual_secrets.push(secret);
        offset += 32;
    }
    Ok((offset, individual_secrets))
}

/// Expects to parse a payload of the form:
/// <NONCE><LENGTH><CYPHERTEXT>
/// <..>
pub fn parse_encrypted_payload(
    bytes: &[u8],
) -> Result<([u8; 12] /* nonce */, Vec<u8> /* cyphertext */), Error> {
    let mut offset = init_offset(bytes, 0)?;
    // <NONCE>
    check_offset_lookahead(offset, bytes, 12)?;
    let nonce: [u8; 12] = bytes[offset..offset + 12].try_into().expect("chacked");
    offset = increment_offset(bytes, offset, 12)?;
    // <LENGTH>
    let data_len_size = bytes[offset] as usize;
    offset = increment_offset(bytes, offset, 1)?;
    check_offset_lookahead(offset, bytes, data_len_size)?;
    let data_len = bitcoin::consensus::deserialize(&bytes[offset..offset + data_len_size])
        .map_err(|_| Error::VarInt)?;
    let data_len = match data_len {
        bitcoin::VarInt(n) => n as usize,
    };
    offset = increment_offset(bytes, offset, data_len_size)?;
    // <CYPHERTEXT>
    check_offset_lookahead(offset, bytes, data_len)?;
    let cyphertext = bytes[offset..offset + data_len].to_vec();
    Ok((nonce, cyphertext))
}

#[cfg(test)]
mod tests {
    // use bitcoin::hex::DisplayHex;
    //
    // use super::*;
    // use std::str::FromStr;
    //
    // #[test]
    // fn test_basic_encrypt_decrypt() {
    //     let pk1 = secp256k1::PublicKey::from_str(
    //         "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
    //     )
    //     .unwrap();
    //     let pk2 = secp256k1::PublicKey::from_str(
    //         "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07",
    //     )
    //     .unwrap();
    //     let pk3 = secp256k1::PublicKey::from_str(
    //         "0384526253c27c7aef56c7b71a5cd25bebb000000a437826defc5b2568bde81f07",
    //     )
    //     .unwrap();
    //     let keys = vec![pk2, pk1];
    //     let data = "test".as_bytes().to_vec();
    //     let encrypted = encrypt(keys, data, vec![]).unwrap();
    //
    //     println!("{:?}", encrypted.as_hex());
    //
    //     let (_, deriv_paths) = parse_derivation_paths(&encrypted).unwrap();
    //     assert!(deriv_paths.is_empty());
    //
    //     let decrypted_1 = decrypt(pk1, encrypted.clone()).unwrap();
    //     assert_eq!(String::from_utf8(decrypted_1).unwrap(), "test".to_string());
    //     let decrypted_2 = decrypt(pk2, encrypted.clone()).unwrap();
    //     assert_eq!(String::from_utf8(decrypted_2).unwrap(), "test".to_string());
    //     let decrypt_3 = decrypt(pk3, encrypted);
    //     assert!(decrypt_3.is_err());
    // }
    //
    // #[test]
    // fn test_decrypt_wrong_secret() {
    //     let mut engine = sha256::HashEngine::default();
    //     engine.input("secret".as_bytes());
    //     let secret = sha256::Hash::from_engine(engine);
    //
    //     let mut engine = sha256::HashEngine::default();
    //     engine.input("wrong_secret".as_bytes());
    //     let wrong_secret = sha256::Hash::from_engine(engine);
    //
    //     let payload = "payload".as_bytes().to_vec();
    //     let ciphertext = inner_encrypt(secret, payload).unwrap();
    //     // decrypting with secret success
    //     let _ = try_decrypt(&ciphertext, secret.as_byte_array()).unwrap();
    //     // decrypting with wrong secret fails
    //     let fails = try_decrypt(&ciphertext, wrong_secret.as_byte_array());
    //     assert!(fails.is_none());
    // }
    //
    // #[test]
    // fn test_decrypt_corrupted_ciphertext_fails() {
    //     let mut engine = sha256::HashEngine::default();
    //     engine.input("secret".as_bytes());
    //     let secret = sha256::Hash::from_engine(engine);
    //
    //     let payload = "payload".as_bytes().to_vec();
    //     let mut ciphertext = inner_encrypt(secret, payload).unwrap();
    //     // decrypting with secret success
    //     let _ = try_decrypt(&ciphertext, secret.as_byte_array()).unwrap();
    //
    //     // corrupting the ciphertext
    //     let offset = ciphertext.len() - 10;
    //     for i in offset..offset + 5 {
    //         *ciphertext.get_mut(i).unwrap() = 0;
    //     }
    //
    //     // decryption must then fails
    //     let fails = try_decrypt(&ciphertext, secret.as_byte_array());
    //     assert!(fails.is_none());
    // }
}
