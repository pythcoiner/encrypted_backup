---
BIP: ?  
Layer: Applications  
Title: Bitcoin Encrypted Backup  
Author: // TBD  
Comments-Summary: No comments yet.  
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-????  
Status: Draft  
Type: Standards Track  
Created: 2025-08-22  
License: BSD-2-Clause  
---

## Introduction

### Abstract

This BIP specifies a compact, deterministic encryption scheme for wallet descriptors (BIP-380) and wallet policies (BIP-388) that contain **only public keys**.  The encrypted output—called a *Bitcoin Encrypted Backup* (BEB)—lets users outsource long-term storage to untrusted media or cloud services without revealing which addresses, scripts, or cosigners are involved.  Encryption keys are derived from the lexicographically-sorted public keys inside the descriptor itself, so any party who already holds one of those keys can later decrypt the backup without extra secrets or round-trips.  The format uses AES-GCM-256 with a 96-bit random nonce and a 128-bit authentication tag to provide confidentiality and integrity.  A single binary blob contains a magic header, version byte, optional derivation-path hints, per-key individual secrets, and the authenticated ciphertext.  While designed for descriptors, the same scheme can encrypt any arbitrary data that must remain private yet deterministically reconstructible by key holders.  The goal is to eliminate the single-point-of-failure that arises when the descriptor, not the seed, is lost.  Backups created with this specification are vendor-neutral, human-verifiable, and future-extensible through a one-byte version field.

### Copyright

This BIP is licensed under the BSD 2-Clause License.  
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the above copyright notice and this permission notice appear in all copies.

### Motivation

In practice, losing the **wallet descriptor** (or **wallet policy**) is often **as catastrophic as losing the wallet’s seed** itself.  While the seed grants the ability to sign, the descriptor grants a map to the coins.  In multisig or miniscript contexts, keys alone are **not sufficient** for recovery: without the original descriptor the wallet cannot reconstruct the script.

Offline storage of descriptors has two practical obstacles:

1. **Descriptors are hard to store offline.**  
   The JSON-serialized text can be far longer than a 12/24-word seed phrase.  Paper, steel, and other long-term analog media quickly become impractical for such lengths or error-prone to transcribe.

2. **Online redundancy carries risk.**  
   Keeping backups on USB thumb-drives, computers, phones, or (worst) cloud drives avoids the first problem but amplifies surveillance risk: anyone who gains these **plaintext descriptors** learns the wallet’s public keys, script structure, etc...  Even with encryption at the cloud provider, an attacker or a subpoena can compel access, and each extra copy multiplies the attack surface.

These constraints lead to an acute need for an **encrypted, deterministic**, and ideally compact backup format that:

* can be **safely stored in multiple places**, including untrusted on-line services,  
* can be **decrypt only by intended holders** of specified public keys,  
* and keeps both **keys and plaintext** hidden from any party who lacks the necessary key(s).

In bitcoin signing, the **seed** as it is what protects the key material that allows spending funds.  Unauthorized access to the seed implies that attackers gain ownership of the funds (or at least the specific access controls that the keys are protecting).  Hence, it is very valuable for an attacker to gain access to seed, and they will be willing to increase the cost and the sophistication of the attacks, because of the potential of high returns.

Therefore, for seeds:

* **digital copies are a high risk**: hardware signing devices have been built to keep the seeds in a secure enclave, separate from the machine the software wallet is running on.  
* **redundant copies of the seed are a high risk**: the seed has to be physically protected, and multiple copies in multiple places inherently make protection harder.

**Descriptors** and *xpubs* are only private: unauthorized access allows an attacker, to spy on your funds.  That is bad, but not nearly as valuable as taking your funds.  Attackers might use this to get information about you, and to inform further attacks, but will lose interest once attempting an attack becomes too costly or sophisticated.

For **descriptors**:

* **digital copies are unavoidable**: each parties using the account will necessarily have a digital copy in their software wallet.  
* additional **redundant copies pose only a moderate risk**.

Therefore, having multiple copies of the descriptor, whether physical, digital, on your disk or on the cloud, is a valid mean to reduce the risk of loss of funds, unlike replicating the seed, which would incur a much higher risk.

### Expected properties

* **Encrypted**: this allows users to outsource its storage to untrusted parties, for example, cloud providers, specialized services, etc..  
* **Has access control**: decrypting it should only be available to the desired parties (typically, a subset of the cosigners).  
* **Easy to implement**: it should not require any sophisticated tools.  
* **Vendor-independent**: it should be easy to implement using any hardware signing device.  
* **Deterministic**: the result of the backup is the same for the same payload. Not crucial, but a nice-to-have.

### Scope

This specification applies to encrypting **wallet descriptors** (BIP-0380) or **wallet policies** (BIP-0388) that contain only **public keys** and any other relevant bitcoin "wallet" metadata.  It is NOT intended for descriptors containing private keys, or private keys.  The encrypted format is intended for long-term backup storage, not for interactive processes.

## Specification

### Security considerations

Deterministic encryption, by definition, cannot satisfy the standard [semantic security](https://en.wikipedia.org/wiki/Semantic_security) property commonly used in cryptography; however, in our context, it is safe to assume that the adversary does not have access to plaintexts, and no other plaintext will be encrypted with the same secrets.

### Secret generation

* Let `p1`, `p2`, .., `pn` be the public keys in the descriptor/wallet policy, in increasing lexicographical order.  
* let `secret` = sha256("BEB_DECRYPTION_SECRET" ‖ `p1` ‖ `p2` ‖ ... ‖ `pn`)  
* let `si` = sha256("BEB_INDIVIDUAL_SECRET" ‖ `pi`)  
* let `individual_secret_i` = `secret` ⊕ `si`

### AES-GCM Encryption

* let `nonce` = random()  
* let `cyphertext` = aes_gcm_256_encrypt(`payload`, `secret`, `nonce`)

### AES-GCM Decryption

In order to decrypt the payload of a backup, the owner of a certain public key p computes:

* let `si` = sha256("BEB_INDIVIDUAL_SECRET" ‖ `p`)  
* for each `individual_secret_i` generate `reconstructed_secret_i` = `individual_secret_i` ⊕ `si`  
* for each `reconstructed_secret_i` process `payload` = aes_gcm_256_decrypt(`cyphertext`, `secret`, `nonce`)

Decryption will succeed if and only if **p** was one of the keys in the descriptor/wallet policy.

### Encoding

The encrypted backup must be encoded as follows:

`MAGIC` `VERSION` `DERIVATION_PATHS` `INDIVIDUAL_SECRETS` `CONTENT` `ENCRYPTION` `ENCRYPTED_PAYLOAD`

#### Magic

`MAGIC`: 7 bytes which are ASCII/UTF-8 representation of **BEB** (`0x42, 0x45, 0x42`).

#### Version

`VERSION`: 1 byte unsigned integer representing the format version. The current specification defines version `0x01`.

#### Derivation Paths

> Note: the derivation-path vector should not contain duplicates.  
> Derivation paths are optional; they can be useful to simplify the recovery process if one has used a non-common derivation path to derive his key.

`DERIVATION_PATH` follows this format:

- `COUNT`  
- `CHILD_COUNT` `CHILD`...`CHILD`
- `CHILD_COUNT` `CHILD`...`CHILD`

* `COUNT`: 1-byte unsigned integer (0–255) indicating how many derivation paths are included.
* `CHILD_COUNT`: 1-byte unsigned integer (1–255) indicating how many children are in the current path.
* `CHILD`: 4-byte big-endian unsigned integer representing a child index per BIP-32.

#### Individual Secrets

At least one individual secret must be supplied.

The `INDIVIDUAL_SECRETS` section follows this format:

- `COUNT`  
- `INDIVIDUAL_SECRET` `INDIVIDUAL_SECRET`

* `COUNT`: 1-byte unsigned integer (1–255) indicating how many secrets are included.  
* `INDIVIDUAL_SECRET`: 32-byte serialization of the derived individual secret.

#### Content

`CONTENT`: 1-byte unsigned integer identifying what has been encrypted.

| Value  | Definition                             |
|:-------|:---------------------------------------|
| 0x00   | Undefined                              |
| 0x01   | BIP-0380 Descriptor (string)           |
| 0x02   | BIP-0388 Wallet policy (string)        |
| 0x03   | BIP-0329 Labels (JSONL)                |
| 0x04   | Wallet backup (JSON)                   |

#### Encrypted Payload

`ENCRYPTED_PAYLOAD` follows this format:

- `TYPE` `NONCE` `LENGTH` `CYPHERTEXT`

* `TYPE`: 1-byte unsigned integer identifying the encryption algorithm.  

| Value  | Definition                             |
|:-------|:---------------------------------------|
| 0x00   | Undefined                              |
| 0x01   | BIP-0380 Descriptor (string)           |

* `NONCE`: 12-byte nonce for AES-GCM-256.  
* `LENGTH`: [compact size](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer) integer representing ciphertext length.  
* `CYPHERTEXT`: variable-length ciphertext.

## Rationale

The deterministic encryption approach is chosen so that every participant can re-derive the exact same encrypted blob from a given descriptor without extra round-trips or access to a signing device.  
AES-GCM-256 supplies authenticated encryption with 128-bit authentication tags, sufficient against offline ciphertext-only attackers.  
Public-key-derived secrets avoid an extra key-negotiation step while still binding decryption rights to the original wallet keys.

### Future Extensions

The version field enables possible future enhancements:

- Additional encryption algorithms  
- Support for threshold-based decryption

### Implementation

See rust [implementation](TBD)

### Test Vectors

See rust implementation [tests](TBD)

## Acknowledgements

// TBD
