# 🛡️ Secure-Message-API (E2EE)
A Python-based End-to-End Encrypted (E2EE) messaging framework utilizing Elliptic Curve Cryptography (ECC) and AES-GCM authenticated encryption.

---

# 🚀 Current Status: Phase 2 — Pre-Key Layer Implemented

The project now implements the pre-key management layer on top of the identity layer, moving toward full asynchronous session establishment.

---

## ✅ Implemented Features

### 🔑 Persistent Identity Management
- Automatic generation of long-term ECC P-256 identity key pairs
- Persistent `.pem` key storage
- Automatic loading of existing identity keys
- Overwrite guard — prevents silent replacement of long-term identity keys
- Returns key objects immediately on creation for direct use
- Separation of:
  - key generation
  - serialization
  - storage
  - orchestration logic

### 🔏 Pre-Key Management
- **Signed Pre-Key (SPK)**
  - ECC key pair generation per pre-key
  - ECDSA signing of SPK public key using identity private key
  - Persistent PEM storage with key ID (`spk_<id>_private.pem` / `spk_<id>_public.pem`)
  - Loading of SPK by ID
- **One-Time Pre-Keys (OTK)**
  - Batch generation with sequential IDs and configurable `start_id` for pool replenishment
  - Persistent PEM storage per key (`otk_<id>_private.pem` / `otk_<id>_public.pem`)
  - Directory scanning for available OTK discovery
  - Hard deletion after use — enforces forward secrecy at the filesystem level

### 🔐 Cryptographic Primitives
- ECC (P-256)
- ECDSA signatures
- ECDH shared secret derivation
- HKDF key derivation
- AES-GCM authenticated encryption

### 🧪 Testing
- Identity key generation tests
- Key persistence tests
- Existing key loading tests
- AES-GCM encryption/decryption tests
- Tampered ciphertext detection tests
- Pre-key tests *(in progress)*

---

# 🏗️ Current Architecture

## Crypto Service Layer
`crypto/crypto_service.py`
- High-level orchestration layer
- Manages identity initialization and future protocol workflows

## ECC Module Structure
`crypto/ecc/`

- `identity_keys.py`
- `pre_keys.py`
- `serialization.py`
- `signatures.py`
- `key_generation.py`
- `handshake.py`
- `key_exchange.py`
- `storage.py`

## AES-GCM Module
`crypto/aesgcm/`
- Encryption worker
- Decryption worker

---

# 🔐 Protocol Direction

This project is being designed toward an asynchronous E2EE architecture inspired by the Signal Protocol, including the Double Ratchet Algorithm for forward secrecy and break-in recovery.

Planned protocol components include:
- ✅ Identity Keys
- ✅ Signed Pre Keys (SPK)
- ✅ One-Time Pre Keys (OTK)
- X3DH (Extended Triple Diffie-Hellman) key agreement
- Double Ratchet Algorithm
  - Diffie-Hellman ratchet (forward secrecy)
  - Symmetric-key ratchet (break-in recovery)
- Asynchronous session establishment
- Encrypted message envelope relay

---

# 📌 Current Development Focus

## In Progress
- Pre-key test coverage
- Pre-key bundle orchestration via `crypto_service.py`

## Planned
- X3DH initial key agreement
- Double Ratchet session management
- Client-to-client encrypted handshake
- Flask API integration
- Encrypted envelope relay system

---

# 🧠 Security Goals
- Zero-knowledge server architecture
- End-to-end encrypted communication
- Forward secrecy via Double Ratchet Algorithm
- Break-in recovery through symmetric-key ratchet
- Persistent client identity verification
- Overwrite-safe long-term identity management

---

# 🛠️ Tech Stack
- Python
- cryptography
- pytest
- Flask (planned)
