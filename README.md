# 🛡️ Secure-Message-API (E2EE)
A Python-based End-to-End Encrypted (E2EE) messaging framework utilizing Elliptic Curve Cryptography (ECC) and AES-GCM authenticated encryption.

---

# 🚀 Current Status: Phase 4 — X3DH Handshake Implemented

The project now implements the full X3DH key agreement protocol, enabling asynchronous session establishment between two parties without requiring both to be online simultaneously.

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

### 🔧 Service Orchestration
- `initialize_identity()` — load or create identity keys on startup
- `initialize_pre_keys()` — generate, sign, and store SPK + OTK batch
- `get_available_otks()` — check remaining OTK pool
- `consume_otk(otk_id)` — hard delete after session use with auto-replenishment
- `replenish_otks()` — manual OTK pool top up
- `sign_authentication_proof()` — ECDSA challenge signing for server authentication
- `verify_authentication_proof()` — signature verification

### 🤝 X3DH Key Agreement
- `perform_ecdh()` — single raw ECDH primitive, reused for all DH1-DH4 operations
- `derive_x3dh_master_secret()` — HKDF-SHA256 over 3-4 combined DH outputs → 32-byte root key
- `x3dh_sender()` — initiator side, generates ephemeral key pair and performs 3-4 DH operations
- `x3dh_receiver()` — responder side, mirrors sender DH operations in reverse using published keys
- `verify_spk_signature()` — validates pre-key bundle authenticity before trusting it

### 🔐 Cryptographic Primitives
- ECC (P-256)
- ECDSA signatures
- ECDH shared secret derivation
- HKDF key derivation
- AES-GCM authenticated encryption

### 🧪 Testing
- Identity key generation, persistence, and loading tests
- AES-GCM encryption/decryption and tamper detection tests
- SPK and OTK generation, storage, loading, and deletion tests
- CryptoService orchestration layer tests
- X3DH key exchange and handshake tests

---

# 🏗️ Current Architecture

## Crypto Service Layer
`crypto/crypto_service.py`
- High-level orchestration layer
- Manages identity initialization, pre-key lifecycle, and authentication

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
- ✅ X3DH key agreement
- Double Ratchet Algorithm
  - Diffie-Hellman ratchet (forward secrecy)
  - Symmetric-key ratchet (break-in recovery)
- Asynchronous session establishment
- Encrypted message envelope relay

---

# 📌 Current Development Focus

## In Progress


## Planned
- Double Ratchet session management (`ratchet.py`)
- Client-to-client encrypted handshake via Flask
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