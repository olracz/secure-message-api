# 🛡️ Secure-Message-API (E2EE)

A Python-based End-to-End Encrypted (E2EE) messaging framework utilizing Elliptic Curve Cryptography (ECC) and AES-GCM authenticated encryption.

---

# 🚀 Current Status: Phase 1 — Identity Layer Implemented

The project currently implements the foundational cryptographic identity layer required for asynchronous secure messaging systems.

## ✅ Implemented Features

### 🔑 Persistent Identity Management
- Automatic generation of long-term ECC P-256 identity key pairs
- Persistent `.pem` key storage
- Automatic loading of existing identity keys
- Separation of:
  - key generation
  - serialization
  - storage
  - orchestration logic

### 🔐 Cryptographic Primitives
- ECC (P-256)
- ECDSA signatures
- ECDH shared secret derivation
- HKDF key derivation
- AES-GCM authenticated encryption

### 🧪 Testing
- Identity key generation tests
- Key persistence tests
- Existing key loading tests using `pytest`

---

# 🏗️ Current Architecture

## Crypto Service Layer
`crypto/crypto_service.py`
- High-level orchestration layer
- Manages identity initialization and future protocol workflows

## ECC Module Structure
`crypto/ecc/`

Current modules:
- `identity_keys.py`
- `serialization.py`
- `signatures.py`
- `key_generation.py`

Planned modules:
- `pre_keys.py`
- `storage.py`
- `key_exchange.py`

## AES-GCM Module
`crypto/aesgcm/`
- Encryption worker
- Decryption worker

---

# 🔐 Protocol Direction

This project is being designed toward an asynchronous E2EE architecture inspired by modern secure messaging systems such as Signal.

Planned protocol components include:
- Identity Keys
- Signed Pre Keys (SPK)
- One-Time Pre Keys (OTK)
- Asynchronous session establishment
- Forward secrecy

---

# 📌 Current Development Focus

## In Progress
- Pre-key management architecture
- PEM storage abstraction layer
- Signed Pre-Key generation workflow

## Planned
- Pre-key bundle orchestration
- Session establishment workflow
- Client-to-client encrypted handshake
- Flask API integration
- Encrypted envelope relay system

---

# 🧠 Security Goals

- Zero-knowledge server architecture
- End-to-end encrypted communication
- Forward secrecy through ephemeral session keys
- Persistent client identity verification

---

# 🛠️ Tech Stack

- Python
- cryptography
- pytest
- Flask (planned)
