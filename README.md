# 🔐 EncryptiChat: Hybrid Messaging Security API
A high-integrity backend service built with Python and Flask, focusing on authenticated encryption and secure key exchange.

## 🚀 Project Status: [BETA] Symmetric Core Operational
The project has successfully implemented the **Symmetric Encryption** engine. It is currently capable of encrypting and decrypting data using industry-standard authenticated ciphers via a RESTful API.

### ✅ Completed & Functional
* **AES-256-GCM Core:** Implemented high-performance authenticated encryption.
* **Flask API Layer:** Endpoints for `/encrypt` and `/decrypt` are functional and tested via Postman.
* **Modular Design:** Clear separation between cryptographic primitives and API routing.
* **Unit Testing:** Pytest suite integrated to verify encryption/decryption cycles.

### 🛠 In Development (Roadmap)
* **ECC Handshake (P-256):** Transitioning from static keys to dynamic **ECDH** key exchange.
* **HKDF Integration:** Implementing HMAC-based Key Derivation to securely bridge ECC secrets with AES keys.
* **Public Key Infrastructure:** Developing a local database schema to manage user public keys.

---

## 🏗 Cryptographic Details

### Authenticated Encryption (AES-GCM)
I chose **AES-GCM (Galois/Counter Mode)** because it provides **AEAD** (Authenticated Encryption with Associated Data). Unlike older modes (CBC/ECB), GCM ensures:
* **Confidentiality:** The message is encrypted.
* **Authenticity:** A 16-byte tag ensures the data hasn't been tampered with in transit.

### File Structure
```text
├── api/             # Flask routes and request handling
├── crypto/          
│   ├── aesgcm/      # AES-256-GCM core implementation
│   ├── ecc          # ECC logic
│   └── utils/       # Encoding (Base64) and Randomness (os.urandom)
├── tests/           # Automated test suite
└── keys/            # Local storage for key material
