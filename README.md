# 🔐 EncryptiChat: Hybrid Messaging Security API
A high-integrity backend service built with Python and Flask, focusing on authenticated encryption and secure key exchange.

## 🚀 Project Status: [BETA] Symmetric Core Operational
The project has successfully implemented the **Symmetric Encryption** engine. It is currently capable of encrypting and decrypting data using industry-standard authenticated ciphers via a RESTful API.

### ✅ Completed & Functional
* **AES-256-GCM Core:** Implemented high-performance authenticated encryption.
* **Flask API Layer:** Endpoints for `/encrypt` and `/decrypt` are functional and tested via Postman.
* **Modular Design:** Clear separation between cryptographic primitives and API routing.
* **Unit Testing:** Pytest suite integrated to verify core cryptographic cycles and key loading.
* **Modern Identity Foundation**: Migrated from RSA to ECC (NIST P-256) for faster, more secure identity management.

### 🛠 In Development (Roadmap)
* **ECC Handshake Protocol:** Implementing a Challenge-Response mechanism in handshake.py to verify user identity before key exchange.
* **Dynamic Key Exchange (ECDH):** Replacing static AES keys with secrets derived dynamically per session
* **Mutual Authentication:** Ensuring the Flask API signs responses so clients can verify the server's identity.
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
