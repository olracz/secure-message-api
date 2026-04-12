🛡️ Secure-Message-API (E2EE)
A Python-based, End-to-End Encrypted (E2EE) messaging framework utilizing Elliptic Curve Cryptography (ECC) and Authenticated Encryption (AES-GCM).

🚀 Current Status: Phase 1 Complete
I have successfully implemented the Persistent Identity Layer. The system can now generate, store, and manage long-term cryptographic "passports" for clients.

Key Milestones:
Identity Management: Completed initial_client_identity logic.

Automatic generation of P-256 ECC key pairs.

Secure persistence of Private Keys via .pem files.

Cryptographic Primitives:

ECDH: For shared secret agreement.

ECDSA: For identity verification and message signing.

HKDF: For deriving high-entropy AES keys.

AES-GCM: For authenticated encryption of message payloads.

🏗️ Technical Architecture
1. Identity & Authentication (The Signal Model)
Instead of traditional real-time challenge-response, this system is transitioning toward an Asynchronous Handshake using:

Identity Keys: Permanent P-256 keys stored on the client.

Pre-Signed Keys: The client signs a temporary key and uploads it to the server. This allows peers to establish an E2EE session even when the recipient is offline.

2. End-to-End Encryption (E2EE)
Zero-Knowledge Server: The backend acts purely as a relay. It never sees raw message content or the derived session keys.

Forward Secrecy: Every session utilizes ephemeral keys, ensuring that even if an identity key is compromised in the future, past conversations remain secure.

📂 Project Structure
crypto/crypto_service.py: The high-level orchestrator (Service Layer).

crypto/ecc/: Core logic for key_exchange, signatures, and generate_keys.

crypto/aesgcm/: Implementation of encrypt and decrypt workers.

🛠️ Next Steps
Implement Pre-Signed Key Logic: Allow clients to upload signed bundles to the server.

Session Orchestration: Finalize the CryptoService functions to handle peer key retrieval.

Flask API Integration: Build the endpoints to relay encrypted "envelopes" between clients.
