# Secure-Message-API Dev Checklist

## Phase 1 — Identity Layer
- [x] key_generation.py — ECC P-256 key pair generation
- [x] serialization.py — PEM conversion (pem_to_key, key_to_pem)
- [x] storage.py — file read/write with auto directory creation
- [x] identity_keys.py — create, store, load, overwrite guard
- [x] test_identity_keys.py — full test coverage
- [x] test_encryption.py — AES-GCM encrypt/decrypt tests

## Phase 2 — Pre-Key Layer
- [x] pre_keys.py — SPK generation, signing, storage, loading
- [x] pre_keys.py — OTK batch generation, storage, loading, hard delete
- [x] test_pre_keys.py — full SPK and OTK test coverage

## Phase 3 — Service Orchestration
- [x] crypto_service.py — initialize_identity()
- [x] crypto_service.py — initialize_pre_keys()
- [x] crypto_service.py — get_available_otks()
- [x] crypto_service.py — consume_otk(otk_id)
- [x] crypto_service.py — replenish_otks()
- [x] test_crypto_service.py — update with new function tests

## Phase 4 — X3DH Handshake
- [ ] key_exchange.py — perform_ecdh()
- [ ] key_exchange.py — derive_x3dh_master_secret()
- [ ] handshake.py — verify_spk_signature()
- [ ] handshake.py — x3dh_sender()
- [ ] handshake.py — x3dh_receiver()
- [ ] test_key_exchange.py
- [ ] test_handshake.py

## Phase 5 — Double Ratchet
- [ ] ratchet.py — ratchet state initialization from master secret
- [ ] ratchet.py — symmetric key ratchet (per message)
- [ ] ratchet.py — DH ratchet (per round trip)
- [ ] ratchet.py — encrypt message with ratchet
- [ ] ratchet.py — decrypt message with ratchet
- [ ] test_ratchet.py

## Phase 6 — Flask API
- [ ] server — pre-key bundle upload endpoint
- [ ] server — pre-key bundle fetch endpoint
- [ ] server — encrypted message relay endpoint
- [ ] server — OTK replenishment endpoint
- [ ] test_api.py

## Phase 7 — Polish
- [ ] Remove utils/key_loader.py (obsolete RSA loader) ← do this now
- [ ] Update README after each phase
- [ ] Review zero-knowledge server architecture
- [ ] Security audit of full protocol flow