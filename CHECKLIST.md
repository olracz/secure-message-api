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
- [x] crypto_service.py — sign_authentication_proof()
- [x] crypto_service.py — verify_authentication_proof()
- [x] test_crypto_service.py — full test coverage

## Phase 4 — X3DH Handshake
- [x] key_exchange.py — perform_ecdh()
- [x] key_exchange.py — derive_x3dh_master_secret()
- [x] handshake.py — verify_spk_signature()
- [x] handshake.py — x3dh_sender()
- [x] handshake.py — x3dh_receiver()
- [x] test_handshake.py
- [x] test_key_exchange.py

## Phase 5 — Double Ratchet
- [x] ratchet.py — kdf_chain_key()
- [x] ratchet.py — kdf_root_key()
- [x] ratchet.py — RatchetState class
- [x] ratchet.py — ratchet_encrypt()
- [x] ratchet.py — ratchet_decrypt()
- [x] ratchet.py — skip_message_keys() with MAX_SKIP guard
- [x] ratchet.py — try_skipped_message_keys()
- [x] test_ratchet.py — full coverage including out-of-order and DH boundary tests
- [x] session_manager.py — start_conversation_as_initiator()
- [x] session_manager.py — start_conversation_as_receiver()
- [x] test_session_manager.py — full coverage including round trip tests

## AES-GCM Validation Layer
- [x] exceptions.py — custom exception hierarchy
- [x] validators.py — validate_key, validate_plaintext, validate_ciphertext_and_nonce
- [x] aesgcm_encrypt.py — validation wired in
- [x] aesgcm_decrypt.py — validation and DecryptionError wired in
- [x] test_aesgcm.py — full validation and tamper detection coverage

## Utils Refactor
- [x] base64_utils.py — generate_nonce() added, standard base64
- [x] __init__.py — cleaned up exports
- [x] randomness.py — removed (consolidated into base64_utils.py)
- [x] key_loader.py — removed (obsolete RSA loader)

## Phase 6 — Flask API
- [ ] server setup — Flask app factory
- [ ] POST /register — upload pre-key bundle
- [ ] POST /auth — challenge-response authentication
- [ ] GET /bundle/<user_id> — fetch peer pre-key bundle
- [ ] POST /messages — relay encrypted message envelope
- [ ] POST /otk/replenish — upload new OTK batch
- [ ] test_api.py — full endpoint coverage

## Phase 7 — Polish
- [ ] Update README after each phase
- [ ] RatchetState persistence layer
- [ ] Security audit of full protocol flow
- [ ] Zero-knowledge server architecture review