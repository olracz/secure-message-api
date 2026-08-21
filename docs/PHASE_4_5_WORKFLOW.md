# Phase 4 & 5 Workflow Reference
### X3DH Handshake + Double Ratchet — Secure-Message-API

Reference document for building the session orchestrator. 
> Read this before starting Phase 6 session orchestration, or any time 
 you need to remember how X3DH feeds into the Double Ratchet.

---

## 1. High-Level Flow

```
┌─────────────┐                                              ┌─────────────┐
│   ALICE     │                                              │    BOB      │
│ (initiator) │                                              │ (responder) │
└──────┬──────┘                                              └──────┬──────┘
       │                                                            │
       │  PHASE 4 — X3DH (one-time, per new conversation)           │
       │                                                            │
       │  x3dh_sender() ──────► (secret_list, eph_public_key)       │
       │  derive_x3dh_master_secret(secret_list) ──► master_secret  │
       │  [eph_public_key sent to Bob, out of band / via server]    │
       │ ───────────────────────────────────────────────────────►   │
       │                                                            │
       │                             x3dh_receiver() ──► secret_list│
       │                derive_x3dh_master_secret() ─► master_secret|
       │                                                            │
       │        ✓ Both sides now hold the SAME master_secret        |
       │                                                            │
       │  PHASE 5 — Double Ratchet (ongoing, entire conversation)   │
       │                                                            │
       │  RatchetState.ratchet_state_alice(master_secret, ...)      │
       │        RatchetState.ratchet_state_bob(master_secret, ...)  |
       │                                                            │
       │  ratchet_encrypt() ──► envelope                            │
       │ ───────────────────────────────────────────────────────►   │
       │                                   ratchet_decrypt(envelope)│
       │                                   ──► plaintext            │
       │                                                            │
       │                             ratchet_encrypt() ──► envelope │
       │   ◄─────────────────────────────────────────────────────── │
       │  ratchet_decrypt(envelope) ──► plaintext                   │
       │                                                            │
       │        (repeats for the entire conversation)               │
```

---

## 2. Phase 4 — X3DH Handshake

**File:** `crypto/ecc/key_exchange.py` (primitives), `crypto/ecc/handshake.py` (orchestration)

**Purpose:** Establish one shared `master_secret` between two parties who may
not both be online at the same time (asynchronous key agreement).

### 2.1 Function Reference

```
perform_ecdh(my_private_key, peer_public_key) -> bytes
    Single raw ECDH computation. No HKDF. Reused 3-4 times per handshake.

derive_x3dh_master_secret(secret_list: list[bytes]) -> bytes
    Concatenates 3-4 raw ECDH outputs, runs HKDF-SHA256 once.
    Salt is FIXED (b"\x00" * 32) -- NOT random. Both sides must derive
    the same salt independently, which is impossible with random salt.
    Called by BOTH sender and receiver, on their own independently
    computed secret_list -- this is the ONE place HKDF happens for X3DH.

verify_spk_signature(identity_public_key, spk_public_pem, signature) -> bool
    REQUIRED security step. Verifies the peer's SPK was actually signed
    by their identity key, before trusting it in any DH computation.
    Must run BEFORE x3dh_sender()/x3dh_receiver() -- skipping this makes
    X3DH vulnerable to key-substitution attacks.

x3dh_sender(my_identity_private_key, peer_identity_public_key,
            peer_spk_public_key, peer_otk_public_key=None)
    -> (secret_list: list[bytes], eph_public_key)

    Generates a FRESH ephemeral key pair (one-shot, discarded after this
    call). Computes DH1-DH4 (DH4 only if peer_otk_public_key given).
    Returns the raw secret list AND the ephemeral public key -- the
    latter MUST be transmitted to the peer, or they cannot compute a
    matching secret at all.

x3dh_receiver(my_spk_private_key, my_identity_private_key,
              peer_identity_public_key, peer_ephemeral_public_key,
              my_otk_private_key=None)
    -> secret_list: list[bytes]

    Mirror of x3dh_sender(). Does NOT generate a new key -- uses
    already-existing SPK/identity/OTK keys against the sender's
    ephemeral public key. DH1/DH2 have private/public roles SWAPPED
    relative to the sender's version -- this is what makes the two
    sides' math agree.
```

### 2.2 DH Computation Table

| # | Sender uses (private) | Sender uses (peer public) | Receiver uses (private) | Receiver uses (peer public) |
|---|---|---|---|---|
| DH1 | my identity | peer's SPK | my SPK | peer's identity |
| DH2 | my ephemeral | peer's identity | my identity | peer's ephemeral |
| DH3 | my ephemeral | peer's SPK | my SPK | peer's ephemeral |
| DH4 (optional) | my ephemeral | peer's OTK | my OTK | peer's ephemeral |

**Rule:** DH*n* on the sender's side and DH*n* on the receiver's side must
always produce the same value. Verify this holds for any new code touching
this table — it's the single most important invariant in Phase 4.

### 2.3 Key Lifetimes in This Phase

|      Key      |                Lifetime                    |                      Notes                               |
|---------------|--------------------------------------------|----------------------------------------------------------|
| Identity key  |                Permanent                   | Never regenerate — silently breaks all future handshakes |
|      SPK      |             Rotates on timer               | Reused for DH1/DH3 across many handshakes until rotated  |
|      OTK      |          Single use, hard-deleted          |         DH4 only, one handshake, then gone forever       |
| Ephemeral key | One handshake, discarded immediately after |           Never reused, not even by the ratchet          |  

### 2.4 Orchestrator Checklist for This Phase
- [ ] Fetch peer's pre-key bundle (identity pub, SPK pub + signature, optional OTK pub)
- [ ] Call `verify_spk_signature()` — **abort if it returns False**
- [ ] Call `x3dh_sender()` (if initiating) or `x3dh_receiver()` (if responding)
- [ ] Call `derive_x3dh_master_secret()` on the resulting `secret_list`
- [ ] If sender: transmit `eph_public_key` to the peer as part of the first message envelope
- [ ] If an OTK was consumed: mark it deleted (Phase 2's `consume_otk()`)
- [ ] Pass `master_secret` directly into Phase 5's ratchet init — **do not** use it as an AES key directly

---

## 3. Phase 5 — Double Ratchet

**File:** `crypto/ecc/ratchet.py`

**Purpose:** Continuously rotate encryption keys for the lifetime of a
conversation, providing forward secrecy (per-message) and break-in
recovery / post-compromise security (per DH ratchet step).

### 3.1 RatchetState Fields

```
root_key                       32 bytes. Ties every DH step back to master_secret.
sending_chain_key              Advances via kdf_chain_key() on every SEND.
receiving_chain_key            Advances via kdf_chain_key() on every RECEIVE.
my_ratchet_private_key         Current DH key pair (private half).
my_ratchet_public_key          Current DH key pair (public half). Sent in every
                                outgoing envelope header.
their_ratchet_public_key       Peer's last-known ratchet public key. Comparison
                                point for detecting a direction flip.
skipped_message_keys           {(sender_pem, message_number): message_key}
                                Cache for out-of-order delivery.
sending_message_number         messages sent on CURRENT sending chain.
receiving_message_number       messages received on CURRENT receiving chain.
previous_sending_chain_length  total messages sent on PREVIOUS sending
                                chain, captured right before it's replaced.
```

### 3.2 Function Reference

```
kdf_chain_key(chain_key: bytes) -> (message_key: bytes, next_chain_key: bytes)
    Symmetric ratchet step. HMAC-SHA256 twice, same key, different
    labels. Runs on EVERY message, sent or received. One-way — a
    leaked chain key cannot recover past chain keys.

kdf_root_key(root_key: bytes, fresh_dh_output: bytes)
    -> (new_root_key: bytes, new_chain_key: bytes)

    DH ratchet step. One HKDF call, 64-byte output split in half.
    root_key is HKDF salt (ties the step to conversation history).
    Runs ONLY on a direction flip — never on every message.

RatchetState.ratchet_state_alice(master_secret, bob_spk_public_key)
    Initiator's init. Generates a BRAND-NEW key pair (not the X3DH
    ephemeral key). Performs ONE immediate DH step (against bob_spk_
    public_key) so Alice has a sending_chain_key before sending
    message 1. receiving_chain_key starts None.

RatchetState.ratchet_state_bob(master_secret, bob_spk_private_key,
                                bob_spk_public_key)
    Responder's init. NO DH step. root_key = master_secret directly.
    Existing SPK key pair doubles as the initial ratchet key pair.
    their_ratchet_public_key starts None (Alice's key doesn't exist
    anywhere yet at this point).

ratchet_encrypt(self, plaintext: str) -> dict (envelope)
    Advances sending_chain_key by one step, encrypts via AES-GCM.
    NEVER triggers a DH step -- only ratchet_decrypt() does. Returns
    an envelope: {ratchet_public_key (PEM), previous_chain_key_length,
    message_number, ciphertext, nonce}.

ratchet_decrypt(self, envelope: dict) -> str
    1. Check skip cache first (try_skipped_message_keys) — return
       immediately if found.
    2. Compare envelope's ratchet key to their_ratchet_public_key.
       - SAME key: skip_message_keys() for any same-chain gap, then
         normal kdf_chain_key() step.
       - NEW key (direction flip):
         a. skip_message_keys() on the OLD chain's total count
            (envelope["previous_chain_key_length"]) — BEFORE updating
            their_ratchet_public_key.
         b. Update their_ratchet_public_key. DH + kdf_root_key ->
            new receiving_chain_key. Reset receiving_message_number=0.
         c. skip_message_keys() on THIS message's own number
            (envelope["message_number"]) within the new chain.
         d. kdf_chain_key() for this message's actual key.
         e. Generate a NEW key pair. DH + kdf_root_key -> new
            sending_chain_key (using the NEW key pair).
         f. previous_sending_chain_length = sending_message_number
            (save the OLD count), THEN sending_message_number = 0.
    3. receiving_message_number += 1 (in BOTH branches — the skip
       loop stops one short of the current message; this accounts
       for the message actually being decrypted right now).
    4. Decrypt and return.

skip_message_keys(self, until: int)
    Raises ValueError if the gap exceeds MAX_SKIP (100). Otherwise
    advances receiving_chain_key/receiving_message_number forward to
    `until`, STORING each intermediate key in skipped_message_keys
    instead of discarding it.

try_skipped_message_keys(self, envelope: dict) -> str | None
    Looks up (envelope["ratchet_public_key"], envelope["message_number"])
    in skipped_message_keys. If found: pop it (one-time use), decrypt,
    return plaintext. If not found: return None.
```

### 3.3 The Two-Half DH Reaction (critical detail)

When `ratchet_decrypt()` detects a new key, it does **two separate DH
computations** — easy to collapse into one by mistake:

```
Half 1 ("catch up" — decrypt what just arrived):
    perform_ecdh(MY EXISTING key, THEIR new key) -> kdf_root_key
    -> receiving_chain_key -> kdf_chain_key -> decrypts THIS message

Half 2 ("get ready" — prep to reply, before a reply is even sent):
    generate_key_pair() -> NEW key pair
    perform_ecdh(MY NEW key, THEIR new key) -> kdf_root_key
    -> sending_chain_key (NOT consumed by kdf_chain_key() here —
       that only happens later, inside ratchet_encrypt())
```

### 3.4 Trigger Condition Summary

| Event | Symmetric step (kdf_chain_key) | DH step (kdf_root_key) |
|---|---|---|
| Sending, same chain as last time | ✓ every message | never |
| Receiving, same key as stored `their_ratchet_public_key` | ✓ every message | never |
| Receiving, DIFFERENT key than stored | ✓ (after DH step) | ✓ once, two computations |

### 3.5 Orchestrator Checklist for This Phase
- [ ] After Phase 4 completes, call `ratchet_state_alice()` or `ratchet_state_bob()` — never both, never manually
- [ ] For every outgoing message: call `ratchet_encrypt()` only — never call `kdf_chain_key`/`kdf_root_key` directly
- [ ] For every incoming message: call `ratchet_decrypt()` only — same rule
- [ ] Persist the `RatchetState` object (or its fields) between messages — it is NOT stateless like Phase 4
- [ ] Never log, print, or transmit `my_ratchet_private_key`, `root_key`, `sending_chain_key`, or `receiving_chain_key`
- [ ] `skipped_message_keys` should be periodically pruned or capped in a long-lived production system (entries for messages that never arrive will accumulate)

---

## 4. Common Mistakes (from actual bugs hit building this)

| Symptom | Real cause |
|---|---|
| Master secret / chain key silently doesn't match between Alice and Bob | Random (not fixed) salt in an HKDF call |
| Function returns a valid-looking but wrong value, no crash | Hardcoded/literal return instead of the computed variable |
| `AttributeError: 'HMAC'/'HKDF' object has no attribute ...` | Forgot to call `.derive()` / `.digest()` — returned the un-executed machine object |
| Two calls to the same function unpack results in different order | `kdf_chain_key()`/`kdf_root_key()` called from two places (encrypt vs decrypt) with inconsistent tuple order |
| `cryptography.exceptions.InvalidTag` several calls deep | Wrong key reached AES-GCM — almost always an unpacking-order or stale-reference bug upstream |
| Decrypts fine in isolation, fails once a DH step happens | `previous_sending_chain_length` / `sending_message_number` never reset after a DH step |
| `AttributeError` on a field that "should" exist | Typo'd `self.` attribute name — silently creates a new, unused attribute instead of erroring |

---

## 5. One-Sentence Mental Model

**Phase 4 (X3DH):** four independent Diffie-Hellman computations get
concatenated and hashed once, producing a single shared secret — entirely
stateless, run once per new conversation.

**Phase 5 (Ratchet):** that one secret becomes the root of a continuously
mutating state machine — a cheap step (`kdf_chain_key`) runs every message,
an expensive step (`kdf_root_key`) runs only when the conversation's
direction flips, and `skip_message_keys`/`try_skipped_message_keys` handle
the reality that messages don't always arrive in the order they were sent.
