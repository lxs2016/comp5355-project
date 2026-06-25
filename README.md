# E2EE Messaging System — COMP5355

End-to-End Encrypted one-to-one messaging system built for **COMP5355 Cyber and Internet Security (2025/2026)**.

Plaintext exists **only** on sender and recipient devices.  
The relay server handles registration, public-key distribution, and ciphertext routing — it never sees, stores, or derives message content.

---

## Table of Contents

1. [Security Properties](#security-properties)
2. [Threat Model](#threat-model)
3. [Protocol Overview](#protocol-overview)
4. [Cryptographic Primitives](#cryptographic-primitives)
5. [Project Structure](#project-structure)
6. [Installation](#installation)
7. [Full Demo Script](#full-demo-script)
8. [Safety Number — Out-of-Band Key Verification](#safety-number--out-of-band-key-verification)
9. [Security Attack Demonstrations](#security-attack-demonstrations)
10. [Running Tests](#running-tests)

---

## Security Properties

| ID | Property | Implementation |
|----|----------|----------------|
| SR1 | **Confidentiality** — server cannot read messages | XChaCha20-Poly1305 AEAD; key never leaves client |
| SR2 | **Integrity** — tampered ciphertext is rejected | AEAD authentication tag covers ciphertext + AD |
| SR3 | **Authenticity** — messages are bound to sender + session | Associated Data (AD) binds `session_id`, `sender`, `recipient`, `seq` |
| SR4 | **Replay protection** — duplicate/reordered messages are rejected | Monotonic per-session sequence number checked on receive |
| SR5 | **Forward secrecy (Bonus B1)** — past sessions safe after long-term key leak | Ephemeral key (EK) is destroyed after SK derivation; DH1 and DH2 cannot be recomputed |
| SR6 | **Malicious server resistance (Bonus B2)** — MITM key substitution is detectable | Safety number: deterministic SHA-256 fingerprint of both parties' IK_dh public keys |

---

## Threat Model

| Attacker | Capability | Mitigation |
|----------|-----------|------------|
| A1 — Passive network attacker | Intercept traffic | All messages encrypted with XChaCha20-Poly1305 |
| A2 — Active network attacker | Inject / modify packets | AEAD tag detects any ciphertext modification |
| A3 — Honest-but-curious server | Read stored data | Server stores only ciphertext + public key material |
| A4 — Transient endpoint compromise | Read memory after session | EK private bytes overwritten with random data then zeroed before `del` |
| A5 — Malicious server (MITM) | Substitute public keys | Safety number: users compare out-of-band to detect substitution |

**Trust assumption**: the relay server is trusted for availability and routing, but NOT for confidentiality or key authenticity.

---

## Protocol Overview

### 1. Registration

```
Alice                                  Server
  |--- POST /register ----------------->|
  |    { username, password_hash,       |
  |      IK_sig_pub, IK_dh_pub,         |
  |      SPK_pub, SPK_sig }             |
  |<--- 200 OK -------------------------|
```

### 2. X3DH-lite Key Exchange (Session Establishment)

```
Alice                                  Server                  Bob
  |--- GET /keys/bob --------------->  |                        |
  |<-- { IK_dh_pub, SPK_pub, ... } ----|                        |
  |                                    |                        |
  | Generate EK (ephemeral)            |                        |
  | DH1 = X25519(EK.priv,  Bob.IK_dh) |                        |
  | DH2 = X25519(EK.priv,  Bob.SPK)   |                        |
  | DH3 = X25519(IK_dh,    Bob.SPK)   |                        |
  | SK  = HKDF-SHA256(DH1‖DH2‖DH3)   |                        |
  | *** EK.priv destroyed here ***     |                        |
  |                                    |                        |
  |--- POST /handshake ------------->  |                        |
  |    { EK_pub, hs_sig, ... }         |                        |
  |                                    |--- GET /handshakes --> |
  |                                    |<-- pending list -------|
  |                                    |                        | Mirror DH1/DH2/DH3
  |                                    |                        | SK = HKDF-SHA256(...)
  |                                    |<-- POST /ack --------- |
```

Both sides independently derive the same SK. The relay server sees only public keys and ciphertext.

### 3. Encrypted Messaging

```
Alice                                  Server                  Bob
  | nonce = random(24 bytes)           |                        |
  | AD    = {session_id, sender,       |                        |
  |           recipient, seq}          |                        |
  | CT    = XChaCha20-Poly1305(SK,     |                        |
  |           nonce, msg, AD)          |                        |
  |--- POST /message ---------------> |                        |
  |    { CT, AD, seq }                 |--- GET /messages ---> |
  |                                    |<-- { CT, AD } --------|
  |                                    |                        | Verify seq
  |                                    |                        | Decrypt CT with SK
```

---

## Cryptographic Primitives

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Identity signing key (IK_sig) | Ed25519 | PyNaCl |
| Identity DH key (IK_dh) | X25519 | PyNaCl |
| Signed prekey (SPK) | X25519 + Ed25519 signature | PyNaCl |
| Ephemeral key (EK) | X25519 — generated per session, **destroyed** after SK derivation | PyNaCl |
| Key derivation | HKDF-SHA256, `info=b"e2ee-chat-v1"` | cryptography |
| Message encryption | XChaCha20-Poly1305 AEAD, 24-byte nonce | PyNaCl bindings |
| Safety number | SHA-256 over lexicographically-sorted IK_dh public keys | hashlib |
| Password hashing | bcrypt | bcrypt |
| API authentication | JWT (HS256) | PyJWT |

---

## Project Structure

```
cyber-project/
├── server/
│   ├── main.py                    # FastAPI entry point + all API routes
│   ├── database.py                # SQLite schema and connection helper
│   ├── models.py                  # Pydantic request / response models
│   └── auth.py                    # bcrypt password hashing + JWT
├── client/
│   ├── cli.py                     # CLI entry point (argparse subcommands)
│   ├── crypto.py                  # All cryptographic operations (PyNaCl)
│   ├── protocol.py                # X3DH handshake + message send/recv orchestration
│   ├── storage.py                 # Local identity / session state (~/.e2ee/)
│   └── api.py                     # HTTP client wrapper (httpx)
├── tests/
│   ├── test_phase2_acceptance.py  # X3DH key agreement + signature checks
│   ├── test_phase3_acceptance.py  # Message E2E + replay/tampering rejection
│   ├── test_phase5_acceptance.py  # Safety number symmetry + MITM detection
│   └── test_security.py           # Forward secrecy (Bonus B1)
├── requirements.txt
├── .gitignore
└── README.md
```

**Local state** (never committed):

```
~/.e2ee/<username>/
├── identity.json   # private keys — mode 0o600
├── token.txt       # current JWT
└── sessions/
    └── <peer>_<session_id>.json   # SK + sequence counters
```

---

## Installation

### Prerequisites

- Python 3.11 or later
- pip

### Steps

```bash
git clone <repo-url>
cd cyber-project

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

---

## Full Demo Script

Open **three terminal windows** in the project root with the virtual environment activated.

### Terminal 0 — Start the relay server

```bash
uvicorn server.main:app --host 127.0.0.1 --port 8000 --reload
# → INFO: Application startup complete.
```

Health check:

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

### Terminal 1 — Alice

```bash
# Register and log in
python -m client.cli register --user alice --password alice123
python -m client.cli login    --user alice --password alice123

# Initiate a session with Bob (run AFTER Bob is registered)
python -m client.cli connect --user alice --to bob

# Send a message
python -m client.cli send --user alice --to bob --msg "Hello Bob!"
# → [OK] Encrypted (seq=1)

# Verify safety number matches Bob's (Bonus B2)
python -m client.cli safety-number --user alice --peer bob
# → Safety Number: XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX
```

### Terminal 2 — Bob

```bash
# Register and log in
python -m client.cli register --user bob --password bob123
python -m client.cli login    --user bob --password bob123

# Accept the incoming session from Alice
python -m client.cli listen --user bob

# Receive and decrypt messages
python -m client.cli recv --user bob
# → [alice] Hello Bob!

# Verify safety number matches Alice's (Bonus B2)
python -m client.cli safety-number --user bob --peer alice
# → Safety Number: XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX
```

Both sides must print the **same** 40-digit safety number.

### Verify the server sees only ciphertext

```bash
sqlite3 server/relay.db "SELECT ciphertext FROM messages LIMIT 1;"
# → base64-encoded ciphertext (no plaintext visible)
```

---

## Safety Number — Out-of-Band Key Verification

The safety number is a deterministic, **symmetric** digest of both parties' `IK_dh` public keys:

```
safety_number = format( SHA-256( sort([alice.IK_dh_pub, bob.IK_dh_pub]) ) )
```

Lexicographic sorting ensures both parties compute the same value regardless of call order.  
The 256-bit digest is reduced to **8 groups of 5 decimal digits** (40 digits total).

### Verification procedure

1. Alice runs `python -m client.cli safety-number --user alice --peer bob` → reads out the number.
2. Bob runs `python -m client.cli safety-number --user bob --peer alice` → reads out the number.
3. Compare over a voice call or in person.
   - **Numbers match** → the relay server has not substituted either party's key. Session is authentic.
   - **Numbers differ** → possible key-substitution attack by the server (threat A5). Do not continue the session.

### Why this works

If a malicious server replaces Bob's `IK_dh_pub` with an attacker-controlled key (classic MITM), Alice's safety number will incorporate the fake key while Bob's will incorporate his real key. The two numbers will differ with overwhelming probability (collision resistance of SHA-256).

---

## Security Attack Demonstrations

Run the acceptance test suite to see all attacks blocked automatically:

```bash
pytest tests/ -v -s
```

Individual attack scenarios:

| Attack | Test | Expected result |
|--------|------|-----------------|
| Forged SPK signature | `test_phase2_acceptance.py::test_forged_spk_sig_rejected` | `[REJECT]` — invalid Ed25519 signature |
| Forged handshake signature | `test_phase2_acceptance.py::test_forged_hs_sig_rejected` | `[REJECT]` — transcript mismatch |
| Replay of seq=1 message | `test_phase3_acceptance.py::test_replay_rejected` | `[REJECT]` — duplicate/out-of-order seq |
| Ciphertext byte flip | `test_phase3_acceptance.py::test_aead_tampering_rejected` | `[REJECT]` — AEAD authentication failed |
| Unauthenticated POST | `test_phase3_acceptance.py::test_unauthorized_post_rejected` | HTTP 401/403 |
| Leaked long-term key | `test_security.py::test_leaked_longterm_key_cannot_decrypt` | Historical messages unreadable (SR5) |
| MITM key substitution | `test_phase5_acceptance.py::test_mitm_substitution_detected` | Safety numbers diverge (SR6) |

---

## Running Tests

The full test suite requires the relay server running on `http://localhost:8000`.

```bash
# Start the server (if not already running)
uvicorn server.main:app --host 127.0.0.1 --port 8000 &

# Run all tests
pytest tests/ -v

# Run a specific phase
pytest tests/test_phase2_acceptance.py -v -s
pytest tests/test_phase3_acceptance.py -v -s
pytest tests/test_phase5_acceptance.py -v -s
pytest tests/test_security.py          -v -s
```

Expected output: **15 passed**.

---

## CLI Command Reference

```
python -m client.cli <command> [options]

Commands:
  register      Register a new user
  login         Log in and save JWT token
  keys          Fetch a user's public key bundle from the server
  connect       Initiate an X3DH session with a peer
  listen        Accept a pending X3DH session from a peer
  send          Encrypt and send a message
  recv          Fetch and decrypt pending messages
  safety-number Display the safety number for out-of-band key verification

Options:
  --user USER   Your username (required for all commands)
  --password    Password (register / login)
  --to PEER     Peer username (connect / send)
  --peer PEER   Peer username (safety-number / keys)
  --msg TEXT    Message text (send)
```
