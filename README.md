# E2EE Messaging System — COMP5355

End-to-End Encrypted one-to-one messaging system built for COMP5355 Cyber and Internet Security (2025/2026).

Plaintext exists only on sender and recipient devices. The relay server handles registration, public-key distribution, and ciphertext routing but never decrypts message content.

## Requirements

- Python 3.11+

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Start the Relay Server

```bash
uvicorn server.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

## Register Users

```bash
# Terminal 1 — register Alice
python client/cli.py register --user alice --password alice123

# Terminal 2 — register Bob
python client/cli.py register --user bob --password bob123
```

## Establish a Session and Send Messages

```bash
# Terminal 1 — Alice initiates session and sends a message
python client/cli.py connect --user alice --to bob
python client/cli.py send   --user alice --to bob --msg "Hello Bob!"

# Terminal 2 — Bob receives
python client/cli.py recv --user bob
```

## Security Verification Demo

```bash
# Replay attack — expect REJECT
python client/cli.py replay-test --user bob --session <session_id>

# Tamper attack — expect REJECT
python client/cli.py tamper-test --user bob --session <session_id>

# Safety number (Bonus B2 — out-of-band key verification)
python client/cli.py safety-number --user alice --peer bob
python client/cli.py safety-number --user bob   --peer alice
# Both sides must print the same number
```

## Project Structure

```
cyber-project/
├── server/
│   ├── main.py        # FastAPI entry point
│   ├── database.py    # SQLite schema and connection
│   ├── models.py      # Pydantic request/response models
│   └── auth.py        # Password hashing and JWT
├── client/
│   ├── cli.py         # CLI entry point (argparse)
│   ├── crypto.py      # Cryptographic operations (PyNaCl)
│   ├── protocol.py    # X3DH handshake and message flow
│   ├── storage.py     # Local key and session state
│   └── api.py         # HTTP client wrapper
├── tests/
│   ├── test_crypto.py
│   ├── test_protocol.py
│   └── test_security.py
├── requirements.txt
└── README.md
```

## Run Tests

```bash
pytest tests/ -v
```

## Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| Identity signing key | Ed25519 (PyNaCl) |
| Identity DH key & prekey | X25519 (PyNaCl) |
| Ephemeral DH key | X25519 — generated per session, destroyed after SK derivation |
| Session key derivation | HKDF-SHA256 (cryptography) |
| Message encryption | XChaCha20-Poly1305 / XSalsa20-Poly1305 AEAD (PyNaCl SecretBox) |
| Safety number (Bonus B2) | SHA-256 fingerprint of peer identity public key |
