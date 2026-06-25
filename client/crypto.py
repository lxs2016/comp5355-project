"""
Cryptographic operations for the E2EE messaging client.

All primitives come from PyNaCl / cryptography.  Nothing is implemented here
from scratch.

Phase 1: key generation.
Phase 2: X3DH session establishment (x3dh_initiate, x3dh_respond).
Phase 3 will add: encrypt_message, decrypt_message.
"""

import base64
import hashlib
import uuid

import nacl.exceptions
import nacl.public
import nacl.signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    """Encode bytes as base64 string."""
    return base64.b64encode(data).decode()


def from_b64(s: str) -> bytes:
    """Decode a base64 string to bytes."""
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Identity key generation  (FR-1)
# ---------------------------------------------------------------------------

def generate_identity_keys() -> dict:
    """Generate all long-term identity keys for a new user.

    Returns a dict with:
      - IK_sig   : nacl.signing.SigningKey  (Ed25519 private, for signing)
      - IK_dh    : nacl.public.PrivateKey   (X25519 private, for DH)
      - SPK      : nacl.public.PrivateKey   (X25519 signed-prekey private)
      - IK_sig_pub : str  base64 of Ed25519 verify key
      - IK_dh_pub  : str  base64 of X25519 public key
      - SPK_pub    : str  base64 of SPK public key
      - SPK_sig    : str  base64 of IK_sig's signature over SPK_pub bytes
                         (lets the recipient verify SPK was not swapped)
    """
    IK_sig = nacl.signing.SigningKey.generate()  # Ed25519
    IK_dh = nacl.public.PrivateKey.generate()    # X25519
    SPK = nacl.public.PrivateKey.generate()       # X25519

    SPK_pub_bytes = bytes(SPK.public_key)
    # Sign the raw SPK public-key bytes so the recipient can verify it later
    SPK_sig_bytes = IK_sig.sign(SPK_pub_bytes).signature

    return {
        # Private key objects (never leave the client)
        "IK_sig": IK_sig,
        "IK_dh": IK_dh,
        "SPK": SPK,
        # Public material (uploaded to server)
        "IK_sig_pub": b64(bytes(IK_sig.verify_key)),
        "IK_dh_pub": b64(bytes(IK_dh.public_key)),
        "SPK_pub": b64(SPK_pub_bytes),
        "SPK_sig": b64(SPK_sig_bytes),
    }


# ---------------------------------------------------------------------------
# Private DH / KDF helpers  (Phase 2+)
# ---------------------------------------------------------------------------

def _raw_dh(private_bytes: bytes, peer_public_bytes: bytes) -> bytes:
    """Raw X25519 Diffie-Hellman. Returns 32-byte shared secret.

    Uses the `cryptography` library for the raw scalar multiplication so that
    we get the unadjusted output suitable for HKDF input.
    """
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return priv.exchange(pub)


def _hkdf(material: bytes) -> bytes:
    """Derive a 32-byte session key from concatenated DH outputs via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"e2ee-chat-v1",
    ).derive(material)


# ---------------------------------------------------------------------------
# SPK signature verification  (SR3 + Bonus B2 foundation)
# ---------------------------------------------------------------------------

def verify_spk_sig(IK_sig_pub_b64: str, SPK_pub_b64: str, SPK_sig_b64: str) -> bool:
    """Verify that SPK_pub was signed by the owner of IK_sig_pub.

    Calling this before initiating a session ensures the relay server cannot
    silently substitute a different SPK without the owner's private IK_sig.
    """
    vk = nacl.signing.VerifyKey(from_b64(IK_sig_pub_b64))
    try:
        vk.verify(from_b64(SPK_pub_b64), from_b64(SPK_sig_b64))
        return True
    except nacl.exceptions.BadSignatureError:
        return False


# ---------------------------------------------------------------------------
# X3DH-lite session establishment  (FR-2, SR3, Bonus B1)
# ---------------------------------------------------------------------------

def x3dh_initiate(alice_identity: dict, bob_bundle: dict) -> dict:
    """Initiator side of X3DH-lite (Alice).

    Steps:
      1. Verify Bob's SPK signature (SR3, B2).
      2. Generate ephemeral key EK.
      3. Perform three DH operations.
      4. Derive SK = HKDF-SHA256(DH1 || DH2 || DH3).
      5. Sign the handshake transcript with Alice's IK_sig.
      6. Destroy EK private key material (Bonus B1 forward secrecy).

    Returns dict with: SK (bytes), session_id, EK_pub (b64),
                       hs_sig (b64), transcript_hash (b64).
    """
    session_id = str(uuid.uuid4())

    # Verify Bob's SPK was signed by Bob's IK_sig (SR3, B2)
    if not verify_spk_sig(
        bob_bundle["IK_sig_pub"], bob_bundle["SPK_pub"], bob_bundle["SPK_sig"]
    ):
        raise ValueError(
            "Bob's SPK signature verification failed — possible key substitution attack"
        )

    # Generate ephemeral key (B1: destroyed after SK derivation)
    EK = nacl.public.PrivateKey.generate()
    EK_pub_bytes = bytes(EK.public_key)
    EK_priv_bytes = bytes(EK)

    bob_IK_dh = from_b64(bob_bundle["IK_dh_pub"])
    bob_SPK = from_b64(bob_bundle["SPK_pub"])
    alice_IK_dh_priv = bytes(alice_identity["IK_dh"])

    # Three DH operations matching the X3DH-lite spec
    DH1 = _raw_dh(EK_priv_bytes, bob_IK_dh)        # EK.priv  ↔ Bob.IK_dh.pub
    DH2 = _raw_dh(EK_priv_bytes, bob_SPK)           # EK.priv  ↔ Bob.SPK.pub
    DH3 = _raw_dh(alice_IK_dh_priv, bob_SPK)        # Alice.IK_dh.priv ↔ Bob.SPK.pub
    SK = _hkdf(DH1 + DH2 + DH3)

    # Handshake transcript = hash of all public values bound to this session
    transcript_hash = hashlib.sha256(
        session_id.encode() + EK_pub_bytes + bob_IK_dh + bob_SPK
    ).digest()

    # Sign transcript with Alice's long-term signing key (SR3)
    hs_sig = alice_identity["IK_sig"].sign(transcript_hash).signature

    EK_pub_b64 = b64(EK_pub_bytes)

    # Forward secrecy: remove all references to EK private material (B1)
    del EK
    del EK_priv_bytes

    return {
        "SK": SK,
        "session_id": session_id,
        "EK_pub": EK_pub_b64,
        "hs_sig": b64(hs_sig),
        "transcript_hash": b64(transcript_hash),
    }


def x3dh_respond(bob_identity: dict, alice_bundle: dict, handshake: dict) -> bytes:
    """Responder side of X3DH-lite (Bob).

    Steps:
      1. Recompute transcript hash and verify it matches the provided value.
      2. Verify Alice's Ed25519 signature on the transcript (SR3).
      3. Perform three mirrored DH operations.
      4. Derive SK = HKDF-SHA256(DH1 || DH2 || DH3).

    Returns SK (bytes).  Raises ValueError if any verification fails.
    """
    EK_pub_bytes = from_b64(handshake["EK_pub"])
    alice_IK_dh_pub = from_b64(alice_bundle["IK_dh_pub"])
    bob_IK_dh_pub = bytes(bob_identity["IK_dh"].public_key)
    bob_SPK_pub = bytes(bob_identity["SPK"].public_key)
    bob_IK_dh_priv = bytes(bob_identity["IK_dh"])
    bob_SPK_priv = bytes(bob_identity["SPK"])

    # Recompute transcript and verify integrity
    expected_hash = hashlib.sha256(
        handshake["session_id"].encode() + EK_pub_bytes + bob_IK_dh_pub + bob_SPK_pub
    ).digest()
    if expected_hash != from_b64(handshake["transcript_hash"]):
        raise ValueError(
            "Transcript hash mismatch — handshake may have been tampered with"
        )

    # Verify Alice's signature on the transcript (SR3)
    alice_vk = nacl.signing.VerifyKey(from_b64(alice_bundle["IK_sig_pub"]))
    try:
        alice_vk.verify(expected_hash, from_b64(handshake["hs_sig"]))
    except nacl.exceptions.BadSignatureError:
        raise ValueError(
            "Handshake signature verification failed — rejecting session"
        )

    # Mirror DH operations (must produce same shared secrets as Alice)
    DH1 = _raw_dh(bob_IK_dh_priv, EK_pub_bytes)    # Bob.IK_dh.priv ↔ EK.pub
    DH2 = _raw_dh(bob_SPK_priv, EK_pub_bytes)       # Bob.SPK.priv   ↔ EK.pub
    DH3 = _raw_dh(bob_SPK_priv, alice_IK_dh_pub)    # Bob.SPK.priv   ↔ Alice.IK_dh.pub
    return _hkdf(DH1 + DH2 + DH3)
