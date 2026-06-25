"""
Cryptographic operations for the E2EE messaging client.

All primitives come from PyNaCl / cryptography.  Nothing is implemented here
from scratch.

Phase 1: key generation only.
Phase 2 will add: x3dh_initiate, x3dh_respond.
Phase 3 will add: encrypt_message, decrypt_message.
"""

import base64

import nacl.public
import nacl.signing


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    """Encode bytes as a URL-safe base64 string."""
    return base64.b64encode(data).decode()


def from_b64(s: str) -> bytes:
    """Decode a base64 string (standard or URL-safe) to bytes."""
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
