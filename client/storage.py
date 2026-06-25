"""
Local persistent storage for identity keys, session state, and auth tokens.

Layout:
    ~/.e2ee/<username>/
        identity.json      – long-term private keys (chmod 0o600)
        token.txt          – JWT bearer token      (chmod 0o600)
        sessions/
            <peer>_<session_id>.json  – per-session state (Phase 2+)
"""

import base64
import json
from pathlib import Path

import nacl.public
import nacl.signing

BASE_DIR = Path.home() / ".e2ee"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _user_dir(username: str) -> Path:
    d = BASE_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _from_b64(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Identity  (long-term keys)
# ---------------------------------------------------------------------------

def save_identity(username: str, keys: dict, server_url: str) -> None:
    """Persist private keys to disk.  File is written with mode 0o600."""
    data = {
        "username": username,
        "server_url": server_url,
        # Serialise private key objects as raw bytes → base64
        "IK_sig_private": _b64(bytes(keys["IK_sig"])),
        "IK_dh_private": _b64(bytes(keys["IK_dh"])),
        "SPK_private": _b64(bytes(keys["SPK"])),
    }
    path = _user_dir(username) / "identity.json"
    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)


def load_identity(username: str) -> dict:
    """Load private keys from disk and reconstruct nacl key objects."""
    path = _user_dir(username) / "identity.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No identity found for '{username}'. Run 'register' first."
        )
    data = json.loads(path.read_text())
    # Reconstruct nacl objects from raw bytes
    data["IK_sig"] = nacl.signing.SigningKey(_from_b64(data["IK_sig_private"]))
    data["IK_dh"] = nacl.public.PrivateKey(_from_b64(data["IK_dh_private"]))
    data["SPK"] = nacl.public.PrivateKey(_from_b64(data["SPK_private"]))
    return data


def identity_exists(username: str) -> bool:
    return (_user_dir(username) / "identity.json").exists()


# ---------------------------------------------------------------------------
# Auth token
# ---------------------------------------------------------------------------

def save_token(username: str, token: str) -> None:
    path = _user_dir(username) / "token.txt"
    path.write_text(token)
    path.chmod(0o600)


def load_token(username: str) -> str:
    path = _user_dir(username) / "token.txt"
    if not path.exists():
        raise FileNotFoundError(
            f"No token found for '{username}'. Run 'login' first."
        )
    return path.read_text().strip()


# ---------------------------------------------------------------------------
# Session state  (Phase 2+)
# ---------------------------------------------------------------------------

def sessions_dir(username: str) -> Path:
    d = _user_dir(username) / "sessions"
    d.mkdir(exist_ok=True)
    return d


def save_session(username: str, peer: str, session_id: str, state: dict) -> None:
    """Persist session state (SK, seq counters, …)."""
    path = sessions_dir(username) / f"{peer}_{session_id}.json"
    path.write_text(json.dumps(state, indent=2))
    path.chmod(0o600)


def load_session(username: str, peer: str, session_id: str) -> dict:
    path = sessions_dir(username) / f"{peer}_{session_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Session {session_id} not found.")
    return json.loads(path.read_text())


def list_sessions(username: str) -> list[str]:
    """Return a list of '<peer>_<session_id>' stem names."""
    return [p.stem for p in sessions_dir(username).glob("*.json")]
