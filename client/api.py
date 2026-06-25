"""
HTTP client wrapper for the relay server API.

Phase 1: register, login, get_keys.
Phase 2 will add: post_handshake, get_handshake.
Phase 3 will add: post_message, poll_messages.
"""

import httpx

DEFAULT_TIMEOUT = 10.0


def _url(server_url: str, path: str) -> str:
    return server_url.rstrip("/") + path


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Phase 1 — registration, login, key lookup
# ---------------------------------------------------------------------------

def register(
    server_url: str,
    username: str,
    password: str,
    key_bundle: dict,
) -> dict:
    """Upload a new user's credentials and public key bundle.

    key_bundle must contain: IK_sig_pub, IK_dh_pub, SPK_pub, SPK_sig.
    Returns {"ok": true} on success; raises httpx.HTTPStatusError on failure.
    """
    r = httpx.post(
        _url(server_url, "/register"),
        json={
            "username": username,
            "password": password,
            **{k: key_bundle[k] for k in ("IK_sig_pub", "IK_dh_pub", "SPK_pub", "SPK_sig")},
        },
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def login(server_url: str, username: str, password: str) -> str:
    """Authenticate and return the JWT bearer token."""
    r = httpx.post(
        _url(server_url, "/login"),
        json={"username": username, "password": password},
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["token"]


def get_keys(server_url: str, peer: str, token: str) -> dict:
    """Fetch the public key bundle for *peer*.

    Returns a dict with IK_sig_pub, IK_dh_pub, SPK_pub, SPK_sig.
    """
    r = httpx.get(
        _url(server_url, f"/keys/{peer}"),
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Phase 2 — handshake
# ---------------------------------------------------------------------------

def post_handshake(
    server_url: str,
    token: str,
    session_id: str,
    to: str,
    EK_pub: str,
    hs_sig: str,
    transcript_hash: str,
) -> dict:
    """Initiator submits a handshake envelope to the relay server."""
    r = httpx.post(
        _url(server_url, "/handshake"),
        json={
            "session_id": session_id,
            "to": to,
            "EK_pub": EK_pub,
            "hs_sig": hs_sig,
            "transcript_hash": transcript_hash,
        },
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def get_pending_handshakes(server_url: str, token: str) -> list[dict]:
    """Responder polls for handshakes addressed to the authenticated user."""
    r = httpx.get(
        _url(server_url, "/handshakes/pending"),
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def get_handshake_status(server_url: str, token: str, session_id: str) -> dict:
    """Check whether a handshake has been acknowledged.

    Returns {"status": "pending"} or {"status": "established"}.
    """
    r = httpx.get(
        _url(server_url, f"/handshake/{session_id}"),
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def ack_handshake(server_url: str, token: str, session_id: str) -> dict:
    """Responder acknowledges a handshake after deriving SK."""
    r = httpx.post(
        _url(server_url, f"/handshake/{session_id}/ack"),
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Phase 3 — messaging
# ---------------------------------------------------------------------------

def post_message(
    server_url: str,
    token: str,
    session_id: str,
    to: str,
    ciphertext: str,
    seq: int,
    ad: str,
) -> dict:
    """Upload an encrypted message to the relay server for delivery."""
    r = httpx.post(
        _url(server_url, "/message"),
        json={
            "session_id": session_id,
            "to": to,
            "ciphertext": ciphertext,
            "seq": seq,
            "ad": ad,
        },
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def get_messages(server_url: str, token: str) -> list[dict]:
    """Fetch and consume all undelivered messages for the authenticated user."""
    r = httpx.get(
        _url(server_url, "/messages"),
        headers=_auth_headers(token),
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["messages"]
