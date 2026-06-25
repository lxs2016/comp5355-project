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
