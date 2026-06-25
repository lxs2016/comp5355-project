"""
High-level protocol orchestration for the E2EE messaging client.

This module coordinates API calls, cryptographic operations, and local storage,
keeping the CLI layer thin and making the protocol logic independently testable.

Phase 2: session establishment (X3DH-lite).
Phase 3 will add: send_message, receive_messages.
"""

import time

import httpx

from client import api, storage
from client.crypto import b64, from_b64, x3dh_initiate, x3dh_respond

# How long to wait for the peer to acknowledge (seconds)
CONNECT_TIMEOUT = 60
# Poll interval while waiting for ack
POLL_INTERVAL = 1.5


# ---------------------------------------------------------------------------
# Initiator side  (Alice — "connect")
# ---------------------------------------------------------------------------

def establish_session_as_initiator(
    username: str,
    peer: str,
    debug: bool = False,
) -> str:
    """Initiate an X3DH-lite session with *peer*.

    1. Load own identity and auth token.
    2. Fetch peer's public key bundle and verify SPK signature.
    3. Run x3dh_initiate → derive SK, generate session_id.
    4. POST /handshake to relay server.
    5. Poll GET /handshake/{session_id} until peer acknowledges (or timeout).
    6. Persist session state locally.

    Returns session_id.
    """
    identity = storage.load_identity(username)
    token = storage.load_token(username)
    server_url = identity["server_url"]

    # Step 1: fetch peer's public key bundle
    bob_bundle = api.get_keys(server_url, peer, token)

    # Step 2: run X3DH initiation (verifies SPK_sig internally)
    result = x3dh_initiate(identity, bob_bundle)
    session_id = result["session_id"]
    SK = result["SK"]

    if debug:
        print(f"[DEBUG] session_id     : {session_id}")
        print(f"[DEBUG] SK (initiator) : {b64(SK)}")

    # Step 3: post handshake to server
    api.post_handshake(
        server_url, token,
        session_id=session_id,
        to=peer,
        EK_pub=result["EK_pub"],
        hs_sig=result["hs_sig"],
        transcript_hash=result["transcript_hash"],
    )

    # Step 4: poll for responder's ack
    deadline = time.time() + CONNECT_TIMEOUT
    while time.time() < deadline:
        status_resp = api.get_handshake_status(server_url, token, session_id)
        if status_resp.get("status") == "established":
            break
        time.sleep(POLL_INTERVAL)
    else:
        raise TimeoutError(
            f"Peer '{peer}' did not acknowledge within {CONNECT_TIMEOUT}s. "
            "Run 'listen' on the peer's side."
        )

    # Step 5: persist session state
    storage.save_session(username, peer, session_id, {
        "session_id": session_id,
        "peer": peer,
        "SK": b64(SK),
        "seq_send": 0,
        "seq_recv_expected": 0,
        "established_at": int(time.time()),
    })

    return session_id


# ---------------------------------------------------------------------------
# Responder side  (Bob — "listen")
# ---------------------------------------------------------------------------

def establish_session_as_responder(
    username: str,
    debug: bool = False,
) -> list[str]:
    """Process all pending incoming handshakes for *username*.

    For each pending handshake:
      1. Fetch initiator's public key bundle.
      2. Run x3dh_respond — verifies the handshake signature and derives SK.
      3. POST /handshake/{session_id}/ack to relay server.
      4. Persist session state locally.

    Returns list of newly established session_ids.
    """
    identity = storage.load_identity(username)
    token = storage.load_token(username)
    server_url = identity["server_url"]

    pending = api.get_pending_handshakes(server_url, token)
    established = []

    for hs in pending:
        session_id = hs["session_id"]
        initiator = hs["initiator"]

        # Fetch initiator's public key bundle
        alice_bundle = api.get_keys(server_url, initiator, token)

        # Derive SK and verify handshake signature
        SK = x3dh_respond(identity, alice_bundle, hs)

        if debug:
            print(f"[DEBUG] session_id    : {session_id}")
            print(f"[DEBUG] SK (responder): {b64(SK)}")

        # Acknowledge to relay server
        api.ack_handshake(server_url, token, session_id)

        # Persist session state
        storage.save_session(username, initiator, session_id, {
            "session_id": session_id,
            "peer": initiator,
            "SK": b64(SK),
            "seq_send": 0,
            "seq_recv_expected": 0,
            "established_at": int(time.time()),
        })

        established.append(session_id)

    return established
