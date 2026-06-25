"""
High-level protocol orchestration for the E2EE messaging client.

This module coordinates API calls, cryptographic operations, and local storage,
keeping the CLI layer thin and making the protocol logic independently testable.

Phase 2: session establishment (X3DH-lite).
Phase 3: message encryption / decryption (send_message, receive_messages).
"""

import time

import httpx

from client import api, storage
from client.crypto import (
    b64,
    decrypt_message,
    encrypt_message,
    from_b64,
    x3dh_initiate,
    x3dh_respond,
)

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


# ---------------------------------------------------------------------------
# Message send / receive  (Phase 3 — FR-3, SR1, SR2, SR4)
# ---------------------------------------------------------------------------

def send_message(username: str, peer: str, plaintext: str) -> dict:
    """Encrypt *plaintext* and upload it to the relay server for *peer*.

    Loads the latest established session with *peer*, derives the session key,
    builds the associated data, encrypts with XChaCha20-Poly1305, posts to the
    server, and increments seq_send in local session state.

    Returns {"session_id": ..., "seq": ..., "ciphertext": ...}.
    Raises FileNotFoundError if no session with *peer* exists.
    """
    identity = storage.load_identity(username)
    token = storage.load_token(username)
    server_url = identity["server_url"]

    session = storage.find_latest_session(username, peer)
    if session is None:
        raise FileNotFoundError(
            f"No established session with '{peer}'. "
            "Run 'connect' (Alice) and 'listen' (Bob) first."
        )

    SK = from_b64(session["SK"])
    seq = session["seq_send"] + 1  # seq is 1-based for human readability

    ad_dict = {
        "session_id": session["session_id"],
        "sender": username,
        "recipient": peer,
        "seq": seq,
    }

    ciphertext_b64, ad_json = encrypt_message(SK, plaintext, ad_dict)

    api.post_message(
        server_url, token,
        session_id=session["session_id"],
        to=peer,
        ciphertext=ciphertext_b64,
        seq=seq,
        ad=ad_json,
    )

    # Persist updated seq_send
    session["seq_send"] = seq
    storage.save_session(username, peer, session["session_id"], session)

    return {
        "session_id": session["session_id"],
        "seq": seq,
        "ciphertext": ciphertext_b64,
    }


def receive_messages(username: str) -> list[dict]:
    """Fetch and decrypt all pending messages for *username*.

    For each message:
      1. Look up the session by sender username (latest session).
      2. Verify seq == seq_recv_expected (SR4 replay protection).
      3. Decrypt with XChaCha20-Poly1305 (SR1, SR2).
      4. Increment seq_recv_expected and persist session state.

    Returns list of {"sender": ..., "plaintext": ..., "seq": ...}.
    Raises ValueError on seq mismatch or AEAD failure — these are printed
    with [REJECT] prefix by the CLI layer.
    """
    identity = storage.load_identity(username)
    token = storage.load_token(username)
    server_url = identity["server_url"]

    raw_messages = api.get_messages(server_url, token)
    results = []

    for msg in raw_messages:
        sender = msg["sender"]
        session = storage.find_latest_session(username, sender)
        if session is None:
            raise FileNotFoundError(
                f"Received message from '{sender}' but no session exists. "
                "Run 'listen' first."
            )

        expected_seq = session["seq_recv_expected"] + 1
        if msg["seq"] != expected_seq:
            raise ValueError(
                f"Duplicate or out-of-order seq from '{sender}': "
                f"expected {expected_seq}, got {msg['seq']}"
            )

        SK = from_b64(session["SK"])
        plaintext = decrypt_message(SK, msg["ciphertext"], msg["ad"])

        # Persist updated seq_recv_expected
        session["seq_recv_expected"] = expected_seq
        storage.save_session(username, sender, session["session_id"], session)

        results.append({
            "sender": sender,
            "plaintext": plaintext,
            "seq": msg["seq"],
        })

    return results
