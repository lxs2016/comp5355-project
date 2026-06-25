"""
E2EE Messaging Client — command-line interface.

Usage:
    python -m client.cli register --user <name> --password <pw> [--server <url>]
    python -m client.cli login    --user <name> --password <pw> [--server <url>]
    python -m client.cli keys     --user <name> --peer <peer>   [--server <url>]
    python -m client.cli connect  --user <name> --to <peer>     [--debug]
    python -m client.cli listen   --user <name>                 [--debug]

The --server flag defaults to the E2EE_SERVER environment variable, or
http://localhost:8000 if that variable is not set.

Phase 3: send, recv
Phase 5: safety-number
"""

import argparse
import os
import sys

import httpx

from client import api, storage
from client.crypto import compute_safety_number, generate_identity_keys
from client.protocol import (
    establish_session_as_initiator,
    establish_session_as_responder,
    receive_messages,
    send_message,
)

DEFAULT_SERVER = os.environ.get("E2EE_SERVER", "http://localhost:8000")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(msg: str) -> None:
    print(f"[OK] {msg}")


def _err(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def _http_error_detail(e: "httpx.HTTPStatusError") -> str:
    """Extract a human-readable message from an HTTP error response."""
    try:
        return e.response.json().get("detail", e.response.text)
    except Exception:
        return e.response.text or str(e)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_register(args: argparse.Namespace) -> None:
    if storage.identity_exists(args.user):
        _err(
            f"Identity for '{args.user}' already exists locally. "
            "Remove ~/.e2ee/{args.user}/ to re-register."
        )
        sys.exit(1)

    keys = generate_identity_keys()
    _ok("Keys generated: IK_sig (Ed25519), IK_dh (X25519), SPK (X25519)")

    key_bundle = {
        "IK_sig_pub": keys["IK_sig_pub"],
        "IK_dh_pub": keys["IK_dh_pub"],
        "SPK_pub": keys["SPK_pub"],
        "SPK_sig": keys["SPK_sig"],
    }

    try:
        api.register(args.server, args.user, args.password, key_bundle)
    except httpx.HTTPStatusError as e:
        _err(f"Registration failed: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server at {args.server}: {e}")
        sys.exit(1)

    storage.save_identity(args.user, keys, args.server)
    _ok(f"Identity saved to ~/.e2ee/{args.user}/identity.json")
    _ok("Keys generated and uploaded")


def cmd_login(args: argparse.Namespace) -> None:
    try:
        token = api.login(args.server, args.user, args.password)
    except httpx.HTTPStatusError as e:
        _err(f"Login failed: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server at {args.server}: {e}")
        sys.exit(1)

    storage.save_token(args.user, token)
    _ok("Logged in. Token saved.")


def cmd_keys(args: argparse.Namespace) -> None:
    try:
        token = storage.load_token(args.user)
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)

    server = storage.load_identity(args.user)["server_url"] if not args.server else args.server

    try:
        bundle = api.get_keys(server, args.peer, token)
    except httpx.HTTPStatusError as e:
        _err(f"Key lookup failed: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server: {e}")
        sys.exit(1)

    print(f"IK_sig_pub : {bundle['IK_sig_pub']}")
    print(f"IK_dh_pub  : {bundle['IK_dh_pub']}")
    print(f"SPK_pub    : {bundle['SPK_pub']}")
    print(f"SPK_sig    : {bundle['SPK_sig']}")


def cmd_connect(args: argparse.Namespace) -> None:
    """Initiate an X3DH-lite session with a peer (Alice side)."""
    try:
        token = storage.load_token(args.user)  # noqa: F841 — ensure logged in
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)

    _ok(f"Fetching {args.to}'s key bundle …")
    try:
        session_id = establish_session_as_initiator(
            args.user, args.to, debug=args.debug
        )
    except ValueError as e:
        _err(str(e))
        sys.exit(1)
    except TimeoutError as e:
        _err(str(e))
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        _err(f"Server error: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server: {e}")
        sys.exit(1)

    _ok("SPK signature verified (SR3)")
    _ok(f"Session {session_id} established")
    _ok("EK destroyed (forward secrecy, B1)")


def cmd_listen(args: argparse.Namespace) -> None:
    """Process pending incoming handshakes (Bob side)."""
    try:
        storage.load_token(args.user)  # ensure logged in
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)

    try:
        sessions = establish_session_as_responder(args.user, debug=args.debug)
    except ValueError as e:
        _err(str(e))
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        _err(f"Server error: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server: {e}")
        sys.exit(1)

    if not sessions:
        print("[INFO] No pending handshakes.")
    else:
        for sid in sessions:
            _ok(f"Alice's signature verified (SR3)")
            _ok(f"Session {sid} established")


def cmd_safety_number(args: argparse.Namespace) -> None:
    """Compute and display the safety number for a peer pair (Phase 5)."""
    try:
        identity = storage.load_identity(args.user)
        token = storage.load_token(args.user)
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)

    server_url = identity["server_url"]
    my_IK_dh_pub = bytes(identity["IK_dh"].public_key)

    try:
        peer_bundle = api.get_keys(server_url, args.peer, token)
    except httpx.HTTPStatusError as e:
        _err(f"Key lookup failed: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server: {e}")
        sys.exit(1)

    from client.crypto import from_b64
    peer_IK_dh_pub = from_b64(peer_bundle["IK_dh_pub"])

    sn = compute_safety_number(my_IK_dh_pub, peer_IK_dh_pub)
    print(f"Safety Number: {sn}")


def cmd_send(args: argparse.Namespace) -> None:
    """Encrypt and send a message to a peer (Phase 3)."""
    try:
        result = send_message(args.user, args.to, args.msg)
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        _err(f"Server error: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server: {e}")
        sys.exit(1)

    _ok(
        f"Encrypted (seq={result['seq']}), "
        f"ciphertext: {result['ciphertext'][:48]}…"
    )


def cmd_recv(args: argparse.Namespace) -> None:
    """Fetch and decrypt all pending messages (Phase 3)."""
    try:
        messages = receive_messages(args.user)
    except FileNotFoundError as e:
        _err(str(e))
        sys.exit(1)
    except ValueError as e:
        print(f"[REJECT] {e}", file=sys.stderr)
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        _err(f"Server error: {_http_error_detail(e)}")
        sys.exit(1)
    except httpx.RequestError as e:
        _err(f"Cannot reach server: {e}")
        sys.exit(1)

    if not messages:
        print("[INFO] No new messages.")
    else:
        for m in messages:
            print(f"[{m['sender']}] {m['plaintext']}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="E2EE Messaging Client",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # register
    p_reg = sub.add_parser("register", help="Register a new user and generate keys")
    p_reg.add_argument("--user", required=True, help="Username")
    p_reg.add_argument("--password", required=True, help="Password")
    p_reg.add_argument("--server", default=DEFAULT_SERVER, help="Relay server URL")

    # login
    p_login = sub.add_parser("login", help="Log in and save the auth token")
    p_login.add_argument("--user", required=True, help="Username")
    p_login.add_argument("--password", required=True, help="Password")
    p_login.add_argument("--server", default=DEFAULT_SERVER, help="Relay server URL")

    # keys
    p_keys = sub.add_parser("keys", help="Fetch a peer's public key bundle")
    p_keys.add_argument("--user", required=True, help="Your username (for auth token)")
    p_keys.add_argument("--peer", required=True, help="Target username to look up")
    p_keys.add_argument("--server", default=None, help="Relay server URL (default: from identity)")

    # connect  (Phase 2 — initiator)
    p_connect = sub.add_parser("connect", help="Initiate an E2EE session with a peer")
    p_connect.add_argument("--user", required=True, help="Your username")
    p_connect.add_argument("--to", required=True, help="Peer username to connect to")
    p_connect.add_argument("--debug", action="store_true", help="Print session key for verification")

    # listen  (Phase 2 — responder)
    p_listen = sub.add_parser("listen", help="Accept pending incoming session handshakes")
    p_listen.add_argument("--user", required=True, help="Your username")
    p_listen.add_argument("--debug", action="store_true", help="Print session key for verification")

    # send  (Phase 3 — send encrypted message)
    p_send = sub.add_parser("send", help="Send an encrypted message to a peer")
    p_send.add_argument("--user", required=True, help="Your username")
    p_send.add_argument("--to", required=True, help="Recipient username")
    p_send.add_argument("--msg", required=True, help="Plaintext message to send")

    # recv  (Phase 3 — receive and decrypt messages)
    p_recv = sub.add_parser("recv", help="Fetch and decrypt pending messages")
    p_recv.add_argument("--user", required=True, help="Your username")

    # safety-number  (Phase 5 — Bonus B2 malicious server resistance)
    p_sn = sub.add_parser(
        "safety-number",
        help="Display the safety number for out-of-band key verification",
    )
    p_sn.add_argument("--user", required=True, help="Your username")
    p_sn.add_argument("--peer", required=True, help="Peer's username")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "register": cmd_register,
        "login": cmd_login,
        "keys": cmd_keys,
        "connect": cmd_connect,
        "listen": cmd_listen,
        "send": cmd_send,
        "recv": cmd_recv,
        "safety-number": cmd_safety_number,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
