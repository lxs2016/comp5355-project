"""
E2EE Messaging Client — command-line interface.

Usage:
    python client/cli.py register --user <name> --password <pw> [--server <url>]
    python client/cli.py login    --user <name> --password <pw> [--server <url>]
    python client/cli.py keys     --user <name> --peer <peer>   [--server <url>]

The --server flag defaults to the E2EE_SERVER environment variable, or
http://localhost:8000 if that variable is not set.

Phase 2 will add: connect, listen
Phase 3 will add: send, recv, chat
Phase 5 will add: safety-number
"""

import argparse
import os
import sys

import httpx

from client import api, storage
from client.crypto import generate_identity_keys

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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "register": cmd_register,
        "login": cmd_login,
        "keys": cmd_keys,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
