"""
Phase 5 acceptance tests — Bonus B2: Malicious Server Resistance (SR6).

Requires the relay server running on localhost:8000.

Run with:
    pytest tests/test_phase5_acceptance.py -v -s

Core property:
    compute_safety_number(alice.IK_dh_pub, bob.IK_dh_pub) produces the same
    40-digit string on both sides (symmetric and deterministic).

    If the relay server substitutes Bob's IK_dh_pub with a different key,
    Alice's safety number will differ from Bob's real safety number.
    Out-of-band comparison (phone/in-person) lets both parties detect this.
"""

import os
import random
import string
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

SERVER = "http://localhost:8000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_name(prefix: str = "user", n: int = 8) -> str:
    return prefix + "".join(random.choices(string.ascii_lowercase, k=n))


def register_and_login(username: str, password: str = "pw") -> tuple[dict, str]:
    from client.crypto import generate_identity_keys
    identity = generate_identity_keys()
    r = httpx.post(f"{SERVER}/register", json={
        "username": username, "password": password,
        "IK_sig_pub": identity["IK_sig_pub"],
        "IK_dh_pub": identity["IK_dh_pub"],
        "SPK_pub": identity["SPK_pub"],
        "SPK_sig": identity["SPK_sig"],
    })
    assert r.status_code == 200, r.text
    r = httpx.post(f"{SERVER}/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return identity, r.json()["token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Test 1: Safety number is identical on both sides
# ---------------------------------------------------------------------------

def test_safety_number_symmetric():
    """Alice and Bob compute the same safety number from their own identity keys.

    Procedure:
      - Alice computes: compute_safety_number(alice.IK_dh_pub, bob.IK_dh_pub)
      - Bob computes:  compute_safety_number(bob.IK_dh_pub, alice.IK_dh_pub)
      - Both must produce the same 40-digit string.
    """
    from client.crypto import compute_safety_number, from_b64

    alice_name, bob_name = random_name("alice"), random_name("bob")
    alice_id, alice_tok = register_and_login(alice_name)
    bob_id, bob_tok = register_and_login(bob_name)

    alice_IK_dh_pub = bytes(alice_id["IK_dh"].public_key)
    bob_IK_dh_pub   = bytes(bob_id["IK_dh"].public_key)

    # Alice's view: uses her own key + fetches Bob's from server
    bob_bundle   = httpx.get(f"{SERVER}/keys/{bob_name}",   headers=auth(alice_tok)).json()
    alice_bundle = httpx.get(f"{SERVER}/keys/{alice_name}", headers=auth(bob_tok)).json()

    sn_alice = compute_safety_number(alice_IK_dh_pub, from_b64(bob_bundle["IK_dh_pub"]))
    sn_bob   = compute_safety_number(bob_IK_dh_pub,   from_b64(alice_bundle["IK_dh_pub"]))

    assert sn_alice == sn_bob, (
        f"Safety numbers differ!\nAlice: {sn_alice}\nBob:   {sn_bob}"
    )

    # Structural check: 8 groups of 5 digits separated by spaces
    parts = sn_alice.split(" ")
    assert len(parts) == 8, f"Expected 8 groups, got {len(parts)}"
    for part in parts:
        assert len(part) == 5 and part.isdigit(), f"Bad group: {part!r}"

    print(f"\n[PASS] Safety numbers match: {sn_alice}")


# ---------------------------------------------------------------------------
# Test 2: MITM key substitution is detectable
# ---------------------------------------------------------------------------

def test_mitm_substitution_detected():
    """Substituting Bob's IK_dh_pub produces a different safety number on Alice's side.

    This simulates a malicious relay server (A5) replacing Bob's public key.
    Alice fetches the substituted key; Bob retains his real key.
    Their safety numbers diverge — both parties would notice on comparison.
    """
    from client.crypto import compute_safety_number, from_b64
    import nacl.public

    alice_name, bob_name = random_name("alice"), random_name("bob")
    alice_id, alice_tok = register_and_login(alice_name)
    bob_id, bob_tok = register_and_login(bob_name)

    alice_IK_dh_pub = bytes(alice_id["IK_dh"].public_key)
    bob_IK_dh_pub   = bytes(bob_id["IK_dh"].public_key)
    alice_bundle     = httpx.get(f"{SERVER}/keys/{alice_name}", headers=auth(bob_tok)).json()

    # Bob's real safety number (uses his own key + alice's real key from server)
    sn_bob_real = compute_safety_number(
        bob_IK_dh_pub, from_b64(alice_bundle["IK_dh_pub"])
    )

    # Simulate MITM: attacker generates a fresh random key and serves it as "Bob's"
    mitm_key = nacl.public.PrivateKey.generate()
    mitm_IK_dh_pub = bytes(mitm_key.public_key)

    # Alice (deceived by server) computes safety number with substituted key
    sn_alice_deceived = compute_safety_number(alice_IK_dh_pub, mitm_IK_dh_pub)

    assert sn_alice_deceived != sn_bob_real, (
        "MITM not detected: safety numbers match despite key substitution!"
    )

    print(
        f"\n[PASS] MITM key substitution detected\n"
        f"       Bob's real safety number:   {sn_bob_real}\n"
        f"       Alice's (deceived) number:  {sn_alice_deceived}\n"
        "       Out-of-band comparison would reveal the mismatch."
    )


# ---------------------------------------------------------------------------
# Test 3: Safety number is deterministic (same inputs → same output)
# ---------------------------------------------------------------------------

def test_safety_number_deterministic():
    """compute_safety_number always returns the same value for the same inputs."""
    from client.crypto import compute_safety_number

    alice_name, bob_name = random_name("alice"), random_name("bob")
    alice_id, _ = register_and_login(alice_name)
    bob_id, _   = register_and_login(bob_name)

    alice_pub = bytes(alice_id["IK_dh"].public_key)
    bob_pub   = bytes(bob_id["IK_dh"].public_key)

    sn1 = compute_safety_number(alice_pub, bob_pub)
    sn2 = compute_safety_number(alice_pub, bob_pub)
    sn3 = compute_safety_number(bob_pub, alice_pub)  # reversed order → same result

    assert sn1 == sn2 == sn3, (
        f"Safety number is not deterministic or not symmetric!\n"
        f"  sn1={sn1}\n  sn2={sn2}\n  sn3={sn3}"
    )
    print(f"\n[PASS] Safety number is deterministic and symmetric: {sn1}")
