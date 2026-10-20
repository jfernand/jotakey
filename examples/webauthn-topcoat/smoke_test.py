#!/usr/bin/env python3
# (c) Javier Fernandez @ JotaSoft 2026
"""End-to-end smoke test for webauthn-topcoat, with a software ES256 authenticator that
answers like a Jotakey (packed self-attestation, its AAGUID and credential ID format).

It registers and signs in, and checks replays, duplicate credentials, the counter, a
non-canonical attestation object, keys registered with PIN, the list of users, removing
keys, and that a session never reaches a new account under a freed username.

    cargo run &                                  # or any deployment
    uv run -q --with cbor2 --with requests --with cryptography \
        python3 -I smoke_test.py http://localhost:3000 [origin] [rp_id]

Its accounts are named smoke...; at the end it signs in to each and removes its keys,
which deletes the account. Sessions and ceremonies expire on their own (an hour, 5 min).
"""
import atexit, base64, hashlib, json, os, sys

import cbor2
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

BASE = sys.argv[1]
ORIGIN = sys.argv[2] if len(sys.argv) > 2 else BASE
RP_ID = sys.argv[3] if len(sys.argv) > 3 else ORIGIN.split("//")[1].split(":")[0]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

key = ec.generate_private_key(ec.SECP256R1())
cred_id = b"\x01" + os.urandom(48)  # a Jotakey credential ID: 0x01 ‖ nonce ‖ tag
counter = 0
s = requests.Session()
# (username, private key, credential ID, registered with PIN) of every account made.
created = []


def post(path, body):
    r = s.post(BASE + path, json=body)
    r.raise_for_status()
    if BASE.startswith("http:"):  # browsers send Secure cookies to localhost; requests does not
        for c in s.cookies:
            c.secure = False
    return r.json()


def client_data(kind, challenge):
    return json.dumps({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False}).encode()


def auth_data(flags, attested=None):
    rp = hashlib.sha256(RP_ID.encode()).digest()
    d = rp + bytes([flags]) + counter.to_bytes(4, "big")
    if attested:
        d += attested
    return d


def register(user, canonical=True, packed=False, pin=False, uv=False):
    r = post("/api/register/start", {"username": user, "pin": pin})
    assert r["ok"], r
    pk = r["options"]["publicKey"]
    assert pk["rp"]["id"] == RP_ID, pk["rp"]
    nums = key.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
    attested = b"jotakey-v01-c6\x00\x01" + len(cred_id).to_bytes(2, "big") + cred_id + cose
    ad = auth_data(0x45 if uv else 0x41, attested)
    cd = client_data("webauthn.create", pk["challenge"])
    assert pk.get("attestation") == "direct", pk.get("attestation")
    if packed:  # self-attestation, as Jotakey sends: signed by the credential key itself
        sig = key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        fields = {"fmt": "packed", "attStmt": {"alg": -7, "sig": sig}, "authData": ad}
    else:
        fields = {"fmt": "none", "attStmt": {}, "authData": ad}
    if not canonical:  # authData first: valid CBOR, but not CTAP2 canonical order
        fields = {"authData": fields["authData"], "fmt": "none", "attStmt": {}}
    att = cbor2.dumps(fields)
    cred = {"id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key", "extensions": {},
            "response": {"attestationObject": b64(att), "clientDataJSON": b64(cd), "transports": ["usb"]}}
    return r["ceremony"], cred


def sign_in(user, bump=1, uv=False, want_uv="discouraged"):
    global counter
    r = post("/api/login/start", {"username": user})
    assert r["ok"], r
    allowed = r["options"]["publicKey"]["allowCredentials"]
    assert {"type": "public-key", "id": b64(cred_id), "transports": ["usb"]} in allowed, allowed
    assert r["options"]["publicKey"]["userVerification"] == want_uv, r["options"]["publicKey"]
    counter += bump
    ad = auth_data(0x05 if uv else 0x01)
    cd = client_data("webauthn.get", r["options"]["publicKey"]["challenge"])
    sig = key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    cred = {"id": b64(cred_id), "rawId": b64(cred_id), "type": "public-key", "extensions": {},
            "response": {"authenticatorData": b64(ad), "clientDataJSON": b64(cd), "signature": b64(sig), "userHandle": None}}
    return r["ceremony"], cred


def clean_up():
    """Sign in to each account made and remove its key, which deletes the account."""
    global key, cred_id, counter, s
    left = []
    for name, key, cred_id, pin in created:
        counter, s = 1_000_000, requests.Session()
        try:
            want = "required" if pin else "discouraged"
            ceremony, cred = sign_in(name, uv=pin, want_uv=want)
            assert post("/api/login/finish", {"ceremony": ceremony, "credential": cred})["ok"]
            r = post("/api/keys/remove", {"credential": b64(cred_id)}); assert r == {"ok": True, "keys": 0}, r
        except Exception as e:
            left.append(f"{name} ({e})")
    print("cleaned up" if not left else "NOT CLEANED UP, remove by hand: " + ", ".join(left))


atexit.register(clean_up)
user = "smoke" + b64(os.urandom(4)).replace("-", "x").replace("_", "y")
ceremony, cred = register(user, packed=True)
r = post("/api/register/finish", {"ceremony": ceremony, "credential": cred}); assert r == {"ok": True, "username": user, "keys": 1, "model": "Jotakey v01-c6", "warning": None}, r
created.append((user, key, cred_id, False))
r = post("/api/register/finish", {"ceremony": ceremony, "credential": cred}); assert not r["ok"] and "expired" in r["error"], r
print("register ok; replayed finish refused")

# Same credential under another username: duplicate.
c2, cred2 = register(user + "b")
r = post("/api/register/finish", {"ceremony": c2, "credential": cred2}); assert not r["ok"] and "already registered" in r["error"], r
print("duplicate credential refused")

# Someone else cannot take the username.
r = post("/api/register/start", {"username": user}); assert not r["ok"] and "taken" in r["error"], r

ceremony, cred = sign_in(user)
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert r == {"ok": True, "username": user, "counter": 1}, r
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert not r["ok"], r
page = s.get(BASE + "/").text; assert "Signed in as " in page and user in page, page[:500]
for want in ["You signed in with a Jotakey (v01-c6).", "<dd>Jotakey v01-c6</dd>", 'class="signed-in"', "everything the server stores", "User handle", "This sign-in", "Key 1", b64(cred_id), "device-bound", "With</dt><dd>key 1", "<dd>usb</dd>", "<dd>ES256</dd>", "<dd>packed</dd>", "Sign-ins</dt><dd>1</dd>"]:
    assert want in page, (want, page)
print("sign-in ok; session works; replay refused")

ceremony, cred = sign_in(user, bump=0)  # counter did not go up: a cloned key
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert not r["ok"], r
print("non-increasing counter refused:", r["error"])

ceremony, cred = sign_in(user, bump=5)
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert r["ok"] and r["counter"] == 6, r
s.post(BASE + "/logout", allow_redirects=False)
assert "Signed in as" not in s.get(BASE + "/").text
print("counter 6 stored; logout ok")
# A browser that re-encodes the attestation object out of canonical order: the key still
# registers, and the page says what Jotakey's decoder rejected.
key = ec.generate_private_key(ec.SECP256R1()); cred_id = os.urandom(20); counter = 0
s = requests.Session()
other = user + "c"
ceremony, cred = register(other, canonical=False)
r = post("/api/register/finish", {"ceremony": ceremony, "credential": cred})
created.append((other, key, cred_id, False))
assert r["ok"] and r["warning"].startswith("Hmm, it looks like your browser just sent bad CBOR: its map keys are not in canonical order."), r
assert r["model"].startswith("unknown: Hmm"), r
ceremony, cred = sign_in(other)
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert r["ok"], r
page = s.get(BASE + "/").text
assert "<dd>unknown: Hmm, it looks like your browser just sent bad CBOR" in page, page
assert "You signed in with a Jotakey" not in page
print("non-canonical attestation object: registered, warning shown")

# Register with PIN: the request asks for UV; a response without the UV flag is refused,
# and every sign-in with the key must carry it.
key = ec.generate_private_key(ec.SECP256R1()); cred_id = b"\x01" + os.urandom(48); counter = 0
s = requests.Session()
pinned = user + "p"
r = post("/api/register/start", {"username": pinned, "pin": True})
assert r["options"]["publicKey"]["authenticatorSelection"]["userVerification"] == "required", r
ceremony, cred = register(pinned, packed=True, pin=True, uv=False)
r = post("/api/register/finish", {"ceremony": ceremony, "credential": cred}); assert not r["ok"] and "did not verify" in r["error"], r
ceremony, cred = register(pinned, packed=True, pin=True, uv=True)
r = post("/api/register/finish", {"ceremony": ceremony, "credential": cred}); assert r["ok"], r
created.append((pinned, key, cred_id, True))
ceremony, cred = sign_in(pinned, uv=False, want_uv="required")
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert not r["ok"], r
print("PIN key: unverified registration and sign-in refused:", r["error"])
ceremony, cred = sign_in(pinned, uv=True, want_uv="required")
r = post("/api/login/finish", {"ceremony": ceremony, "credential": cred}); assert r["ok"], r
page = s.get(BASE + "/").text
for want in ["PIN required</dt><dd>yes", "User verified</dt><dd>yes", "Add a key with PIN"]:
    assert want in page, (want, page)
print("PIN key: verified sign-in ok")

# The sign-in page lists registered users; signed in, each key has a remove button.
s = requests.Session()
assert f'class="quiet user" data-username="{pinned}"' in s.get(BASE + "/").text
r = post("/api/keys/remove", {"credential": b64(cred_id)}); assert not r["ok"] and "sign in" in r["error"], r

key = ec.generate_private_key(ec.SECP256R1()); cred_id = b"\x01" + os.urandom(48); counter = 0
first = (key, cred_id)
owner = user + "r"
ceremony, cred = register(owner)
assert post("/api/register/finish", {"ceremony": ceremony, "credential": cred})["ok"]
ceremony, cred = sign_in(owner)
assert post("/api/login/finish", {"ceremony": ceremony, "credential": cred})["ok"]
key = ec.generate_private_key(ec.SECP256R1()); cred_id = b"\x01" + os.urandom(48); counter = 0
ceremony, cred = register(owner)  # a second key, added while signed in
r = post("/api/register/finish", {"ceremony": ceremony, "credential": cred}); assert r["ok"] and r["keys"] == 2, r
page = s.get(BASE + "/").text
assert page.count("Remove this key") == 2 and 'data-last="no"' in page, page
r = post("/api/keys/remove", {"credential": b64(first[1])}); assert r == {"ok": True, "keys": 1}, r
r = post("/api/keys/remove", {"credential": b64(first[1])}); assert not r["ok"] and "no such key" in r["error"], r
print("second key added; first removed")

# A second browser signed in to the same account.
mine = s
s = requests.Session()
ceremony, cred = sign_in(owner)
assert post("/api/login/finish", {"ceremony": ceremony, "credential": cred})["ok"]
other_browser, s = s, mine
assert 'data-last="yes"' in s.get(BASE + "/").text
r = post("/api/keys/remove", {"credential": b64(cred_id)}); assert r == {"ok": True, "keys": 0}, r
assert "Signed in as" not in s.get(BASE + "/").text, "removing the last key signs out"
assert f'data-username="{owner}"' not in s.get(BASE + "/").text, "account gone from the list"
print("last key removed: account deleted, signed out")

# Someone registers the freed username, with the freed credential: the other browser's old
# session must not sign it in to the new account.
s = requests.Session()
ceremony, cred = register(owner)
assert post("/api/register/finish", {"ceremony": ceremony, "credential": cred})["ok"], "credential ID freed"
created.append((owner, key, cred_id, False))
assert "Signed in as" not in other_browser.get(BASE + "/").text, "old session reaches the new account"
print("re-registered username: old sessions stay signed out")
print("ALL OK")
