# (c) Javier Fernandez @ JotaSoft 2026
"""Write the seed inputs in fuzz/seeds/<target>/: real transactions in each target's input
format, so the fuzzer starts from requests that get all the way through the authenticator
instead of having to discover CTAPHID or BLE framing from random bytes.

    python3 fuzz/make_seeds.py

`just fuzz` passes the seeds to libFuzzer next to the (untracked) working corpus.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent / "seeds"


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + struct.pack(">H", n)


def text(s):
    return head(3, len(s)) + s.encode()


def bstr(b):
    return head(2, len(b)) + b


GET_INFO = bytes([0x04])
# makeCredential: clientDataHash, rp {"id": "example.com"}, user {"id": h'010203'},
# pubKeyCredParams [{"alg": -7, "type": "public-key"}] (canonical key order).
MAKE_CREDENTIAL = bytes([0x01]) + head(5, 4) + b"".join([
    head(0, 1), bstr(bytes([0xCD] * 32)),
    head(0, 2), head(5, 1), text("id"), text("example.com"),
    head(0, 3), head(5, 1), text("id"), bstr(bytes([1, 2, 3])),
    head(0, 4), head(4, 1), head(5, 2), text("alg"), head(1, 6), text("type"), text("public-key"),
])
REQUESTS = {"get_info": GET_INFO, "make_credential": MAKE_CREDENTIAL}


def ctaphid(request):
    """INIT on the broadcast channel (allocates channel 1), then CBOR on channel 1.
    Records are [flags, packet(64)]; flags 0 = broadcast CID, 1 = channel 1."""
    def packet(body):
        return bytes(4) + body + bytes(60 - len(body))

    out = bytes([0]) + packet(bytes([0x86, 0, 8]) + bytes(range(8)))
    payload = request
    out += bytes([1]) + packet(bytes([0x90]) + struct.pack(">H", len(payload)) + payload[:57])
    payload, seq = payload[57:], 0
    while payload:
        out += bytes([1]) + packet(bytes([seq]) + payload[:59])
        payload, seq = payload[59:], seq + 1
    return out


def ble(request):
    """One GATT write carrying the whole MSG at fragment size 510: [frag/2, len, write]."""
    write = bytes([0x83]) + struct.pack(">H", len(request)) + request
    return bytes([255, len(write)]) + write


def serial():
    """Boot text, then two intact frames, in the target's script format (op 1 = intact)."""
    boot = b"ESP-ROM:esp32c6\r\n"
    return bytes([3 * len(boot)]) + boot + bytes([1]) + bytes(range(64)) + bytes([1]) + bytes(64)


# pin_protocol: the authenticator scalar, the platform's COSE key and a ciphertext, from the
# python-fido2 vectors in crates/jotakey-core/src/pin_protocol.rs.
PIN_SCALAR = bytes(range(1, 33))
PIN_PEER = head(5, 5) + b"".join([
    head(0, 1), head(0, 2), head(0, 3), head(1, 24),
    head(1, 0), head(0, 1),
    head(1, 1), bstr(bytes.fromhex("261efbd3550cf068ef013ed7366ba32f5d6fe557b4b2abce8ade58cba168a55e")),
    head(1, 2), bstr(bytes.fromhex("1788a0b29a56a6abec4084c0c96bd3dcbca6b507f35dbea9e985708479d8bdc9")),
])
PIN_CIPHERTEXT = bytes.fromhex(
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf8291a56a04b2f8b88b9f3732e3635b2c"
    "830437c66240d732de4f761d7801110ab6026bdb0f02c92fd38b430ce0688e32"
    "049329fa5b574ebf107fc915f3776e2b")


def pin_protocol(message):
    assert len(PIN_PEER) == 78
    return PIN_SCALAR + bytes([len(PIN_PEER)]) + PIN_PEER + message


# client_pin: scripts of operations (see fuzz_targets/client_pin.rs). Op bytes: 0 key
# agreement, 1 setPIN, 2 changePIN, 3 get token, 4/5 use the token, 6 power cycle,
# 7 reset, 8 getPINRetries, 9 toggle storage failure.
PIN_1234 = [4, 1, 2, 3, 4]          # setPIN shape: 4 digits
RIGHT = [0]                          # guess: the current PIN
WRONG = [3, 9, 9, 9, 9]              # guess: "9999"
CLIENT_PIN_SCRIPTS = {
    "lifecycle": bytes([0, 1, *PIN_1234,
                        3, 1, 3, 0, *RIGHT, 4, 0, 0,        # token mc|ga for a.example; makeCredential
                        3, 1, 2, 2, *RIGHT, 5, 1, 4,        # token ga; silent getAssertion
                        5, 1, 0, 8]),                       # the same with a touch; retries
    "lockout": bytes([0, 1, *PIN_1234,
                      3, 1, 2, 2, *WRONG, 0, 3, 1, 2, 2, *WRONG, 0, 3, 1, 2, 2, *WRONG,
                      3, 1, 2, 2, *RIGHT, 6, 0, 3, 1, 2, 2, *RIGHT, 8, 7, 8]),
    "change_and_failures": bytes([0, 1, *PIN_1234, 2, *RIGHT, 6, 5, 6, 7, 8, 9,
                                  3, 1, 2, 2, *RIGHT, 9, 0, 3, 0, 0, 0, *RIGHT, 4, 1, 2, 9, 7]),
}


def main():
    seeds = {
        "ctaphid_stack": {k: ctaphid(v) for k, v in REQUESTS.items()},
        "ble_stream": {k: ble(v) for k, v in REQUESTS.items()},
        "serial_deframe": {"boot_then_frames": serial()},
        "cbor_decode": {"make_credential_params": MAKE_CREDENTIAL[1:]},
        # mode 0 (raw request), presence byte 0 (Confirmed).
        "ctap_dispatch": {k: bytes([0, 0]) + v for k, v in REQUESTS.items()},
        "client_pin": CLIENT_PIN_SCRIPTS,
        "pin_protocol": {"new_pin_enc": pin_protocol(PIN_CIPHERTEXT), "pin_auth": pin_protocol(bytes(33))},
    }
    for target, files in seeds.items():
        d = HERE / target
        d.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (d / name).write_bytes(data)
    print(f"wrote {sum(map(len, seeds.values()))} seeds for {len(seeds)} targets")


main()
