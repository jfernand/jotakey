#!/usr/bin/env python3
# (c) Javier Fernandez @ JotaSoft 2026
"""Independent check of a Jotakey's PIN support with Yubico's python-fido2.

Without arguments it needs no touch: it sets the PIN if none is set, reads the retry
counter, makes one wrong guess and checks it was counted, gets tokens, and changes the PIN
and back. With --touch it then registers and signs in with user verification required,
which takes two touches, and has python-fido2's server check the UV flag.

The PIN stays set afterwards. Only authenticatorReset removes it, and that also ends every
credential on the key: unplug it, plug it in, and within 10 s run a reset (for example
`fido2-token -R`) and touch the button.

    pip install "fido2>=2.0"
    cargo run -p jotakey-bridge --release -- /dev/ttyACM0 &
    python3 scripts/fido2_pin_check.py [--pin 2468] [--touch]

Use it only with development boards; 2468 is a test PIN.
"""
import argparse
import sys

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

JOTAKEY = (0x1209, 0x0001)
RP_ID = "jotakey.test"


def find_device():
    for dev in CtapHidDevice.list_devices():
        if (dev.descriptor.vid, dev.descriptor.pid) == JOTAKEY:
            return dev
    sys.exit("no Jotakey found (is jotakey-bridge running?)")


def expect_error(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except CtapError as e:
        assert e.code == code, f"expected {code!r}, got {e.code!r}"
        return
    raise AssertionError(f"expected {code!r}, got success")


def no_touch(ctap, pin):
    info = ctap.get_info()
    assert info.options.get("pinUvAuthToken") is True, info.options
    assert info.pin_uv_protocols == [2], info.pin_uv_protocols
    client_pin = ClientPin(ctap)
    assert isinstance(client_pin.protocol, PinProtocolV2)
    if not info.options.get("clientPin"):
        client_pin.set_pin(pin)
        print("PIN set")
        assert ctap.get_info().options["clientPin"] is True
    retries, _ = client_pin.get_pin_retries()
    assert retries == 8, f"{retries} retries left; is --pin right?"

    expect_error(CtapError.ERR.PIN_INVALID, client_pin.get_pin_token, "0000")
    assert client_pin.get_pin_retries()[0] == 7, "the wrong PIN was not counted"
    print("wrong PIN refused and counted: 7 left")

    perms = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
    token = client_pin.get_pin_token(pin, perms, RP_ID)
    assert len(token) == 32
    assert client_pin.get_pin_retries()[0] == 8, "a correct PIN restores the counter"
    print("token with mc|ga for", RP_ID, "issued; counter back to 8")

    expect_error(CtapError.ERR.UNAUTHORIZED_PERMISSION, client_pin.get_pin_token, pin,
                 ClientPin.PERMISSION.CREDENTIAL_MGMT)
    expect_error(CtapError.ERR.NOT_ALLOWED, client_pin.set_pin, pin)
    client_pin.change_pin(pin, pin + "0")
    client_pin.change_pin(pin + "0", pin)
    print("changePIN to a new PIN and back: OK")


class Prompt(UserInteraction):
    def __init__(self, pin):
        self.pin = pin

    def prompt_up(self):
        print(">>> touch the BOOT button (LED blinks amber)")

    def request_pin(self, permissions, rp_id):
        return self.pin


def with_touch(dev, pin):
    client = Fido2Client(dev, client_data_collector=DefaultClientDataCollector("https://" + RP_ID),
                         user_interaction=Prompt(pin))
    server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name="Jotakey test RP"))
    user = PublicKeyCredentialUserEntity(id=b"user-uv", name="alice", display_name="Alice")
    options, state = server.register_begin(user, user_verification="required",
                                           authenticator_attachment="cross-platform")
    reg = client.make_credential(options["publicKey"])
    auth_data = server.register_complete(state, reg)
    assert auth_data.is_user_verified(), "registration without UV"
    print("registered with UV:", auth_data.credential_data.credential_id.hex())
    options, state = server.authenticate_begin([auth_data.credential_data], user_verification="required")
    result = client.get_assertion(options["publicKey"]).get_response(0)
    server.authenticate_complete(state, [auth_data.credential_data], result)
    assert result.response.authenticator_data.is_user_verified()
    print("signed in with UV, verified by python-fido2's server: OK")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin", default="2468", help="the PIN to set or use (a test PIN)")
    parser.add_argument("--touch", action="store_true", help="also register and sign in with UV")
    args = parser.parse_args()
    dev = find_device()
    no_touch(Ctap2(dev), args.pin)
    if args.touch:
        with_touch(dev, args.pin)


if __name__ == "__main__":
    main()
