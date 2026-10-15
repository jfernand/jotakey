#!/usr/bin/env python3
"""Independent end-to-end check of a Jotakey with Yubico's python-fido2.

python-fido2 is an implementation we did not write, so this catches misreadings of the
spec that our own client might share with the firmware.

    pip install "fido2>=2.0"
    cargo run -p jotakey-bridge --release -- /dev/ttyACM0 &
    python3 scripts/fido2_check.py          # touch the button when the LED blinks amber
"""
import sys

from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

JOTAKEY = (0x1209, 0x0001)


class Prompt(UserInteraction):
    def prompt_up(self):
        print(">>> touch the BOOT button (LED blinks amber)")


def find_device():
    for dev in CtapHidDevice.list_devices():
        if (dev.descriptor.vid, dev.descriptor.pid) == JOTAKEY:
            return dev
    sys.exit("no Jotakey found (is jotakey-bridge running?)")


def main():
    dev = find_device()
    print("device:", dev, "CTAPHID version", dev.version, "capabilities", hex(dev.capabilities))
    origin = "https://jotakey.test"
    client = Fido2Client(dev, client_data_collector=DefaultClientDataCollector(origin), user_interaction=Prompt())
    print("getInfo:", client.info)
    assert "FIDO_2_0" in client.info.versions

    server = Fido2Server(PublicKeyCredentialRpEntity(id="jotakey.test", name="Jotakey test RP"),
                         attestation="direct")
    user = PublicKeyCredentialUserEntity(id=b"user-1", name="alice", display_name="Alice")

    options, state = server.register_begin(user, user_verification="discouraged",
                                           authenticator_attachment="cross-platform")
    reg = client.make_credential(options["publicKey"])
    auth_data = server.register_complete(state, reg)
    print("registered credential:", auth_data.credential_data.credential_id.hex())

    options, state = server.authenticate_begin([auth_data.credential_data], user_verification="discouraged")
    result = client.get_assertion(options["publicKey"]).get_response(0)
    server.authenticate_complete(state, [auth_data.credential_data], result)
    print("assertion verified by python-fido2's server implementation: OK")


if __name__ == "__main__":
    main()
