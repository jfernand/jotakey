#!/usr/bin/env python3
# (c) Javier Fernandez @ JotaSoft 2026
"""The independent check of scripts/fido2_check.py, over Bluetooth instead of USB.

python-fido2 has no BLE transport, so this file adds one: CTAP 2.0 §8.3 framing over the
FIDO GATT service (0xFFFD), through bleak and BlueZ. Then python-fido2's own client and
relying party register a credential and sign in with it, as fido2_check.py does.

    # On the C6: hold BOOT for 3 s while idle; the board advertises for 120 s.
    uv run -q --with "fido2>=2.0" --with bleak python3 scripts/fido2_ble_check.py [ADDRESS]

The FIDO characteristics need an encrypted link, so the first run pairs ("Just Works": no
PIN or passkey to confirm). The board keeps bonds in RAM only: after it restarts, remove
the old pairing (bluetoothctl remove ADDRESS) before pairing again.
"""
import asyncio
import sys
import threading

from bleak import BleakClient, BleakScanner
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapDevice, CtapError, STATUS
from fido2.hid import CAPABILITY, CTAPHID
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

FIDO_SERVICE = "0000fffd-0000-1000-8000-00805f9b34fb"
CONTROL_POINT = "f1d0fff1-deb4-4f7a-b2a1-4e1e56d32e4d"
STATUS_CHAR = "f1d0fff2-deb4-4f7a-b2a1-4e1e56d32e4d"
CONTROL_POINT_LENGTH = "f1d0fff3-deb4-4f7a-b2a1-4e1e56d32e4d"
SERVICE_REVISION_BITFIELD = "f1d0fff4-deb4-4f7a-b2a1-4e1e56d32e4d"
REVISION_FIDO2 = 0x20

# BLE frame commands (crates/jotakey-core/src/transport/ble.rs).
PING, KEEPALIVE, MSG, CANCEL, ERROR = 0x81, 0x82, 0x83, 0xBE, 0xBF
# Longest silence between notifications: the device sends a keepalive every ≤ 100 ms.
FRAME_TIMEOUT = 5.0


class BleCtapDevice(CtapDevice):
    """A FIDO authenticator over BLE. bleak is asyncio; python-fido2 calls in from its own
    thread, so the BLE work runs on an event loop in a background thread."""

    def __init__(self, address=None):
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True).start()
        self._client = None
        self._run(self._connect(address))

    def _run(self, coro, timeout=None):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    async def _connect(self, address):
        print("scanning for a FIDO authenticator (hold BOOT for 3 s on the board)…")
        if address:
            device = await BleakScanner.find_device_by_address(address, timeout=30)
        else:
            device = await BleakScanner.find_device_by_filter(
                lambda d, adv: FIDO_SERVICE in adv.service_uuids, timeout=30)
        if device is None:
            sys.exit("no FIDO authenticator advertising (hold BOOT for 3 s, then run this again)")
        print(f"found {device.name} at {device.address}; connecting")
        self._client = BleakClient(device)
        await self._client.connect()
        try:
            await self._client.pair()
        except Exception as e:  # already paired, or the agent refused: the reads below will tell
            print(f"pair: {e}")
        self.name = device.name
        length = await self._client.read_gatt_char(CONTROL_POINT_LENGTH)
        self.fragment = int.from_bytes(length, "big")
        revision = (await self._client.read_gatt_char(SERVICE_REVISION_BITFIELD))[0]
        if not revision & REVISION_FIDO2:
            sys.exit(f"the device does not offer FIDO2 (revision bits {revision:#04x})")
        await self._client.write_gatt_char(SERVICE_REVISION_BITFIELD, bytes([REVISION_FIDO2]), response=True)
        self._frames = asyncio.Queue()
        await self._client.start_notify(STATUS_CHAR, lambda _, data: self._frames.put_nowait(bytes(data)))
        print(f"connected, encrypted; fragment size {self.fragment}")

    @property
    def capabilities(self):
        # CTAP2 only: Jotakey has no U2F.
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        command = {CTAPHID.CBOR: MSG, CTAPHID.PING: PING}.get(cmd)
        if command is None:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)
        return self._run(self._call(command, data, event, on_keepalive))

    async def _write(self, frame):
        await self._client.write_gatt_char(CONTROL_POINT, frame, response=True)

    async def _call(self, command, data, event, on_keepalive):
        # Request: CMD ‖ HLEN ‖ LLEN ‖ data, then SEQ ‖ data continuations.
        first = self.fragment - 3
        await self._write(bytes([command, len(data) >> 8, len(data) & 0xFF]) + data[:first])
        rest, sequence = data[first:], 0
        while rest:
            await self._write(bytes([sequence]) + rest[: self.fragment - 1])
            rest, sequence = rest[self.fragment - 1 :], (sequence + 1) & 0x7F

        last_status, cancelled = None, False
        while True:
            if event is not None and event.is_set() and not cancelled:
                await self._write(bytes([CANCEL, 0, 0]))
                cancelled = True
            try:
                frame = await asyncio.wait_for(self._frames.get(), timeout=0.1 if event else FRAME_TIMEOUT)
            except asyncio.TimeoutError:
                if event is not None:
                    continue  # keep checking for a cancel; keepalives arrive meanwhile
                raise CtapError(CtapError.ERR.TIMEOUT)
            if frame[0] == KEEPALIVE:
                status = frame[3] if len(frame) > 3 else 0
                if on_keepalive and status != last_status and status in iter(STATUS):
                    on_keepalive(STATUS(status))
                last_status = status
                continue
            if frame[0] == ERROR:
                raise CtapError(frame[3] if len(frame) > 3 else CtapError.ERR.OTHER)
            if frame[0] != command:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)
            total = (frame[1] << 8) | frame[2]
            response, sequence = bytearray(frame[3:]), 0
            while len(response) < total:
                frame = await asyncio.wait_for(self._frames.get(), timeout=FRAME_TIMEOUT)
                if frame[0] != sequence:
                    raise CtapError(CtapError.ERR.INVALID_SEQ)
                response += frame[1:]
                sequence = (sequence + 1) & 0x7F
            return bytes(response[:total])

    def close(self):
        if self._client is not None:
            self._run(self._client.disconnect())

    @classmethod
    def list_devices(cls):
        return iter(())


class Prompt(UserInteraction):
    def prompt_up(self):
        print(">>> press the BOOT button (LED blinks amber)")


def main():
    with BleCtapDevice(sys.argv[1] if len(sys.argv) > 1 else None) as dev:
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
        print("registered over BLE, credential:", auth_data.credential_data.credential_id.hex())

        options, state = server.authenticate_begin([auth_data.credential_data], user_verification="discouraged")
        result = client.get_assertion(options["publicKey"]).get_response(0)
        server.authenticate_complete(state, [auth_data.credential_data], result)
        print("assertion over BLE verified by python-fido2's server implementation: OK")


if __name__ == "__main__":
    main()
