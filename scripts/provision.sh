#!/usr/bin/env bash
# (c) Javier Fernandez @ JotaSoft 2026
# Jotakey device provisioning — IRREVERSIBLE eFuse operations.
#
# This script is for a HUMAN to run, step by step, on a board dedicated to being a Jotakey.
# Agents and CI must never run it (AGENTS.md §4). By default it only PRINTS the commands.
#
#   scripts/provision.sh                          # dry run: show every step
#   scripts/provision.sh --execute root-key       # burn the HMAC root key (step 1)
#   scripts/provision.sh --execute lockdown       # disable JTAG / secure download (step 4)
#
# Steps:
#   1. root-key       256-bit K_dev into BLOCK_KEY0, purpose HMAC_UP. eFuse keys with this
#                     purpose are read-protected automatically: software can only use them
#                     through the HMAC peripheral. Without this the firmware fails closed.
#   2. secure-boot    Secure Boot v2 (RSA-3072). Needs an ESP-IDF-built bootloader with
#                     CONFIG_SECURE_BOOT_V2_ENABLED; the app image must be signed. See the
#                     document, chapter "Hardware security". Printed only; do it by hand.
#   3. flash-encrypt  Flash encryption in RELEASE mode (encrypts app + `jotakey` partition).
#                     Also driven by the ESP-IDF bootloader on first boot. Printed only.
#   4. lockdown       Disable pad JTAG and USB JTAG (USB serial stays enabled for the
#                     CTAPHID tunnel) and switch ROM download mode to "secure download".
#                     After this, probe-rs and the on-device test firmware stop working.
#
# Requirements: esptool (espefuse.py / espsecure.py) >= 4.7, openssl, shred.
set -euo pipefail

PORT="${JOTAKEY_PORT:-/dev/ttyACM0}"
CHIP="esp32c6"
EXECUTE=""
STEP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --execute) EXECUTE=1; STEP="${2:-}"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

run() {
    echo "+ $*"
    if [[ -n "$EXECUTE" ]]; then
        "$@"
    fi
}

confirm() {
    [[ -z "$EXECUTE" ]] && return 0
    echo
    echo "!!! $1"
    echo "!!! This cannot be undone. Type the chip's MAC address (see 'espefuse.py summary') to continue:"
    local mac
    mac="$(espefuse.py --chip "$CHIP" --port "$PORT" summary 2>/dev/null | awk '/MAC \(BLOCK1\)/{print $NF; exit}')"
    read -r typed
    if [[ -z "$mac" || "$typed" != "$mac" ]]; then
        echo "confirmation mismatch; aborting" >&2
        exit 1
    fi
}

step_root_key() {
    echo "== Step 1: root key K_dev -> BLOCK_KEY0 (HMAC_UP)"
    # Generate in RAM (tmpfs) and destroy immediately after burning. The key then exists
    # only inside the chip. (Future: on-device generation so it never touches the host.)
    local dir
    dir="$(mktemp -d -p /dev/shm jotakey.XXXXXX)"
    trap 'shred -u "$dir"/* 2>/dev/null || true; rmdir "$dir" 2>/dev/null || true' RETURN
    run openssl rand -out "$dir/k_dev.bin" 32
    confirm "About to burn K_dev into BLOCK_KEY0 with purpose HMAC_UP."
    run espefuse.py --chip "$CHIP" --port "$PORT" burn_key BLOCK_KEY0 "$dir/k_dev.bin" HMAC_UP
    run shred -u "$dir/k_dev.bin"
}

step_secure_boot() {
    echo "== Step 2: Secure Boot v2 (manual; printed for reference)"
    echo "   espsecure.py generate_signing_key --version 2 --scheme rsa3072 jotakey_sb_key.pem"
    echo "   # keep jotakey_sb_key.pem OFFLINE; whoever holds it can sign firmware"
    echo "   idf.py menuconfig  -> Security features -> Enable hardware Secure Boot (v2)"
    echo "   idf.py bootloader  # signed bootloader; flash it at 0x0"
    echo "   espsecure.py sign_data --version 2 --keyfile jotakey_sb_key.pem \\"
    echo "       --output jotakey-fw.signed.bin jotakey-fw.bin"
    echo "   # the bootloader burns the key digest and SECURE_BOOT_EN on first boot"
}

step_flash_encryption() {
    echo "== Step 3: Flash encryption, release mode (manual; printed for reference)"
    echo "   idf.py menuconfig  -> Security features -> Enable flash encryption on boot"
    echo "                      -> Usage mode: Release"
    echo "   # first boot generates the XTS-AES key on-chip (never leaves the chip),"
    echo "   # encrypts app + partitions flagged 'encrypted' (incl. 'jotakey'), and"
    echo "   # disables plaintext flashing"
}

step_lockdown() {
    echo "== Step 4: lock down debug and download interfaces"
    confirm "About to permanently disable JTAG and enable secure download mode."
    run espefuse.py --chip "$CHIP" --port "$PORT" burn_efuse DIS_PAD_JTAG 1 DIS_USB_JTAG 1
    run espefuse.py --chip "$CHIP" --port "$PORT" burn_efuse ENABLE_SECURITY_DOWNLOAD 1
}

if [[ -z "$EXECUTE" ]]; then
    echo "DRY RUN — nothing is written. Use --execute <step> to perform one step."
    echo
    step_root_key
    echo
    step_secure_boot
    echo
    step_flash_encryption
    echo
    step_lockdown
    exit 0
fi

case "$STEP" in
    root-key) step_root_key ;;
    secure-boot) step_secure_boot ;;
    flash-encrypt) step_flash_encryption ;;
    lockdown) step_lockdown ;;
    *) echo "unknown step '$STEP' (root-key | secure-boot | flash-encrypt | lockdown)" >&2; exit 2 ;;
esac
