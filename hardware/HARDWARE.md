# Jotakey key: hardware brief

A dedicated security-key board: an STM32L432KC (UFQFPN32) with crystal-less USB, an Infineon
OPTIGA Trust M secure element (PG-USON-10) on I2C, a 3.3 V LDO, a capacitive touch pad and a
status LED. The board is a PCB-edge USB-A dongle, fabricated and assembled by JLCPCB.

Every pin and part below is checked against the documents in `datasheets/`; the section of
each document is given where it matters. The KiCad project is `jotakey-key/`.

## 1. Power supply and decoupling

The key is powered from USB VBUS (5 V, noisy), so the MCU and the secure element need a clean,
stable 3.3 V rail.

- **Regulator:** a 3.3 V LDO from VBUS to the 3V3 rail.
  - First choice: XC6206P332MR, JLCPCB Basic, LCSC C5446, 200 mA.
  - Alternative with more headroom: AP2112K-3.3, LCSC C51118, 600 mA.
  - 1 µF at the LDO input and output, plus one 4.7 µF bulk capacitor on 3V3.
- **MCU decoupling** (AN4555):
  - 100 nF placed at each VDD pin (pins 1 and 17);
  - VDDA (pin 5): 100 nF + 1 µF.
  - Check in DS11451 that VDDUSB is bonded to VDD in the UFQFPN32 package.
- **Secure element decoupling:** 100 nF directly next to the OPTIGA VCC pin (pin 10).
- **Bring-up links:** the 3.3 V supply is three rails joined by two 0 Ω resistors (0402,
  LCSC C17168, Basic), so a board can be powered up one stage at a time:
  - `+3V3`: the LDO's output, with C2 and C3;
  - `+3V3_MCU`: the MCU's VDD and VDDA pins, their decoupling and the 3V3 SWD pad (TP4), fed
    from `+3V3` through R6;
  - `+3V3_SE`: the OPTIGA's VCC, its decoupling and the two I2C pull-ups, fed from
    `+3V3_MCU` through R7.

  JLCPCB fits both links. On a hand-assembled board, leave them off at first: check the LDO's
  output with nothing on it, fit R6 and reach the MCU over SWD, then fit R7 for the OPTIGA.
  Across an open link's pads, an ammeter measures one rail's current.
  - The I2C pull-ups are on the OPTIGA's rail so that, with R7 open, they cannot power the
    OPTIGA through the input protection diodes of its SDA and SCL pins. For the same reason,
    firmware run with R7 open keeps PA5 (the OPTIGA's reset) low or floating.

## 2. Crystal-less USB

The STM32L432 USB FS device has an internal D+ pull-up. Its 48 MHz clock comes from HSI48,
trimmed by the clock recovery system (CRS) synchronised to the USB start-of-frame (RM0394,
AN4879). No crystal and no external resistors are needed.

- **USB D+** (USB-A pin 3) → PA12 (pin 22).
- **USB D−** (USB-A pin 2) → PA11 (pin 21).
- **VBUS** (USB-A pin 1) → LDO input. **GND** (USB-A pin 4) → GND plane.
- **ESD:** USBLC6-2SC6 (LCSC C7519) on D+, D− and VBUS, placed next to the edge contacts.
- **No VBUS sensing.** A bus-powered key has no power without VBUS, so a VBUS-detect input has
  nothing to report. (An earlier draft put VBUS sense on PA9, which is also the I2C clock.)

## 3. MCU to OPTIGA Trust M (I2C)

I2C1 on PA9/PA10 (alternate function I2C1_SCL / I2C1_SDA in DS11451).

OPTIGA Trust M PG-USON-10 pinout (datasheet rev 3.70, Table 6 and Figure 7):

| OPTIGA pin | Signal | Connection |
|---|---|---|
| 1 | GND | GND plane |
| 2 | n.c. | leave floating |
| 3 | SDA | PA10 (pin 20), I2C1_SDA |
| 4, 5, 6, 7 | n.c. | leave floating |
| 8 | SCL | PA9 (pin 19), I2C1_SCL |
| 9 | RST (active low, weak internal pull-up) | PA5 (pin 11), push-pull GPIO for a hard reset |
| 10 | VCC | the OPTIGA's 3V3 rail (`+3V3_SE`, §1), 100 nF next to the pin |
| exposed pad | not connected internally | solder to a PCB copper area (GND) for heat |

There is no separate VCC_IO pin; the I2C level follows VCC (1.62–5.5 V).

- **Pull-ups:** 4.7 kΩ from SDA and SCL to the OPTIGA's 3V3 rail (§1). Without them the bus
  floats and the firmware cannot initialise it.
- **Package:** 3 × 3 mm, 0.5 mm pitch, leads 0.25 × 0.4 mm, exposed pad 2.5 × 1.7 mm
  (datasheet Figure 6).
- **Part:** SLS32AIA010MH (OPTIGA Trust M V1, −40…+105 °C), LCSC C539250, JLCPCB Extended.
  V3 (SLS32AIA010MK/ML), which adds HMAC-SHA256, HKDF and AES, was the first choice, but
  JLCPCB has none in stock (C17444580: 0 units). V1 does ECDSA P-256 key generation and
  signing, SHA-256 and the TLS PRF, so the firmware derives keys on the MCU. Both versions
  share the package and pinout, so moving to V3 later changes only the BOM line.

## 4. User presence, status and debug

- **User presence: capacitive touch pad** read by the STM32L432 touch sensing controller
  (TSC), group 2:
  - PB4 (pin 27), TSC_G2_IO1: 10 nF C0G sampling capacitor to GND. AN4310 requires a
    low-absorption dielectric (C0G/NP0) when the MCU uses low-power modes, which an idle key
    will;
  - PB5 (pin 28), TSC_G2_IO2: the touch electrode, through a series resistor near the MCU
    (≈1 kΩ);
  - the electrode is a 10 mm copper disc at the far end of the dongle, laid out as AN4312
    (§3.5.6) describes: 4 mm of bare board around it on the top layer (AN4312 asks for at
    least 2 mm, 4–5 mm recommended), and a 10 % hatched ground plane behind it.
  A touch is required for every signature. This is what stops a remote attacker from silently
  logging into accounts.
- **Status LED:** a single red LED with a 1 kΩ series resistor on PA3 (pin 9, next to the LED), about 1.3 mA.
  Blink patterns signal "touch requested", OK and fault. Red because white and blue LEDs need
  up to 3.1 V, too close to the 3.3 V rail.
- **BOOT0** (PH3, pin 31): 10 kΩ pull-down, so the MCU always boots from flash.
- **NRST** (pin 4): 100 nF to GND.
- **SWD:** PA13 (SWDIO), PA14 (SWCLK), NRST, 3V3 and GND on five test pads, for a pogo-pin
  jig with an ST-Link or J-Link. A dongle has no room for a header.

## 5. Parts and manufacturing

JLCPCB fabricates and assembles the board, so every part is chosen from its catalogue with an
LCSC number. Prefer Basic parts.

The BOM, as chosen from the JLCPCB parts database on 2026-10-16 (stock is a snapshot; check it
before ordering):

| Ref | Part | LCSC | Class |
|---|---|---|---|
| U1 | STM32L432KCU6, UFQFPN-32 | C1337280 | Extended (62 in stock) |
| U2 | OPTIGA Trust M SLS32AIA010MH, USON-10 | C539250 | Extended (60 in stock) |
| U3 | XC6206P332MR-G LDO, SOT-23 | C5446 | Basic |
| U4 | USBLC6-2SC6 ESD, SOT-23-6 | C7519 | Extended |
| D1 | KT-0603R red LED, 0603 | C2286 | Basic |
| C1, C2, C7 | 1 µF 25 V X5R, 0402 | C52923 | Basic |
| C3 | 4.7 µF 16 V X5R, 0603 | C19666 | Basic |
| C4, C5, C6, C8, C9 | 100 nF 16 V X7R, 0402 | C1525 | Basic |
| C10 | 10 nF 50 V C0G, 0402 (touch sampling) | C22400107 | Extended |
| R1, R2 | 1 kΩ 1 %, 0402 | C11702 | Basic |
| R3, R4 | 4.7 kΩ 1 %, 0402 | C25900 | Basic |
| R5 | 10 kΩ 1 %, 0402 | C25744 | Basic |
| R6, R7 | 0 Ω, 0402 (bring-up links, §1) | C17168 | Basic |

J1 (edge contacts), E1 (touch electrode) and TP1–TP5 (SWD pads) are copper on the board, not
parts. Four Extended parts each add JLCPCB's per-part setup fee.
- **Missing parts:** if JLCPCB lacks one, it is sourced through JLCPCB global sourcing or
  consigned, and recorded in `MANUFACTURING.md`.
- **Board:** 2 layers, 2.0 mm thick, ENIG finish, gold fingers with a bevelled edge, black
  solder mask with white silkscreen (recorded in the KiCad board stackup; choose the same
  options when ordering). All parts on the top side.

## 6. Form factor

A USB dongle whose PCB edge is the USB-A plug:
- four contacts on the top side, per the USB 2.0 Series "A" plug drawing (`datasheets/`, USB
  2.0 specification chapter 6), VBUS and GND longer so they mate first;
- the board is 12.0 mm wide at the plug, 18 mm wide and 47 mm long overall;
- 2.0 mm thickness, so the tongue sits firmly in a USB-A receptacle;
- before ordering assembled boards, order bare boards and check the fit in several ports.

## 7. Security notes

- **Readout protection:** production units must set STM32 RDP level 2, which disables debug
  permanently. Like burning eFuses on the ESP32 design, this is irreversible: a human does it,
  never automation (`AGENTS.md` §4).
- **SWD:** the SWD pads are for prototypes only.
- **Shielded Connection:** the I2C bus to the OPTIGA is exposed on the board, so the firmware
  must use the OPTIGA Shielded Connection (encrypted I2C, Solution Reference Manual).
- **Secure element:** the root secret and the signature counter live in the OPTIGA, which
  derives each credential's values on request; the key hierarchy, provisioning and what a
  physical attacker gets are in `AGENTS.md` §3 and chapter 7.5 of `docs/jotakey.typ`.

## 8. Versions

The board and the firmware are versioned separately, each with semantic versioning.

- **Hardware version:** set in one place, the KiCad project text variable `HW_VERSION`
  (`jotakey-key/jotakey-key.kicad_pro`; File > Project Settings > Text Variables). The
  schematic and PCB title blocks and the "HW x.y.z" text on the bottom silkscreen all show
  `${HW_VERSION}`. Releases are tagged `hw-vX.Y.Z`. Bump the major version for changes that
  need different firmware (a pin moves), the minor version for compatible changes (a part
  value, routing), the patch version for silkscreen or documentation fixes.
- **Firmware version:** the Cargo workspace version, tagged `fw-vX.Y.Z`.
