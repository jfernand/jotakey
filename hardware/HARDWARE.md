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
| 9 | RST (active low, weak internal pull-up) | PB0 (pin 14), push-pull GPIO for a hard reset |
| 10 | VCC | 3V3 rail, 100 nF next to the pin |
| exposed pad | not connected internally | solder to a PCB copper area (GND) for heat |

There is no separate VCC_IO pin; the I2C level follows VCC (1.62–5.5 V).

- **Pull-ups:** 4.7 kΩ from SDA and SCL to 3V3. Without them the bus floats and the firmware
  cannot initialise it.
- **Package:** 3 × 3 mm, 0.5 mm pitch, leads 0.25 × 0.4 mm, exposed pad 2.5 × 1.7 mm
  (datasheet Figure 6).
- **Part:** SLS32AIA010MLUSON10XTMA2 (OPTIGA Trust M V3, −40…+105 °C), LCSC C3232507, JLCPCB
  Extended. V3 rather than V1, because V3 adds HMAC-SHA256, HKDF and AES, which the key
  hierarchy will need.

## 4. User presence, status and debug

- **User presence: capacitive touch pad** read by the STM32L432 touch sensing controller
  (TSC), group 2:
  - PB4 (pin 27), TSC_G2_IO1: sampling capacitor to GND (value from AN4310; ≈22 nF X7R to
    start);
  - PB5 (pin 28), TSC_G2_IO2: the touch electrode, through a series resistor near the MCU
    (≈1 kΩ);
  - the electrode is a copper area at the far end of the dongle, laid out as AN4312 describes.
  A touch is required for every signature. This is what stops a remote attacker from silently
  logging into accounts.
- **Status LED:** a single LED with a series resistor on PA8 (pin 18). Blink patterns signal
  "touch requested", OK and fault.
- **BOOT0** (PH3, pin 31): 10 kΩ pull-down, so the MCU always boots from flash.
- **NRST** (pin 4): 100 nF to GND.
- **SWD:** PA13 (SWDIO), PA14 (SWCLK), NRST, 3V3 and GND on five test pads, for a pogo-pin
  jig with an ST-Link or J-Link. A dongle has no room for a header.

## 5. Parts and manufacturing

JLCPCB fabricates and assembles the board, so every part is chosen from its catalogue with an
LCSC number. Prefer Basic parts.

- **STM32L432KCU6:** LCSC C1337280, Extended.
- **OPTIGA Trust M:** C3232507, Extended.
- **Stock:** for both, check before ordering.
- **Missing parts:** if JLCPCB lacks one, it is sourced through JLCPCB global sourcing or
  consigned, and recorded in `MANUFACTURING.md`.
- **Board:** 2 layers, 2.0 mm thick, ENIG finish, gold fingers with a bevelled edge. All parts
  on the top side.

## 6. Form factor

A USB dongle whose PCB edge is the USB-A plug:
- four contacts on the top side, per the USB 2.0 Series "A" plug drawing (`datasheets/`, USB
  2.0 specification chapter 6), VBUS and GND longer so they mate first;
- the board is 12.0 mm wide at the plug;
- 2.0 mm thickness, so the tongue sits firmly in a USB-A receptacle;
- before ordering assembled boards, order bare boards and check the fit in several ports.

## 7. Security notes

- **Readout protection:** production units must set STM32 RDP level 2, which disables debug
  permanently. Like burning eFuses on the ESP32 design, this is irreversible: a human does it,
  never automation (`AGENTS.md` §4).
- **SWD:** the SWD pads are for prototypes only.
- **Shielded Connection:** the I2C bus to the OPTIGA is exposed on the board, so the firmware
  must use the OPTIGA Shielded Connection (encrypted I2C, Solution Reference Manual).
- **Secure element:** keys generated in the OPTIGA never leave it. The firmware port that uses
  it (and the changes it implies for `AGENTS.md`, the document and the Lean models) is a
  separate piece of work.
