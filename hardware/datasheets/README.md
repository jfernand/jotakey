# Datasheets for the jotakey-key board

The documents themselves are not in the repository: they belong to their authors and publishers. Download each from the source listed below into this folder; git ignores everything here except this file.

Reference documents for the STM32L432 + OPTIGA Trust M USB dongle (`hardware/HARDWARE.md`).
Downloaded 2026-10-16. When a part changes or a newer revision is used, replace the file and
update this table.

| File | Document | Revision | Source |
|---|---|---|---|
| `STM32L432KC_datasheet_DS11451.pdf` | STM32L432KB/KC datasheet (pinout, alternate functions, electrical) | DS11451 Rev 4, May 2018 | ST, via the JLCPCB/LCSC part page for C1337280; identical (MD5) to the copy downloaded from st.com |
| `Infineon_OPTIGA_Trust_M_SLS32AIA_datasheet_rev3.70.pdf` | OPTIGA Trust M SLS 32AIA datasheet (pinout Table 6, package outline Fig. 6–7, application circuits §3) | Rev 3.70, 2024-10-09 | https://www.infineon.com/assets/row/public/documents/30/49/infineon-optiga-trust-m-sls32aia-datasheet-en.pdf |
| `Infineon_OPTIGA_Trust_M_Solution_Reference_Manual_v3.60.pdf` | OPTIGA Trust M Solution Reference Manual (commands, objects, shielded connection) | v3.60 | https://github.com/Infineon/optiga-trust-m, branch `develop`, `documents/` |
| `Infineon_OPTIGA_I2C_Protocol_v2.03.pdf` | Infineon I2C protocol specification for OPTIGA (timing, reset, addressing) | v2.03 | same repository |
| `Infineon_OPTIGA_Trust_M_ConfigGuide_v2.2.pdf` | OPTIGA Trust M configuration guide (provisioning and lifecycle) | v2.2 | same repository |
| `Infineon_board_assembly_recommendations_leadless_packages_v02.00.pdf` | Board assembly recommendations for leadless packages (USON land pattern, stencil, exposed pad) | Rev 2.0 | https://www.infineon.com/assets/row/public/documents/packages/infineon-board-assembly-recommendations-integrated-leadless-package-v02-00-en.pdf |
| `ST_USBLC6-2SC6_datasheet.pdf` | USBLC6-2 USB ESD protection (SOT23-6L) | Rev 5, October 2011 | ST, via the JLCPCB part page for C7519 |
| `Torex_XC6206_LDO_datasheet.pdf` | XC6206 LDO regulator (candidate: XC6206P332MR, JLC Basic C5446) | ETR0305_004b | Torex, via the JLCPCB part page for C5446 |
| `Diodes_AP2112_LDO_datasheet.pdf` | AP2112 600 mA LDO (alternative: AP2112K-3.3TRG1, C51118) | DS39724 Rev. 2-2 | Diodes Inc., via the JLCPCB part page for C51118 |
| `USB-IF_USB_2.0_Specification.pdf` | USB 2.0 specification; chapter 6 has the Series "A" plug and receptacle drawings used for the PCB-edge contacts | Revision 2.0 (package of 2025-06-03) | https://www.usb.org/sites/default/files/usb_20_20250603.zip (`usb_20.pdf`) |
| `ST_RM0394_STM32L41x-L46x_reference_manual.pdf` | RM0394, STM32L41xxx–L46xxx reference manual (TSC, USB FS, CRS and HSI48, I2C, flash option bytes and readout protection) | Rev 5, December 2024 | st.com, downloaded in a browser |
| `ST_AN4555_STM32L4_hardware_development.pdf` | AN4555, Getting started with STM32L4 Series hardware development (power, decoupling, reset, BOOT0) | Rev 9, November 2022 | st.com, downloaded in a browser |
| `ST_AN4879_USB_hardware_and_PCB_guidelines.pdf` | AN4879, USB hardware and PCB guidelines using STM32 MCUs (crystal-less USB, routing, ESD) | Rev 12, June 2026 | st.com, downloaded in a browser |
| `ST_AN4312_touch_sensing_surface_sensors.pdf` | AN4312, Design with surface sensors for touch sensing applications (electrode size, ground, layout) | Rev 10, December 2024 | st.com, downloaded in a browser |
| `ST_AN4310_touch_sensing_sampling_capacitor.pdf` | AN4310, How to choose the sampling capacitor for touch sensing applications | Rev 8, December 2024 | st.com, downloaded in a browser |

st.com does not answer scripted downloads (curl, WebFetch and a headless browser all fail), so
the ST documents above were downloaded in a normal browser and copied here.

The status LED's datasheet is added once its part number is chosen.

## Notes from these documents

- **OPTIGA Trust M pinout** (datasheet Table 6, Figure 7):
  - pin 1 GND, pin 3 SDA, pin 8 SCL, pin 9 RST (active low, weak internal pull-up), pin 10 VCC;
  - pins 2 and 4–7 not connected (leave floating);
  - the exposed pad is not connected internally, but should be soldered to a PCB copper area.
- **OPTIGA package** (Figure 6): PG-USON-10-2, 3 × 3 mm, 0.5 mm pitch, leads 0.25 × 0.4 mm,
  exposed pad 2.5 × 1.7 mm, 0.6 mm maximum height.
- **The JLCPCB part for the secure element** is C3232507, SLS32AIA010MLUSON10XTMA2. That is
  OPTIGA Trust M V3, extended temperature range, JLCPCB Extended class.
