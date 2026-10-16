Here is your essential hardware wiring checklist and schematic layout guide to connect the STM32L432 (in the compact QFN32 package) to the Infineon OPTIGA Trust M (in the USON-10 package) for a crystal-less USB security key.

1. Power Supply & Decoupling (The Foundation)

Because your key draws power directly from a dirty 5V USB VBUS line, you need stable power rails to protect your MCU and Secure Element data transfers.
• Regulator: Add a 3.3V Low-Dropout (LDO) linear regulator (e.g., AP2112K-3.3 or XC6206) to step down the USB 5V VBUS to a clean 3.3V VDD rail.
• MCU Decoupling: Place a 0.1µF ceramic capacitor physically close to every VDD/VDDA pin on the STM32L432, paired with one bulk 4.7µF or 10µF capacitor on the main rail.
• Secure Element Decoupling: Place a 0.1µF capacitor directly next to the VCC pin of the OPTIGA Trust M.

2. Crystal-less USB Bus Connections

The STM32L432 routes its internal USB peripheral directly to the physical port without needing external resistors or an external clock crystal.
• USB D+ (Data Plus): Connect physical USB Pin 3 (or USB-C DP1/DP2) directly to Pin PA12 on the STM32L432.
• USB D- (Data Minus): Connect physical USB Pin 2 (or USB-C DN1/DN2) directly to Pin PA11 on the STM32L432.
• VBUS Detection (Optional but Recommended): Route the incoming 5V USB VBUS line through a voltage divider to a 3.3V tolerant GPIO (like PA9) so your Rust firmware instantly knows when physical power is attached.

3. MCU to OPTIGA Trust M Interconnect (I2C Bus)

The OPTIGA Trust M uses an I2C interface to communicate with the host MCU. Ensure you pick pins on the STM32 that map cleanly to I2C1 or I2C3 in the Rust embassy-stm32 configuration.

OPTIGA Trust M Pin (USON-10)	Signal Name	Connection Destination on STM32L432
Pin 1	VCC	Connect to your clean 3.3V VDD Rail
Pin 2	GND	Connect to the common PCB GND Plane
Pin 3	SDA (Data)	Connect to Pin PA10 (STM32 I2C1_SDA)
Pin 4	SCL (Clock)	Connect to Pin PA9 (STM32 I2C1_SCL)
Pin 5	RSTB (Reset)	Connect to Pin PB0 (Any standard GPIO to hard-reset the chip)
Pin 6	VCC_IO	Tie directly to your 3.3V VDD Rail (Sets I2C logic level)

• Pull-up Resistors: You must add two 4.7kΩ resistors pulling up the SDA and SCL lines directly to your 3.3V rail. Without these hardware pull-ups, the I2C bus will float and fail to initialize in your firmware.

4. Physical Security & Debug Controls

Since this is a hardware token, you want to easily verify physical user presence and keep a clean interface for initial flashing.
• User Presence Button: Connect a tactile button or capacitive touch pad to a hardware interrupt pin (e.g., PA0 / WKUP1). Wire it to pull down to GND when pressed, with an external 10kΩ pull-up resistor to 3.3V. This prevents a remote attacker from silently logging into accounts without you physically touching the key.
• SWD Flashing Header: Route PA13 (SWDIO), PA14 (SWCLK), NRST (Reset), 3.3V, and GND out to small test pads or a 1.27mm header on your board. You will use this with an ST-Link or J-Link to flash your compiled Rust binary onto the bare board during prototyping.
Would you like help setting up the minimal Cargo.toml dependencies or the async Embassy main loop structure in Rust to get the embassy-usb and I2C peripherals configured for this exact pinout?

5. Parts provisioning/manufacturing.

This board is going to bemanufactured by jlcpcb, and they are going to assemble it, so the parts need to be in their catalog, or you need to call it out.

6. Form factor.

This will be a USB dongle with edge connector where the PCB is inserted into USB A/USB C.