/* (c) Javier Fernandez @ JotaSoft 2026
 * STM32L432KC: 256 KB flash, 64 KB SRAM (SRAM1 48 KB and SRAM2 16 KB, contiguous).
 * The top 32 KB of flash (0x0803_8000..0x0804_0000) hold the record logs
 * (src/flash.rs) and are kept out of the image. */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 224K
  RAM   : ORIGIN = 0x20000000, LENGTH = 64K
}
