// (c) Javier Fernandez @ JotaSoft 2026
//! The data link's frame checksum: CRC-16 with the CCITT polynomial `x¹⁶ + x¹² + x⁵ + 1`,
//! processed least significant bit first (reflected constant `0x8408`), seed 0
//! (IFX I2C protocol §3.3 and the reference implementation in §8.1.1).

/// CRC-16 of `bytes`, seed 0.
#[must_use]
pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc = crc16_byte(crc, b);
    }
    crc
}

/// One byte of the reference implementation (IFX I2C protocol §8.1.1).
#[must_use]
pub fn crc16_byte(seed: u16, byte: u8) -> u16 {
    let mut crc = seed;
    let mut c = byte;
    for _ in 0..8 {
        if (crc ^ u16::from(c)) & 1 == 1 {
            crc = (crc >> 1) ^ 0x8408;
        } else {
            crc >>= 1;
        }
        c >>= 1;
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The "more efficient implementation" of IFX I2C protocol §8.1.2, as in Infineon's
    /// host library (`ifx_i2c_dl_calc_crc_byte`): an independent formulation to compare with.
    fn crc16_fast(seed: u16, c: u8) -> u16 {
        let h1 = (seed ^ u16::from(c)) & 0xFF;
        let h2 = h1 & 0x0F;
        let h3 = (h2 << 4) ^ h1;
        let h4 = h3 >> 4;
        (((((h3 << 1) ^ h4) << 4) ^ h2) << 3) ^ h4 ^ (seed >> 8)
    }

    #[test]
    fn known_values() {
        // CRC-16/KERMIT has the same polynomial, reflection and zero seed: check value 0x2189.
        assert_eq!(crc16(b"123456789"), 0x2189);
        assert_eq!(crc16(&[]), 0);
        // A control frame "ACK for frame 0" (FCTR 0x80, LEN 0).
        assert_eq!(crc16(&[0x80, 0x00, 0x00]), crc16_byte(crc16_byte(crc16_byte(0, 0x80), 0), 0));
    }

    proptest! {
        #[test]
        fn matches_the_fast_formulation(seed in any::<u16>(), byte in any::<u8>()) {
            prop_assert_eq!(crc16_byte(seed, byte), crc16_fast(seed, byte));
        }
    }
}
