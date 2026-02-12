/// Extracted custom S-boxes from the fused S+P lookup tables.
///
/// These are the raw 4-bit S-box values extracted from SBOX9-SBOX16 in tables.rs.
/// Each S-box has 64 entries (indexed 0-63) that map a 6-bit input to a 4-bit output.
///
/// Only CUSTOM_SBOX1 (from SBOX9) matches standard DES S2.
/// CUSTOM_SBOX2 through CUSTOM_SBOX8 are non-standard S-boxes.

/// SBOX9 - Matches standard DES S2
/// Bit positions: [1, 9, 15, 23] (0-indexed)
pub const CUSTOM_SBOX1: [u8; 64] = [
    15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
    9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
    0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
    5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9,
];

/// SBOX10 - Custom S-box (no standard DES match)
/// Bit positions: [4, 5, 14, 19] (0-indexed)
pub const CUSTOM_SBOX2: [u8; 64] = [
    11, 0, 1, 15, 13, 7, 4, 1, 2, 11, 15, 2, 14, 13, 8, 4,
    6, 10, 10, 3, 3, 9, 9, 14, 5, 12, 12, 5, 0, 6, 7, 8,
    1, 15, 4, 9, 11, 8, 8, 2, 13, 1, 3, 12, 2, 4, 14, 7,
    15, 5, 9, 14, 12, 6, 7, 11, 6, 10, 10, 0, 5, 3, 0, 13,
];

/// SBOX11 - Custom S-box (no standard DES match)
/// Bit positions: [2, 8, 16, 20] (0-indexed)
pub const CUSTOM_SBOX3: [u8; 64] = [
    3, 14, 0, 13, 10, 0, 7, 10, 5, 9, 9, 4, 15, 5, 12, 3,
    8, 1, 14, 2, 6, 12, 13, 7, 11, 6, 4, 11, 1, 15, 2, 8,
    14, 8, 5, 3, 4, 14, 10, 0, 2, 5, 15, 10, 9, 2, 0, 13,
    11, 4, 8, 15, 1, 7, 6, 9, 12, 11, 3, 12, 7, 1, 13, 6,
];

/// SBOX12 - Custom S-box (no standard DES match)
/// Bit positions: [6, 12, 22, 31] (0-indexed)
pub const CUSTOM_SBOX4: [u8; 64] = [
    14, 11, 11, 1, 7, 13, 12, 10, 0, 6, 6, 15, 9, 0, 5, 12,
    8, 2, 4, 14, 1, 4, 10, 3, 13, 8, 3, 5, 2, 7, 15, 9,
    5, 12, 6, 15, 9, 0, 0, 6, 3, 5, 13, 8, 14, 11, 11, 1,
    15, 9, 8, 2, 12, 10, 7, 13, 10, 3, 4, 14, 1, 4, 2, 7,
];

/// SBOX13 - Custom S-box (no standard DES match)
/// Bit positions: [7, 18, 24, 29] (0-indexed)
pub const CUSTOM_SBOX5: [u8; 64] = [
    1, 7, 6, 13, 2, 1, 8, 6, 11, 2, 5, 11, 13, 14, 3, 8,
    4, 10, 10, 0, 9, 15, 15, 5, 14, 9, 0, 12, 7, 4, 12, 3,
    2, 13, 1, 4, 8, 6, 13, 11, 5, 8, 14, 7, 11, 1, 4, 14,
    15, 3, 12, 15, 6, 0, 10, 12, 3, 5, 9, 2, 0, 10, 7, 9,
];

/// SBOX14 - Custom S-box (no standard DES match)
/// Bit positions: [3, 13, 21, 28] (0-indexed)
pub const CUSTOM_SBOX6: [u8; 64] = [
    9, 12, 2, 15, 12, 1, 15, 4, 10, 7, 4, 9, 5, 10, 8, 3,
    0, 5, 11, 2, 6, 11, 1, 13, 13, 0, 7, 14, 3, 6, 14, 8,
    10, 1, 13, 6, 15, 4, 3, 9, 4, 10, 8, 3, 9, 15, 6, 12,
    7, 14, 0, 13, 1, 2, 12, 7, 2, 5, 11, 0, 14, 8, 5, 11,
];

/// SBOX15 - Custom S-box (no standard DES match)
/// Bit positions: [0, 10, 25, 26] (0-indexed)
pub const CUSTOM_SBOX7: [u8; 64] = [
    13, 4, 2, 15, 1, 13, 8, 1, 10, 3, 15, 6, 7, 14, 4, 8,
    3, 9, 5, 12, 6, 10, 11, 7, 12, 0, 0, 11, 9, 5, 14, 2,
    14, 2, 7, 4, 8, 11, 4, 14, 5, 8, 9, 3, 11, 1, 2, 13,
    0, 15, 10, 9, 3, 5, 13, 0, 15, 6, 6, 12, 12, 10, 1, 7,
];

/// SBOX16 - Custom S-box (no standard DES match)
/// Bit positions: [11, 17, 27, 30] (0-indexed)
pub const CUSTOM_SBOX8: [u8; 64] = [
    8, 13, 7, 0, 2, 7, 14, 11, 15, 8, 0, 5, 4, 1, 13, 6,
    3, 14, 12, 3, 5, 9, 11, 12, 9, 2, 6, 15, 10, 4, 1, 10,
    1, 10, 8, 7, 7, 13, 13, 4, 12, 1, 3, 8, 11, 6, 14, 11,
    6, 5, 15, 9, 10, 0, 4, 15, 0, 14, 9, 2, 5, 3, 2, 12,
];

/// All custom S-boxes in an array for iteration
pub const CUSTOM_SBOXES: [[u8; 64]; 8] = [
    CUSTOM_SBOX1,
    CUSTOM_SBOX2,
    CUSTOM_SBOX3,
    CUSTOM_SBOX4,
    CUSTOM_SBOX5,
    CUSTOM_SBOX6,
    CUSTOM_SBOX7,
    CUSTOM_SBOX8,
];

/// P-box bit positions for each S-box (0-indexed)
/// These are the bit positions in the 32-bit output word where the 4-bit S-box output is placed.
pub const PBOX_POSITIONS: [[usize; 4]; 8] = [
    [1, 9, 15, 23],    // SBOX9/CUSTOM_SBOX1
    [4, 5, 14, 19],    // SBOX10/CUSTOM_SBOX2
    [2, 8, 16, 20],    // SBOX11/CUSTOM_SBOX3
    [6, 12, 22, 31],   // SBOX12/CUSTOM_SBOX4
    [7, 18, 24, 29],   // SBOX13/CUSTOM_SBOX5
    [3, 13, 21, 28],   // SBOX14/CUSTOM_SBOX6
    [0, 10, 25, 26],   // SBOX15/CUSTOM_SBOX7
    [11, 17, 27, 30],  // SBOX16/CUSTOM_SBOX8
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_values_in_range() {
        for (i, sbox) in CUSTOM_SBOXES.iter().enumerate() {
            for (j, &val) in sbox.iter().enumerate() {
                assert!(
                    val < 16,
                    "CUSTOM_SBOX{} entry {} has value {} which is > 15",
                    i + 1,
                    j,
                    val
                );
            }
        }
    }

    #[test]
    fn test_pbox_positions_unique() {
        let mut all_positions = Vec::new();
        for positions in PBOX_POSITIONS.iter() {
            for &pos in positions {
                assert!(pos < 32, "P-box position {} is >= 32", pos);
                all_positions.push(pos);
            }
        }

        // Check that all 32 bit positions are covered exactly once
        all_positions.sort();
        assert_eq!(
            all_positions.len(),
            32,
            "Expected 32 P-box positions, got {}",
            all_positions.len()
        );

        for (i, &pos) in all_positions.iter().enumerate() {
            assert_eq!(
                pos, i,
                "Expected P-box position {} at index {}, but found {}",
                i, i, pos
            );
        }
    }

    #[test]
    fn test_reconstruct_fused_table() {
        // Test that we can reconstruct SBOX9 from CUSTOM_SBOX1 and PBOX_POSITIONS[0]
        use crate::tables::SBOX9;

        for (input, &expected) in SBOX9.iter().enumerate() {
            let sbox_output = CUSTOM_SBOX1[input];
            let positions = PBOX_POSITIONS[0];

            // Reconstruct the 32-bit value
            let mut reconstructed = 0u32;
            for (bit_idx, &pos) in positions.iter().enumerate() {
                if (sbox_output >> bit_idx) & 1 != 0 {
                    reconstructed |= 1u32 << pos;
                }
            }

            assert_eq!(
                reconstructed, expected,
                "SBOX9[{}]: expected {}, got {}",
                input, expected, reconstructed
            );
        }
    }
}
