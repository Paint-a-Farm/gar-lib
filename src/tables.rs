//! Cipher lookup tables for the GAR DES-variant cipher.
//!
//! The cipher uses standard DES S-boxes (S1-S8, FIPS 46) with a custom P-box
//! permutation. The fused S+P tables (SBOX9-16) and IP/FP bit-spread tables
//! (SBOX7, SBOX8) are derived at compile time from these standard components.

// =============================================================================
// Standard DES S-boxes (FIPS 46-3)
// =============================================================================
//
// Each S-box maps a 6-bit input to a 4-bit output.
// Standard indexing: row = (b0 << 1) | b5, col = b1..b4
// Linearized: for index i, row = ((i>>5)<<1) | (i&1), col = (i>>1) & 0xF

const DES_SBOXES: [[u8; 64]; 8] = [
    // S1
    linearize_sbox([
        [14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7],
        [ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8],
        [ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0],
        [15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13],
    ]),
    // S2
    linearize_sbox([
        [15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10],
        [ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5],
        [ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15],
        [13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9],
    ]),
    // S3
    linearize_sbox([
        [10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1],
        [13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7],
        [ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12],
    ]),
    // S4
    linearize_sbox([
        [ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15],
        [13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9],
        [10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4],
        [ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14],
    ]),
    // S5
    linearize_sbox([
        [ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9],
        [14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6],
        [ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14],
        [11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3],
    ]),
    // S6
    linearize_sbox([
        [12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11],
        [10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8],
        [ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6],
        [ 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13],
    ]),
    // S7
    linearize_sbox([
        [ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1],
        [13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6],
        [ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2],
        [ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12],
    ]),
    // S8
    linearize_sbox([
        [13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7],
        [ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2],
        [ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8],
        [ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11],
    ]),
];

/// Custom P-box permutation (0-indexed).
/// Maps S-box output bit positions to their destination in the 32-bit word.
/// For each S-box slot: [b3→pos, b2→pos, b1→pos, b0→pos] (MSB first).
/// Entry layout: 4 bits per S-box slot, ordered as [S2, S1, S3, S4, S5, S6, S8, S7].
const CUSTOM_PBOX: [u8; 32] = [
    // S2 (slot 0)
    23, 15,  9,  1,
    // S1 (slot 1)
    19,  4,  5, 14,
    // S3 (slot 2)
     8, 16,  2, 20,
    // S4 (slot 3)
     6, 12, 22, 31,
    // S5 (slot 4)
    24, 18,  7, 29,
    // S6 (slot 5)
    28,  3, 21, 13,
    // S8 (slot 6)
     0, 26, 10, 25,
    // S7 (slot 7)
    27, 30, 17, 11,
];

/// S-box slot ordering: which standard DES S-box goes in each slot.
/// Slot 0 uses S2, slot 1 uses S1, ..., slot 7 uses S7.
const SBOX_ORDER: [usize; 8] = [1, 0, 2, 3, 4, 5, 7, 6];

// =============================================================================
// Compile-time derivation of fused S+P lookup tables
// =============================================================================

/// Linearize a 4x16 S-box into a 64-entry table.
/// Standard DES indexing: row = outer bits, col = inner bits.
const fn linearize_sbox(sbox: [[u8; 16]; 4]) -> [u8; 64] {
    let mut result = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        let row = ((i >> 5) << 1) | (i & 1);
        let col = (i >> 1) & 0xF;
        result[i] = sbox[row][col];
        i += 1;
    }
    result
}

/// Build a fused S+P table: for each 6-bit input, look up the S-box output
/// and place the 4 result bits at their P-box destination positions.
const fn build_fused_sp(slot: usize) -> [u32; 64] {
    let sbox = &DES_SBOXES[SBOX_ORDER[slot]];
    let pbox_base = slot * 4;
    let mut table = [0u32; 64];
    let mut i = 0;
    while i < 64 {
        let val = sbox[i] as u32;
        let mut out = 0u32;
        // Bit 3 (MSB) of S-box output → CUSTOM_PBOX[pbox_base + 0]
        // Bit 2 → CUSTOM_PBOX[pbox_base + 1]
        // Bit 1 → CUSTOM_PBOX[pbox_base + 2]
        // Bit 0 (LSB) → CUSTOM_PBOX[pbox_base + 3]
        let mut b = 0;
        while b < 4 {
            if val & (1 << (3 - b)) != 0 {
                out |= 1 << CUSTOM_PBOX[pbox_base + b];
            }
            b += 1;
        }
        table[i] = out;
        i += 1;
    }
    table
}

// =============================================================================
// IP/FP bit-spread tables (Initial/Final Permutation helpers)
// =============================================================================

/// Build SBOX7: IP bit-spread table (86 entries).
/// Spreads even-positioned input bits to positions 0, 8, 16, 24 in a u32.
/// Used by process_input to interleave byte bits into L/R halves.
const fn build_sbox7() -> [u32; 86] {
    let mut table = [0u32; 86];
    let mut i = 0;
    while i < 86 {
        let mut val = 0u32;
        if i & 1 != 0 { val |= 1; }
        if i & 4 != 0 { val |= 1 << 8; }
        if i & 16 != 0 { val |= 1 << 16; }
        if i & 64 != 0 { val |= 1 << 24; }
        table[i] = val;
        i += 1;
    }
    table
}

/// Build SBOX8: FP bit-spread table (16 entries).
/// Spreads a 4-bit nibble to byte positions in a u32 (reversed order).
/// Used by generate_output to de-interleave L/R halves back to bytes.
const fn build_sbox8() -> [u32; 16] {
    let mut table = [0u32; 16];
    let mut i = 0u32;
    while i < 16 {
        let mut val = 0u32;
        if i & 1 != 0 { val |= 1 << 24; }
        if i & 2 != 0 { val |= 1 << 16; }
        if i & 4 != 0 { val |= 1 << 8; }
        if i & 8 != 0 { val |= 1; }
        table[i as usize] = val;
        i += 1;
    }
    table
}

// =============================================================================
// Public constants - all derived at compile time
// =============================================================================

/// IP bit-spread table (86 entries), used by process_input/process_input_esi1
pub const SBOX7: [u32; 86] = build_sbox7();

/// FP bit-spread table (16 entries), used by generate_output
pub const SBOX8: [u32; 16] = build_sbox8();

/// Fused S+P tables: each combines one DES S-box with the custom P-box
pub const SBOX9:  [u32; 64] = build_fused_sp(0); // S2
pub const SBOX10: [u32; 64] = build_fused_sp(1); // S1
pub const SBOX11: [u32; 64] = build_fused_sp(2); // S3
pub const SBOX12: [u32; 64] = build_fused_sp(3); // S4
pub const SBOX13: [u32; 64] = build_fused_sp(4); // S5
pub const SBOX14: [u32; 64] = build_fused_sp(5); // S6
pub const SBOX15: [u32; 64] = build_fused_sp(6); // S8
pub const SBOX16: [u32; 64] = build_fused_sp(7); // S7

// =============================================================================
// Raw encryption keys (k1, k2, k3, k4)
// These were extracted from the macOS game binary.
// Subkeys and RC4 S-boxes are derived from these at runtime.
// =============================================================================

/// FS15-25 raw keys - used for .gar archives (most common for modern files)
pub const KEYS_FS15_25: (u32, u32, u32, u32) = (0x30D0D6B6, 0x14B281C4, 0x2F28AC14, 0x29F53CB9);

/// FS13_A raw keys
pub const KEYS_FS13_A: (u32, u32, u32, u32) = (0x27D85CB2, 0x12E5C984, 0x27D85CB3, 0x12E5C985);

/// FS13_B raw keys - used for .dlc archives
pub const KEYS_FS13_B: (u32, u32, u32, u32) = (0x23F0EA64, 0x317FAC94, 0x1B0C37E7, 0x2501A594);

/// All known key sets for auto-detection (most common first)
pub const ALL_KEYS: [(u32, u32, u32, u32); 3] = [
    KEYS_FS15_25,
    KEYS_FS13_B,
    KEYS_FS13_A,
];
