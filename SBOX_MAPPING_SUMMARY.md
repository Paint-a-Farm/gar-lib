# S-Box Mapping Summary

## Overview

Successfully reverse-engineered the mapping between fused S+P DES lookup tables (SBOX9-SBOX16 in `src/tables.rs`) and their underlying S-box and P-box components.

## Key Findings

### 1. Only One Standard DES S-Box Used

Out of 8 fused tables:
- **SBOX9** = Standard DES S2 (with identity input permutation)
- **SBOX10-SBOX16** = 7 custom S-boxes (no matches to standard DES S1-S8)

This indicates a **custom DES-like cipher** rather than standard DES.

### 2. Perfect P-Box Coverage

The P-box bit positions extracted from all 8 tables provide **complete coverage** of all 32 bits:
- Each S-box outputs to 4 specific bit positions
- All 8 S-boxes together cover all 32 bits exactly once
- No gaps, no overlaps

```
SBOX9:  bits [1, 9, 15, 23]
SBOX10: bits [4, 5, 14, 19]
SBOX11: bits [2, 8, 16, 20]
SBOX12: bits [6, 12, 22, 31]
SBOX13: bits [7, 18, 24, 29]
SBOX14: bits [3, 13, 21, 28]
SBOX15: bits [0, 10, 25, 26]
SBOX16: bits [11, 17, 27, 30]
```

Sorted: `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]` ✓

### 3. Verified Reconstruction

All 8 fused tables can be perfectly reconstructed from:
1. The extracted 4-bit S-box values (64 entries each)
2. The P-box bit positions (4 positions each)

Formula: `fused[i] = place_bits(sbox[i], pbox_positions)`

## Files Generated

1. **`reverse_sbox_mapping.py`** - Initial analysis script with all 720 permutation tests
2. **`reverse_sbox_mapping_detailed.py`** - Enhanced version showing full 64-entry tables
3. **`verify_sbox_reconstruction.py`** - Verification that reconstruction is perfect
4. **`custom_sboxes_extracted.rs`** - Rust constants for the extracted S-boxes
5. **`SBOX_ANALYSIS_REPORT.md`** - Detailed analysis with all extracted values
6. **`SBOX_MAPPING_SUMMARY.md`** (this file) - Executive summary

## Implications for Cryptanalysis

### Custom Cipher Design
This is **not standard DES**. It uses:
- DES-like structure (substitution-permutation network)
- 8 parallel S-boxes with 6-bit input, 4-bit output
- Fused S+P tables for performance optimization
- 7 out of 8 S-boxes are custom (non-standard)

### Security Considerations
- **Custom S-boxes** make standard DES cryptanalysis techniques less applicable
- **Security through obscurity** - effectiveness depends on S-box design quality
- Custom S-boxes may or may not have the same cryptographic properties as DES S-boxes (e.g., avalanche effect, non-linearity)
- Would need to analyze the custom S-boxes for weaknesses

### Performance Optimization
The fused S+P tables are a **performance optimization**:
- Single table lookup instead of S-box lookup + P-box permutation
- Each lookup: 64-entry table → 32-bit output with bits pre-positioned
- Trade memory (8 × 64 × 32 bits = 2KB) for speed

## Usage

To use the extracted S-boxes in Rust:

```rust
use crate::custom_sboxes_extracted::{CUSTOM_SBOXES, PBOX_POSITIONS};

// Apply S-box substitution
fn apply_sbox(input: u8, sbox_num: usize) -> u8 {
    CUSTOM_SBOXES[sbox_num][(input & 0x3F) as usize]
}

// Reconstruct fused table value
fn fused_lookup(input: u8, sbox_num: usize) -> u32 {
    let sbox_output = apply_sbox(input, sbox_num);
    let positions = PBOX_POSITIONS[sbox_num];

    let mut result = 0u32;
    for (bit_idx, &pos) in positions.iter().enumerate() {
        if (sbox_output >> bit_idx) & 1 != 0 {
            result |= 1u32 << pos;
        }
    }
    result
}
```

## Standard DES S2 Reference

For reference, SBOX9 uses standard DES S2:

```
Row 0: 15  1  8 14  6 11  3  4  9  7  2 13 12  0  5 10
Row 1:  3 13  4  7 15  2  8 14 12  0  1 10  6  9 11  5
Row 2:  0 14  7 11 10  4 13  1  5  8 12  6  9  3  2 15
Row 3: 13  8 10  1  3 15  4  2 11  6  7 12  0  5 14  9
```

With standard indexing: `row = (bit5 << 1) | bit0`, `col = bits[4:1]`

## Verification Results

All 8 tables verified successfully:
- ✓ SBOX9: 64/64 entries correct
- ✓ SBOX10: 64/64 entries correct
- ✓ SBOX11: 64/64 entries correct
- ✓ SBOX12: 64/64 entries correct
- ✓ SBOX13: 64/64 entries correct
- ✓ SBOX14: 64/64 entries correct
- ✓ SBOX15: 64/64 entries correct
- ✓ SBOX16: 64/64 entries correct

Total: **512/512 entries verified** (100%)

## Custom S-Box Characteristics

### Similarity to Standard DES

Analyzed similarity by computing Hamming distance (number of differing positions):

- **CUSTOM_SBOX1**: 100% match to DES S2 (0 differences)
- **CUSTOM_SBOX2**: 50% similar to DES S1 (32 differences)
- **CUSTOM_SBOX3**: 25% similar to DES S3 (48 differences)
- **CUSTOM_SBOX4**: 25% similar to DES S4 (48 differences)
- **CUSTOM_SBOX5**: 12.5% similar to DES S1/S5 (56 differences)
- **CUSTOM_SBOX6**: 25% similar to DES S6 (48 differences)
- **CUSTOM_SBOX7**: 23.4% similar to DES S8 (49 differences)
- **CUSTOM_SBOX8**: 50% similar to DES S7 (32 differences)

Notably, CUSTOM_SBOX2 and CUSTOM_SBOX8 are 50% similar to standard DES S-boxes, suggesting they may be:
- Partially derived from standard S-boxes
- Designed with similar cryptographic properties
- Or coincidentally similar

### Value Distribution

All custom S-boxes maintain the **perfect balance property** of standard DES S-boxes:
- Each output value (0-15) appears exactly 4 times in the 64-entry table
- This is identical to standard DES S-boxes
- Ensures uniform distribution of output values

This property suggests the custom S-boxes were **designed with cryptographic rigor**, not just randomly generated.

## Next Steps

To fully understand this cipher:

1. ✓ Extract custom S-boxes from fused tables
2. ✓ Verify P-box positions provide complete coverage
3. ✓ Analyze similarity to standard DES S-boxes
4. ✓ Verify value distribution properties
5. Analyze cryptographic properties (avalanche effect, non-linearity)
6. Check if custom S-boxes have inverse relationships
7. Look for usage patterns in the codebase to understand encryption rounds
