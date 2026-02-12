# S-Box Analysis - Complete Results

## Summary

Successfully reverse-engineered the fused S+P DES lookup tables in `/Users/kim/dev/fs25/gar-lib/src/tables.rs`.

### Key Findings

1. **Only 1 standard DES S-box used**: SBOX9 = DES S2
2. **7 custom S-boxes**: SBOX10-SBOX16 use non-standard substitution tables
3. **Perfect P-box coverage**: All 32 bits covered exactly once across 8 S-boxes
4. **Cryptographic rigor**: All S-boxes maintain perfect value distribution (each value 0-15 appears exactly 4 times)
5. **Partial similarity**: Some custom S-boxes are 25-50% similar to standard DES S-boxes

### Files Created

| File | Description |
|------|-------------|
| `reverse_sbox_mapping.py` | Initial analysis testing all 720 input permutations |
| `reverse_sbox_mapping_detailed.py` | Enhanced version showing full 64-entry tables |
| `verify_sbox_reconstruction.py` | Verification script (100% success on all tables) |
| `compare_sbox_similarity.py` | Similarity analysis vs standard DES |
| `custom_sboxes_extracted.rs` | Rust constants for extracted S-boxes |
| `SBOX_ANALYSIS_REPORT.md` | Detailed technical report |
| `SBOX_MAPPING_SUMMARY.md` | Executive summary |

### Quick Reference

**Mapping Table:**

| Fused Table | S-Box Match | Bit Positions (0-indexed) |
|-------------|-------------|---------------------------|
| SBOX9       | DES S2      | [1, 9, 15, 23]           |
| SBOX10      | Custom      | [4, 5, 14, 19]           |
| SBOX11      | Custom      | [2, 8, 16, 20]           |
| SBOX12      | Custom      | [6, 12, 22, 31]          |
| SBOX13      | Custom      | [7, 18, 24, 29]          |
| SBOX14      | Custom      | [3, 13, 21, 28]          |
| SBOX15      | Custom      | [0, 10, 25, 26]          |
| SBOX16      | Custom      | [11, 17, 27, 30]         |

### Verification

All 512 entries (8 tables × 64 entries) verified:
- ✓ Can reconstruct all fused tables from extracted S-boxes + P-box positions
- ✓ All custom S-boxes maintain perfect value distribution
- ✓ P-box positions provide complete 32-bit coverage with no gaps or overlaps

### Usage

See `custom_sboxes_extracted.rs` for Rust constants ready to use in the codebase.

### Conclusion

This is a **custom DES-like cipher** with:
- Standard DES structure (substitution-permutation network)
- Mostly custom S-boxes (7 out of 8)
- Performance-optimized via fused S+P lookup tables
- Cryptographically sound S-box design (perfect value distribution)

The use of 87.5% custom S-boxes strongly suggests this is a proprietary encryption algorithm designed for the GAR file format.
