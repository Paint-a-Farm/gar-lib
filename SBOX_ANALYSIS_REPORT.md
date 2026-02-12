# Fused S-Box + P-Box Analysis Report

## Summary

The file `src/tables.rs` contains 8 fused lookup tables (SBOX9-SBOX16) that combine S-box substitution with P-box permutation. Each table has 64 entries of 32-bit values.

**Key Finding:** Only SBOX9 matches a standard DES S-box (S2). The remaining 7 tables (SBOX10-SBOX16) use **custom S-boxes** that do not match any of the 8 standard DES S-boxes, even with all possible input bit permutations tested.

## Detailed Analysis

### SBOX9 - Standard DES S2

**Bit Positions Used:** [1, 9, 15, 23] (0-indexed) or [2, 10, 16, 24] (1-indexed)

**P-Box Mapping:**
- Bit 1 (pos 2) → P-box position 16 (pos 17)
- Bit 9 (pos 10) → P-box position 15 (pos 16)
- Bit 15 (pos 16) → P-box position 0 (pos 1)
- Bit 23 (pos 24) → P-box position 18 (pos 19)

**S-Box Match:** Standard DES S2
- Indexing: Standard DES (row = outer bits, column = inner bits)
- Input permutation: Identity (0, 1, 2, 3, 4, 5)

**Extracted 4-bit Values:**
```
[ 0-15]: 15  3  1 13  8  4 14  7  6 15 11  2  3  8  4 14
[16-31]:  9 12  7  0  2  1 13 10 12  6  0  9  5 11 10  5
[32-47]:  0 13 14  8  7 10 11  1 10  3  4 15 13  4  1  2
[48-63]:  5 11  8  6 12  7  6 12  9  0  3  5  2 14 15  9
```

This exactly matches standard DES S2 with standard indexing.

---

### SBOX10 - Custom S-Box

**Bit Positions Used:** [4, 5, 14, 19] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]: 11  0  1 15 13  7  4  1  2 11 15  2 14 13  8  4
[16-31]:  6 10 10  3  3  9  9 14  5 12 12  5  0  6  7  8
[32-47]:  1 15  4  9 11  8  8  2 13  1  3 12  2  4 14  7
[48-63]: 15  5  9 14 12  6  7 11  6 10 10  0  5  3  0 13
```

**Match:** None - Custom S-box

---

### SBOX11 - Custom S-Box

**Bit Positions Used:** [2, 8, 16, 20] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]:  3 14  0 13 10  0  7 10  5  9  9  4 15  5 12  3
[16-31]:  8  1 14  2  6 12 13  7 11  6  4 11  1 15  2  8
[32-47]: 14  8  5  3  4 14 10  0  2  5 15 10  9  2  0 13
[48-63]: 11  4  8 15  1  7  6  9 12 11  3 12  7  1 13  6
```

**Match:** None - Custom S-box

---

### SBOX12 - Custom S-Box

**Bit Positions Used:** [6, 12, 22, 31] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]: 14 11 11  1  7 13 12 10  0  6  6 15  9  0  5 12
[16-31]:  8  2  4 14  1  4 10  3 13  8  3  5  2  7 15  9
[32-47]:  5 12  6 15  9  0  0  6  3  5 13  8 14 11 11  1
[48-63]: 15  9  8  2 12 10  7 13 10  3  4 14  1  4  2  7
```

**Match:** None - Custom S-box

---

### SBOX13 - Custom S-Box

**Bit Positions Used:** [7, 18, 24, 29] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]:  1  7  6 13  2  1  8  6 11  2  5 11 13 14  3  8
[16-31]:  4 10 10  0  9 15 15  5 14  9  0 12  7  4 12  3
[32-47]:  2 13  1  4  8  6 13 11  5  8 14  7 11  1  4 14
[48-63]: 15  3 12 15  6  0 10 12  3  5  9  2  0 10  7  9
```

**Match:** None - Custom S-box

---

### SBOX14 - Custom S-Box

**Bit Positions Used:** [3, 13, 21, 28] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]:  9 12  2 15 12  1 15  4 10  7  4  9  5 10  8  3
[16-31]:  0  5 11  2  6 11  1 13 13  0  7 14  3  6 14  8
[32-47]: 10  1 13  6 15  4  3  9  4 10  8  3  9 15  6 12
[48-63]:  7 14  0 13  1  2 12  7  2  5 11  0 14  8  5 11
```

**Match:** None - Custom S-box

---

### SBOX15 - Custom S-Box

**Bit Positions Used:** [0, 10, 25, 26] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]: 13  4  2 15  1 13  8  1 10  3 15  6  7 14  4  8
[16-31]:  3  9  5 12  6 10 11  7 12  0  0 11  9  5 14  2
[32-47]: 14  2  7  4  8 11  4 14  5  8  9  3 11  1  2 13
[48-63]:  0 15 10  9  3  5 13  0 15  6  6 12 12 10  1  7
```

**Match:** None - Custom S-box

---

### SBOX16 - Custom S-Box

**Bit Positions Used:** [11, 17, 27, 30] (0-indexed)

**Extracted 4-bit Values:**
```
[ 0-15]:  8 13  7  0  2  7 14 11 15  8  0  5  4  1 13  6
[16-31]:  3 14 12  3  5  9 11 12  9  2  6 15 10  4  1 10
[32-47]:  1 10  8  7  7 13 13  4 12  1  3  8 11  6 14 11
[48-63]:  6  5 15  9 10  0  4 15  0 14  9  2  5  3  2 12
```

**Match:** None - Custom S-box

---

## Methodology

1. **Bit Position Extraction:** For each fused table, identified which 4 bit positions contain data by taking the bitwise OR of all 64 entries.

2. **4-bit Value Extraction:** Collapsed the 4 scattered bit positions back to a 4-bit value (0-15) for each of the 64 table entries.

3. **S-box Matching:** Attempted to match the extracted 64×4-bit values against all 8 standard DES S-boxes using:
   - Standard DES indexing (row from outer bits, column from inner 4 bits)
   - Linear indexing (direct 0-63 array access)
   - des-crate indexing (top 2 bits = row, bottom 4 = column)

4. **Input Permutation Testing:** For each indexing method, tested all 720 possible permutations of the 6 input bits (6! = 720).

5. **Result:** Only SBOX9 matched a standard S-box. The other 7 tables use custom S-boxes not found in standard DES.

## Implications

This implementation uses **mostly custom S-boxes** rather than standard DES S-boxes. This is likely for one of the following reasons:

1. **Security through obscurity:** Custom S-boxes make cryptanalysis harder
2. **Proprietary encryption:** A custom cipher algorithm based on DES structure
3. **Optimized for specific use case:** S-boxes tuned for the data being encrypted
4. **Obfuscation:** Deliberate deviation from DES to complicate reverse engineering

The use of 7 custom S-boxes (SBOX10-SBOX16) suggests this is **not standard DES**, but rather a DES-like cipher with modified substitution tables.

## Next Steps

To fully document this cipher:

1. Document the custom S-boxes as standalone lookup tables
2. Verify the P-box bit positions against usage in the cipher
3. Check if there are any relationships between the custom S-boxes (e.g., S10 = inverse of S11)
4. Look for usage patterns in the codebase to understand the encryption rounds
