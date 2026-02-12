#!/usr/bin/env python3
"""
Extract the exact P-box permutation by finding S-box outputs that are powers of 2.
When S-box output is 1, 2, 4, or 8, the fused table has exactly one bit set,
revealing the P-box destination for that S-box output bit.
"""

DES_SBOXES = [
    # S1
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    # S2
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    # S3
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    # S4
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    # S5
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    # S6
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    # S7
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    # S8
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]

FUSED = {
    'SBOX9':  [8421890,514,2,8421378,8388608,32768,8421888,33282,33280,8421890,8389122,512,514,8388608,32768,8421888,8388610,8421376,33282,0,512,2,8421378,8389120,8421376,33280,0,8388610,32770,8389122,8389120,32770,0,8421378,8421888,8388608,33282,8389120,8389122,2,8389120,514,32768,8421890,8421378,32768,2,512,32770,8389122,8388608,33280,8421376,33282,33280,8421376,8388610,0,514,32770,512,8421888,8421890,8388610],
    'SBOX10': [524336,0,16,540720,540688,16432,16384,16,32,524336,540720,32,540704,540688,524288,16384,16416,524320,524320,48,48,524304,524304,540704,16400,540672,540672,16400,0,16416,16432,524288,16,540720,16384,524304,524336,524288,524288,32,540688,16,48,540672,32,16384,540704,16432,540720,16400,524304,540704,540672,16416,16432,524336,16416,524320,524320,0,16400,48,0,540688],
    'SBOX11': [260,1114368,0,1114116,1048832,0,65796,1048832,65540,1048580,1048580,65536,1114372,65540,1114112,260,1048576,4,1114368,256,65792,1114112,1114116,65796,1048836,65792,65536,1048836,4,1114372,256,1048576,1114368,1048576,65540,260,65536,1114368,1048832,0,256,65540,1114372,1048832,1048580,256,0,1114116,1048836,65536,1048576,1114372,4,65796,65792,1048580,1114112,1048836,260,1114112,65796,4,1114116,65792],
    'SBOX12': [2151682048,2147487808,2147487808,64,4198464,2151678016,2151677952,2147487744,0,4198400,4198400,2151682112,2147483712,0,4194368,2151677952,2147483648,4096,4194304,2151682048,64,4194304,2147487744,4160,2151678016,2147483648,4160,4194368,4096,4198464,2151682112,2147483712,4194368,2151677952,4198400,2151682112,2147483712,0,0,4198400,4160,4194368,2151678016,2147483648,2151682048,2147487808,2147487808,64,2151682112,2147483712,2147483648,4096,2151677952,2147487744,4198464,2151678016,2147487744,4160,4194304,2151682048,64,4194304,4096,4198464],
    'SBOX13': [128,17039488,17039360,553648256,262144,128,536870912,17039360,537133184,262144,16777344,537133184,553648256,553910272,262272,536870912,16777216,537133056,537133056,0,536871040,553910400,553910400,16777344,553910272,536871040,0,553648128,17039488,16777216,553648128,262272,262144,553648256,128,16777216,536870912,17039360,553648256,537133184,16777344,536870912,553910272,17039488,537133184,128,16777216,553910272,553910400,262272,553648128,553910400,17039360,0,537133056,553648128,262272,16777344,536871040,262144,0,537133056,17039488,536871040],
    'SBOX14': [268435464,270532608,8192,270540808,270532608,8,270540808,2097152,268443648,2105352,2097152,268435464,2097160,268443648,268435456,8200,0,2097160,268443656,8192,2105344,268443656,8,270532616,270532616,0,2105352,270540800,8200,2105344,270540800,268435456,268443648,8,270532616,2105344,270540808,2097152,8200,268435464,2097152,268443648,268435456,8200,268435464,270540808,2105344,270532608,2105352,270540800,0,270532616,8,8192,270532608,2105352,8192,2097160,268443656,0,270540800,268435456,2097160,268443656],
    'SBOX15': [100663297,33554432,1024,100664321,1,100663297,67108864,1,67109888,1025,100664321,33555456,33555457,100664320,33554432,67108864,1025,67108865,33554433,100663296,33555456,67109888,67109889,33555457,100663296,0,0,67109889,67108865,33554433,100664320,1024,100664320,1024,33555457,33554432,67108864,67109889,33554432,100664320,33554433,67108864,67108865,1025,67109889,1,1024,100663297,0,100664321,67109888,67108865,1025,33554433,100663297,0,100664321,33555456,33555456,100663296,100663296,67109888,1,33555457],
    'SBOX16': [1073741824,1207961600,134350848,0,131072,134350848,1208090624,1073874944,1208092672,1073741824,0,134219776,134217728,2048,1207961600,134348800,133120,1208090624,1207959552,133120,134219776,1073743872,1073874944,1207959552,1073743872,131072,134348800,1208092672,1073872896,134217728,2048,1073872896,2048,1073872896,1073741824,134350848,134350848,1207961600,1207961600,134217728,1207959552,2048,133120,1073741824,1073874944,134348800,1208090624,1073874944,134348800,134219776,1208092672,1073743872,1073872896,0,134217728,1208092672,0,1208090624,1073743872,131072,134219776,133120,131072,1207959552],
}

SBOX_TO_DES = {
    'SBOX9': 1,   # S2
    'SBOX10': 0,  # S1
    'SBOX11': 2,  # S3
    'SBOX12': 3,  # S4
    'SBOX13': 4,  # S5
    'SBOX14': 5,  # S6
    'SBOX15': 7,  # S8
    'SBOX16': 6,  # S7
}

def linearize_sbox(sbox_2d):
    """Convert 4x16 S-box to linear 64-entry table."""
    linear = []
    for i in range(64):
        row = ((i >> 5) << 1) | (i & 1)
        col = (i >> 1) & 0xF
        linear.append(sbox_2d[row][col])
    return linear

def count_set_bits(n):
    """Count number of 1 bits in n."""
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count

def get_bit_position(n):
    """Get the position of the single set bit (0-31). Returns -1 if not exactly one bit."""
    if count_set_bits(n) != 1:
        return -1
    pos = 0
    while (n & 1) == 0:
        n >>= 1
        pos += 1
    return pos

def extract_pbox_mapping():
    """Extract P-box by finding power-of-2 S-box outputs."""

    # P-box maps [sbox_index][output_bit] -> bit_position
    # sbox_index: 0-7 for the 8 S-boxes
    # output_bit: 0-3 for b0, b1, b2, b3
    # bit_position: 0-31 in the output word
    pbox_map = {}

    print("=" * 80)
    print("EXTRACTING P-BOX MAPPING")
    print("=" * 80)
    print()

    for fused_name in sorted(FUSED.keys()):
        des_idx = SBOX_TO_DES[fused_name]
        sbox_2d = DES_SBOXES[des_idx]
        sbox_linear = linearize_sbox(sbox_2d)
        fused_table = FUSED[fused_name]

        print(f"{fused_name} (DES S-box S{des_idx + 1}):")

        # Find power-of-2 outputs
        pbox_entries = {}
        for i in range(64):
            sbox_out = sbox_linear[i]
            fused_val = fused_table[i]

            # Check if S-box output is power of 2
            if sbox_out in [1, 2, 4, 8]:
                bit_pos = get_bit_position(fused_val)
                if bit_pos == -1:
                    print(f"  WARNING: index {i}, S-box={sbox_out}, fused={fused_val:08x} has {count_set_bits(fused_val)} bits set!")
                else:
                    # Map S-box output bit to P-box position
                    if sbox_out == 1:
                        output_bit = 0
                    elif sbox_out == 2:
                        output_bit = 1
                    elif sbox_out == 4:
                        output_bit = 2
                    else:  # 8
                        output_bit = 3

                    pbox_entries[output_bit] = bit_pos
                    print(f"  S-box index {i:2d}: output={sbox_out} (b{output_bit}) -> fused={fused_val:08x} -> bit position {bit_pos}")

        # Verify we found all 4 bits
        if len(pbox_entries) != 4:
            print(f"  ERROR: Only found {len(pbox_entries)} P-box entries, expected 4!")
        else:
            print(f"  Complete mapping: b0->bit{pbox_entries[0]}, b1->bit{pbox_entries[1]}, b2->bit{pbox_entries[2]}, b3->bit{pbox_entries[3]}")

        pbox_map[des_idx] = pbox_entries
        print()

    return pbox_map

def verify_and_build_pbox(pbox_map):
    """Verify the P-box by reconstructing fused tables and build complete P-box array."""

    print("=" * 80)
    print("VERIFYING P-BOX MAPPING")
    print("=" * 80)
    print()

    all_verified = True

    for fused_name in sorted(FUSED.keys()):
        des_idx = SBOX_TO_DES[fused_name]
        sbox_2d = DES_SBOXES[des_idx]
        sbox_linear = linearize_sbox(sbox_2d)
        fused_table = FUSED[fused_name]
        pbox_entries = pbox_map[des_idx]

        print(f"Verifying {fused_name} (S{des_idx + 1}):")

        mismatches = []
        for i in range(64):
            sbox_out = sbox_linear[i]
            expected_fused = fused_table[i]

            # Reconstruct fused value from S-box output + P-box
            reconstructed = 0
            for bit in range(4):
                if sbox_out & (1 << bit):
                    reconstructed |= (1 << pbox_entries[bit])

            if reconstructed != expected_fused:
                mismatches.append((i, sbox_out, expected_fused, reconstructed))

        if mismatches:
            print(f"  FAILED: {len(mismatches)} mismatches!")
            for i, sbox_out, expected, got in mismatches[:10]:  # Show first 10
                print(f"    Index {i}: S-box={sbox_out}, expected={expected:08x}, got={got:08x}")
            if len(mismatches) > 10:
                print(f"    ... and {len(mismatches) - 10} more")
            all_verified = False
        else:
            print(f"  VERIFIED: All 64 entries match!")
        print()

    if not all_verified:
        print("ERROR: Some tables did not verify correctly!")
        return None

    # Build complete P-box array (32 entries)
    # P-box maps output bit position (0-31) to S-box and output bit
    # We need the inverse: for each S-box output bit, where does it go?

    print("=" * 80)
    print("BUILDING COMPLETE P-BOX (32 ENTRIES)")
    print("=" * 80)
    print()

    # Each S-box contributes 4 bits to the 32-bit output
    # S1 contributes bits 0-3, S2 contributes bits 4-7, etc.
    pbox_32 = [0] * 32

    for sbox_idx in range(8):
        pbox_entries = pbox_map[sbox_idx]
        base_bit = sbox_idx * 4  # S1: 0-3, S2: 4-7, etc.

        for output_bit in range(4):
            src_bit = base_bit + output_bit
            dst_bit = pbox_entries[output_bit]
            pbox_32[dst_bit] = src_bit

    # Verify it's a valid permutation (all 0-31 appear exactly once)
    if sorted(pbox_32) != list(range(32)):
        print("ERROR: P-box is not a valid permutation!")
        print(f"Values: {pbox_32}")
        return None

    # Convert to 1-indexed like standard DES (bits numbered 1-32)
    pbox_32_1indexed = [x + 1 for x in pbox_32]

    print("P-box (0-indexed, for Rust code):")
    print("[")
    for i in range(0, 32, 8):
        print(f"    {', '.join(f'{x:2d}' for x in pbox_32[i:i+8])},")
    print("]")
    print()

    print("P-box (1-indexed, standard DES notation):")
    print("[")
    for i in range(0, 32, 8):
        print(f"    {', '.join(f'{x:2d}' for x in pbox_32_1indexed[i:i+8])},")
    print("]")
    print()

    return pbox_32

def compare_to_standard_des():
    """Compare to standard DES P-box."""

    # Standard DES P-box (1-indexed)
    STANDARD_DES_P = [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25,
    ]

    # Convert to 0-indexed
    standard_0indexed = [x - 1 for x in STANDARD_DES_P]

    print("=" * 80)
    print("STANDARD DES P-BOX (for comparison)")
    print("=" * 80)
    print()
    print("Standard DES P-box (0-indexed):")
    print("[")
    for i in range(0, 32, 8):
        print(f"    {', '.join(f'{x:2d}' for x in standard_0indexed[i:i+8])},")
    print("]")
    print()

def main():
    pbox_map = extract_pbox_mapping()
    pbox_32 = verify_and_build_pbox(pbox_map)

    if pbox_32:
        compare_to_standard_des()
        print("=" * 80)
        print("SUCCESS: Extracted and verified P-box!")
        print("=" * 80)
    else:
        print("=" * 80)
        print("FAILED: Could not extract valid P-box")
        print("=" * 80)

if __name__ == "__main__":
    main()
