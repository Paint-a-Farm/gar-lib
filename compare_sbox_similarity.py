#!/usr/bin/env python3
"""
Compare custom S-boxes to standard DES S-boxes to find similarity patterns.
"""

# Standard DES S-boxes
DES_SBOXES = [
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    # S8
    [
        [13,2,8,4,6,15,11,1,10,12,9,7,3,14,5,0],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ],
]

# Custom S-boxes extracted from gar-lib
CUSTOM_SBOXES = [
    # CUSTOM_SBOX1 (SBOX9) - matches DES S2
    [15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
     9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
     0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
     5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9],

    # CUSTOM_SBOX2 (SBOX10)
    [11, 0, 1, 15, 13, 7, 4, 1, 2, 11, 15, 2, 14, 13, 8, 4,
     6, 10, 10, 3, 3, 9, 9, 14, 5, 12, 12, 5, 0, 6, 7, 8,
     1, 15, 4, 9, 11, 8, 8, 2, 13, 1, 3, 12, 2, 4, 14, 7,
     15, 5, 9, 14, 12, 6, 7, 11, 6, 10, 10, 0, 5, 3, 0, 13],

    # CUSTOM_SBOX3 (SBOX11)
    [3, 14, 0, 13, 10, 0, 7, 10, 5, 9, 9, 4, 15, 5, 12, 3,
     8, 1, 14, 2, 6, 12, 13, 7, 11, 6, 4, 11, 1, 15, 2, 8,
     14, 8, 5, 3, 4, 14, 10, 0, 2, 5, 15, 10, 9, 2, 0, 13,
     11, 4, 8, 15, 1, 7, 6, 9, 12, 11, 3, 12, 7, 1, 13, 6],

    # CUSTOM_SBOX4 (SBOX12)
    [14, 11, 11, 1, 7, 13, 12, 10, 0, 6, 6, 15, 9, 0, 5, 12,
     8, 2, 4, 14, 1, 4, 10, 3, 13, 8, 3, 5, 2, 7, 15, 9,
     5, 12, 6, 15, 9, 0, 0, 6, 3, 5, 13, 8, 14, 11, 11, 1,
     15, 9, 8, 2, 12, 10, 7, 13, 10, 3, 4, 14, 1, 4, 2, 7],

    # CUSTOM_SBOX5 (SBOX13)
    [1, 7, 6, 13, 2, 1, 8, 6, 11, 2, 5, 11, 13, 14, 3, 8,
     4, 10, 10, 0, 9, 15, 15, 5, 14, 9, 0, 12, 7, 4, 12, 3,
     2, 13, 1, 4, 8, 6, 13, 11, 5, 8, 14, 7, 11, 1, 4, 14,
     15, 3, 12, 15, 6, 0, 10, 12, 3, 5, 9, 2, 0, 10, 7, 9],

    # CUSTOM_SBOX6 (SBOX14)
    [9, 12, 2, 15, 12, 1, 15, 4, 10, 7, 4, 9, 5, 10, 8, 3,
     0, 5, 11, 2, 6, 11, 1, 13, 13, 0, 7, 14, 3, 6, 14, 8,
     10, 1, 13, 6, 15, 4, 3, 9, 4, 10, 8, 3, 9, 15, 6, 12,
     7, 14, 0, 13, 1, 2, 12, 7, 2, 5, 11, 0, 14, 8, 5, 11],

    # CUSTOM_SBOX7 (SBOX15)
    [13, 4, 2, 15, 1, 13, 8, 1, 10, 3, 15, 6, 7, 14, 4, 8,
     3, 9, 5, 12, 6, 10, 11, 7, 12, 0, 0, 11, 9, 5, 14, 2,
     14, 2, 7, 4, 8, 11, 4, 14, 5, 8, 9, 3, 11, 1, 2, 13,
     0, 15, 10, 9, 3, 5, 13, 0, 15, 6, 6, 12, 12, 10, 1, 7],

    # CUSTOM_SBOX8 (SBOX16)
    [8, 13, 7, 0, 2, 7, 14, 11, 15, 8, 0, 5, 4, 1, 13, 6,
     3, 14, 12, 3, 5, 9, 11, 12, 9, 2, 6, 15, 10, 4, 1, 10,
     1, 10, 8, 7, 7, 13, 13, 4, 12, 1, 3, 8, 11, 6, 14, 11,
     6, 5, 15, 9, 10, 0, 4, 15, 0, 14, 9, 2, 5, 3, 2, 12],
]


def flatten_sbox(sbox):
    """Flatten a 4x16 DES S-box to 64 entries."""
    result = []
    for row in sbox:
        result.extend(row)
    return result


def get_sbox_value_standard(sbox, index):
    """Standard DES S-box indexing."""
    row = ((index >> 5) & 1) << 1 | (index & 1)
    col = (index >> 1) & 0xF
    return sbox[row][col]


def standard_indexed_sbox(sbox):
    """Convert a 4x16 S-box to 64-entry array with standard indexing."""
    return [get_sbox_value_standard(sbox, i) for i in range(64)]


def hamming_distance(sbox1, sbox2):
    """Count how many positions differ between two S-boxes."""
    return sum(1 for a, b in zip(sbox1, sbox2) if a != b)


def analyze_similarity():
    """Analyze similarity between custom and standard DES S-boxes."""
    print("=" * 80)
    print("S-Box Similarity Analysis")
    print("=" * 80)

    # Convert standard DES S-boxes to 64-entry arrays
    des_flat = [standard_indexed_sbox(sbox) for sbox in DES_SBOXES]

    for custom_num, custom_sbox in enumerate(CUSTOM_SBOXES):
        print(f"\nCUSTOM_SBOX{custom_num + 1} (from SBOX{custom_num + 9}):")

        # Find closest matches
        similarities = []
        for des_num, des_sbox in enumerate(des_flat):
            dist = hamming_distance(custom_sbox, des_sbox)
            similarity_pct = (64 - dist) / 64 * 100
            similarities.append((des_num + 1, dist, similarity_pct))

        # Sort by distance (ascending)
        similarities.sort(key=lambda x: x[1])

        print("  Closest matches:")
        for des_num, dist, similarity_pct in similarities[:3]:
            match_str = " *** EXACT MATCH ***" if dist == 0 else ""
            print(f"    DES S{des_num}: {dist:2d} differences ({similarity_pct:5.1f}% similar){match_str}")

        # Show least similar too
        print("  Most different:")
        for des_num, dist, similarity_pct in similarities[-2:]:
            print(f"    DES S{des_num}: {dist:2d} differences ({similarity_pct:5.1f}% similar)")


def analyze_value_distribution():
    """Analyze the distribution of output values in each S-box."""
    print("\n" + "=" * 80)
    print("Value Distribution Analysis (0-15 counts)")
    print("=" * 80)

    def count_values(sbox):
        counts = [0] * 16
        for val in sbox:
            counts[val] += 1
        return counts

    print("\nStandard DES S-boxes:")
    for i, sbox in enumerate([standard_indexed_sbox(s) for s in DES_SBOXES]):
        counts = count_values(sbox)
        print(f"  S{i+1}: {counts}")

    print("\nCustom S-boxes:")
    for i, sbox in enumerate(CUSTOM_SBOXES):
        counts = count_values(sbox)
        print(f"  CUSTOM{i+1}: {counts}")


def main():
    analyze_similarity()
    analyze_value_distribution()

    print("\n" + "=" * 80)
    print("Analysis Complete")
    print("=" * 80)


if __name__ == "__main__":
    main()
