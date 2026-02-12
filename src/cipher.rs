//! GAR Cipher implementation
//!
//! DES-variant Feistel cipher with custom S-box ordering and P-box.
//! Uses standard DES Initial/Final Permutation (bit de-interleaving),
//! standard DES E-box expansion, standard DES S-boxes (FIPS 46-3),
//! and a custom P-box permutation.
//!
//! Block scheduling: 34-block cycle with 1-16 Feistel rounds per block,
//! alternating RC4 XOR on even-numbered blocks.

use crate::tables::*;

/// DES PC-1 permutation table (64 -> 56 bits)
const DES_PC1: [u8; 56] = [
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
];

/// DES PC-2 permutation table (56 -> 48 bits)
const DES_PC2: [u8; 48] = [
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
];

/// DES left rotation counts per round
const DES_ROTATIONS: [u8; 16] = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

/// Derive subkeys and RC4 S-box from 4 encryption keys.
///
/// - DES subkeys: Standard DES key schedule from k1||k2 (64 bits) → 32 packed u32s
/// - RC4 S-box: Standard RC4 KSA with key = k3||k4||k1||k2 (16 bytes)
pub fn derive_keys(k1: u32, k2: u32, k3: u32, k4: u32) -> ([u32; 32], [u8; 256]) {
    // RC4 KSA with key = k3||k4||k1||k2
    let key_sched: [u8; 16] = [
        (k3 & 0xFF) as u8, ((k3 >> 8) & 0xFF) as u8, ((k3 >> 16) & 0xFF) as u8, ((k3 >> 24) & 0xFF) as u8,
        (k4 & 0xFF) as u8, ((k4 >> 8) & 0xFF) as u8, ((k4 >> 16) & 0xFF) as u8, ((k4 >> 24) & 0xFF) as u8,
        (k1 & 0xFF) as u8, ((k1 >> 8) & 0xFF) as u8, ((k1 >> 16) & 0xFF) as u8, ((k1 >> 24) & 0xFF) as u8,
        (k2 & 0xFF) as u8, ((k2 >> 8) & 0xFF) as u8, ((k2 >> 16) & 0xFF) as u8, ((k2 >> 24) & 0xFF) as u8,
    ];

    let mut rc4_sbox: [u8; 256] = [0; 256];
    for i in 0..256 {
        rc4_sbox[i] = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(rc4_sbox[i]).wrapping_add(key_sched[i % 16]);
        rc4_sbox.swap(i, j as usize);
    }

    // DES key schedule from k1||k2
    let key_64: [u8; 8] = [
        (k1 & 0xFF) as u8, ((k1 >> 8) & 0xFF) as u8, ((k1 >> 16) & 0xFF) as u8, ((k1 >> 24) & 0xFF) as u8,
        (k2 & 0xFF) as u8, ((k2 >> 8) & 0xFF) as u8, ((k2 >> 16) & 0xFF) as u8, ((k2 >> 24) & 0xFF) as u8,
    ];

    let get_bit = |bit_num: u8| -> u8 {
        let byte_idx = (bit_num - 1) / 8;
        let bit_idx = 7 - ((bit_num - 1) % 8);
        (key_64[byte_idx as usize] >> bit_idx) & 1
    };

    // PC-1: 64 → 56 bits
    let mut cd: u64 = 0;
    for &pos in &DES_PC1 {
        cd = (cd << 1) | (get_bit(pos) as u64);
    }
    let mut c = (cd >> 28) as u32 & 0x0FFFFFFF;
    let mut d = cd as u32 & 0x0FFFFFFF;

    let mut subkeys: [u32; 32] = [0; 32];

    for round in 0..16 {
        let rot = DES_ROTATIONS[round] as u32;
        c = ((c << rot) | (c >> (28 - rot))) & 0x0FFFFFFF;
        d = ((d << rot) | (d >> (28 - rot))) & 0x0FFFFFFF;

        let cd_combined = ((c as u64) << 28) | (d as u64);
        let get_cd_bit = |pos: u8| -> u8 {
            ((cd_combined >> (56 - pos)) & 1) as u8
        };

        // PC-2: 56 → 48 bits = 8 x 6-bit values
        let mut six_bits: [u8; 8] = [0; 8];
        for i in 0..48 {
            let bit = get_cd_bit(DES_PC2[i]);
            six_bits[i / 6] = (six_bits[i / 6] << 1) | bit;
        }

        // Pack into 2 u32s: [v0,v1,v2,v3] and [v4,v5,v6,v7]
        subkeys[round * 2] = (six_bits[0] as u32) << 24
                           | (six_bits[1] as u32) << 16
                           | (six_bits[2] as u32) << 8
                           | (six_bits[3] as u32);
        subkeys[round * 2 + 1] = (six_bits[4] as u32) << 24
                               | (six_bits[5] as u32) << 16
                               | (six_bits[6] as u32) << 8
                               | (six_bits[7] as u32);
    }

    (subkeys, rc4_sbox)
}

/// Initial Permutation: split 8-byte block into two 32-bit halves.
///
/// Bit de-interleaving using SBOX7 as a bit-spread lookup table.
/// Returns (even_half, odd_half) where:
/// - even_half: bits at positions 0, 2, 4, 6 of each byte
/// - odd_half:  bits at positions 1, 3, 5, 7 of each byte
pub fn initial_permutation(block: &[u8]) -> (u32, u32) {
    let b0 = block[0] as usize;
    let b1 = block[1] as usize;
    let b2 = block[2] as usize;
    let b3 = block[3] as usize;
    let b4 = block[4] as usize;
    let b5 = block[5] as usize;
    let b6 = block[6] as usize;
    let b7 = block[7] as usize;

    // Even-positioned bits (0, 2, 4, 6) — Feistel F input
    let mut even = SBOX7[b7 & 0x55];
    even = (even << 1) | SBOX7[b6 & 0x55];
    even = (even << 1) | SBOX7[b5 & 0x55];
    even = (even << 1) | SBOX7[b4 & 0x55];
    even = (even << 1) | SBOX7[b3 & 0x55];
    even = (even << 1) | SBOX7[b2 & 0x55];
    even = (even << 1) | SBOX7[b1 & 0x55];
    even = (even << 1) | SBOX7[b0 & 0x55];

    // Odd-positioned bits (1, 3, 5, 7) — Feistel XOR target
    let mut odd = SBOX7[(b7 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b6 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b5 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b4 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b3 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b2 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b1 >> 1) & 0x55];
    odd = (odd << 1) | SBOX7[(b0 >> 1) & 0x55];

    (even, odd)
}

/// Final Permutation: re-interleave (L, R) halves back to 8 bytes.
///
/// Uses SBOX8 as a nibble-to-byte spread table.
pub fn final_permutation(l: u32, r: u32) -> [u8; 8] {
    let mut out_ecx: u32 = 0;
    let mut out_eax: u32 = 0;

    for shift in [24i32, 16, 8, 0] {
        out_ecx = out_ecx << 1;
        out_ecx |= SBOX8[((l >> shift) & 0xF) as usize];
        out_ecx = out_ecx << 1;
        out_ecx |= SBOX8[((r >> shift) & 0xF) as usize];
    }

    for shift in [28i32, 20, 12, 4] {
        out_eax = out_eax << 1;
        out_eax |= SBOX8[((l >> shift) & 0xF) as usize];
        out_eax = out_eax << 1;
        out_eax |= SBOX8[((r >> shift) & 0xF) as usize];
    }

    [
        (out_ecx >> 24) as u8,
        (out_ecx >> 16) as u8,
        (out_ecx >> 8) as u8,
        out_ecx as u8,
        (out_eax >> 24) as u8,
        (out_eax >> 16) as u8,
        (out_eax >> 8) as u8,
        out_eax as u8,
    ]
}

/// GAR cipher for decryption
#[derive(Debug)]
pub struct GarCipher {
    subkeys: [u32; 32],
    rc4_sbox_template: [u8; 256],
}

impl GarCipher {
    /// Create cipher with default FS15-25 keys (most common for modern .gar files)
    pub fn new() -> Self {
        let (k1, k2, k3, k4) = KEYS_FS15_25;
        Self::from_keys(k1, k2, k3, k4)
    }

    /// Create cipher by deriving subkeys and S-box from raw k1, k2, k3, k4 values
    pub fn from_keys(k1: u32, k2: u32, k3: u32, k4: u32) -> Self {
        let (subkeys, rc4_sbox) = derive_keys(k1, k2, k3, k4);
        Self {
            subkeys,
            rc4_sbox_template: rc4_sbox,
        }
    }

    /// Access the 32 DES subkeys (16 rounds x 2 packed u32s each)
    pub fn subkeys(&self) -> &[u32; 32] {
        &self.subkeys
    }

    /// Get a copy of the RC4 S-box template (initial state before PRGA)
    pub fn rc4_sbox_template(&self) -> [u8; 256] {
        self.rc4_sbox_template
    }

    /// Single Feistel round: E-box expand R, XOR with subkey pair, S+P lookup.
    ///
    /// Standard DES E-box expansion (32 → 48 bits), split across two subkey words.
    /// The ROR-15 is an implementation optimization for the E-box bit extraction.
    /// Returns the Feistel round output to be XORed with L.
    pub fn feistel_round(&self, r: u32, ka: u32, kb: u32) -> u32 {
        let r_rot = r.rotate_right(15);

        // E-box expansion + S-box lookup via ka (S-boxes in slots 0-3)
        let idx9  = (((ka >> 12) ^ r_rot) >> 12) & 0x3F;
        let idx10 = (((ka >> 8) ^ r_rot) >> 8) & 0x3F;
        let idx11 = (((ka >> 4) ^ r_rot) >> 4) & 0x3F;
        let idx12 = (ka ^ r_rot) & 0x3F;
        let sp_a = SBOX9[idx9 as usize]
                 | SBOX10[idx10 as usize]
                 | SBOX11[idx11 as usize]
                 | SBOX12[idx12 as usize];

        // E-box expansion + S-box lookup via kb (S-boxes in slots 4-7)
        let idx13 = (((kb >> 13) ^ r) >> 11) & 0x3F;
        let idx14 = (((kb >> 9) ^ r) >> 7) & 0x3F;
        let idx15 = (((kb >> 5) ^ r) >> 3) & 0x3F;
        let idx16 = ((r_rot >> 16) ^ kb) & 0x3F;
        let sp_b = SBOX13[idx13 as usize]
                 | SBOX14[idx14 as usize]
                 | SBOX15[idx15 as usize]
                 | SBOX16[idx16 as usize];

        sp_a | sp_b
    }

    /// Generate 8 bytes of RC4 keystream using custom RC4 variant.
    ///
    /// NOT standard RC4 PRGA: first 4 bytes use i=1..4 with normal j accumulation,
    /// second 4 bytes reset j to sbox[1] and restart i at 1.
    pub fn rc4_keystream_8bytes(&self, state: &mut [u8; 256]) -> [u8; 8] {
        let mut result = [0u8; 8];

        // First 4 bytes: i=1..4, j accumulates
        let mut j: u8 = 0;
        for i in 1u8..=4 {
            j = j.wrapping_add(state[i as usize]);
            state.swap(i as usize, j as usize);
            let k_idx = state[i as usize].wrapping_add(state[j as usize]);
            result[(i - 1) as usize] = state[k_idx as usize];
        }

        // Second 4 bytes: j resets to state[1], i restarts at 1
        j = state[1];
        for i in 1u8..=4 {
            if i > 1 {
                j = j.wrapping_add(state[i as usize]);
            }
            state.swap(i as usize, j as usize);
            let k_idx = state[i as usize].wrapping_add(state[j as usize]);
            result[(i + 3) as usize] = state[k_idx as usize];
        }

        result
    }

    /// Process a single 8-byte block through the Feistel cipher.
    ///
    /// - `num_rounds`: number of Feistel rounds (0 for IP-only pass-through)
    /// - `subkey_pairs`: slice of (ka, kb) pairs, applied in order
    /// - `rc4_state`: if Some, XOR with RC4 keystream after Feistel rounds
    fn process_block(
        &self,
        block: &[u8],
        num_rounds: usize,
        subkey_pairs: &[(u32, u32)],
        rc4_state: Option<&mut [u8; 256]>,
    ) -> [u8; 8] {
        let (even, odd) = initial_permutation(block);

        // Feistel network: F operates on `b` (odd half), XOR into `a` (even half).
        // No final swap — (a, b) after all rounds is already in correct FP order.
        //   0 rounds: (even, odd) → FP(even, odd) ✓
        //   1 round:  (odd, even^F) → FP(odd, even^F) ✓
        //   N rounds: correct by induction ✓
        let mut a = even;
        let mut b = odd;

        for i in 0..num_rounds {
            let (ka, kb) = subkey_pairs[i];
            let f_out = self.feistel_round(b, ka, kb);
            let next = a ^ f_out;
            a = b;
            b = next;
        }

        // Optional RC4 XOR
        let (mut fp1, mut fp2) = (a, b);
        if let Some(state) = rc4_state {
            let ks = self.rc4_keystream_8bytes(state);
            let ks_d1 = u32::from_le_bytes([ks[0], ks[1], ks[2], ks[3]]);
            let ks_d2 = u32::from_le_bytes([ks[4], ks[5], ks[6], ks[7]]);
            fp1 ^= ks_d2;
            fp2 ^= ks_d1;
        }

        final_permutation(fp1, fp2)
    }

    /// Build the subkey pair schedule for a given block number.
    ///
    /// Returns (num_rounds, subkey_pairs) where subkey_pairs are ordered
    /// from highest key index down to [0,1].
    fn block_subkey_schedule(&self, block_num: usize) -> (usize, Vec<(u32, u32)>) {
        let num_rounds = (block_num + 1) / 2; // block 2→1, 3-4→2, 5-6→3, etc.
        let start_key_idx = 2 * (num_rounds - 1);

        let mut pairs = Vec::with_capacity(num_rounds);
        for phase in 0..num_rounds {
            let key_idx = start_key_idx - 2 * phase;
            pairs.push((self.subkeys[key_idx], self.subkeys[key_idx + 1]));
        }

        (num_rounds, pairs)
    }

    /// Decrypt data using the full multi-block cipher.
    /// Decrypts all blocks including the last one.
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt_internal(data, true)
    }

    /// Decrypt data for DLC files — same as decrypt.
    pub fn decrypt_dlc(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt_internal(data, true)
    }

    /// Internal decrypt with option to skip last block.
    ///
    /// 34-block cycle:
    ///   pos 0:       block 1 (1 round, keys[0,1], no RC4)
    ///   pos 1-31:    blocks 2-32 (ceil(N/2) rounds, keys descending, RC4 on even N)
    ///   pos 32:      ESI1 — IP-only pass-through (0 rounds, no RC4)
    ///   pos 33:      ESI3 — IP-only with RC4 (0 rounds, RC4)
    ///   pos 34:      block 1 again (new cycle)
    fn decrypt_internal(&self, data: &[u8], decrypt_last_block: bool) -> Vec<u8> {
        assert!(data.len() % 8 == 0, "Data length must be multiple of 8");

        let num_blocks = data.len() / 8;
        if num_blocks == 0 {
            return vec![];
        }
        if num_blocks == 1 {
            return vec![0u8; 8];
        }

        let mut result = Vec::with_capacity(data.len());
        let mut rc4_state = self.rc4_sbox_template;

        let last_pos = if num_blocks == 32 || decrypt_last_block {
            num_blocks
        } else {
            num_blocks - 1
        };

        for pos in 0..last_pos {
            let block = &data[pos * 8..(pos + 1) * 8];

            let decrypted = if pos == 0 {
                // Block 1: 1 round, subkeys[0,1], no RC4
                let pairs = [(self.subkeys[0], self.subkeys[1])];
                self.process_block(block, 1, &pairs, None)
            } else {
                let pos_in_cycle = (pos - 1) % 34;

                if pos_in_cycle < 31 {
                    // Blocks 2-32
                    let block_num = pos_in_cycle + 2;
                    let (num_rounds, pairs) = self.block_subkey_schedule(block_num);
                    let use_rc4 = block_num % 2 == 0;

                    if use_rc4 {
                        self.process_block(block, num_rounds, &pairs, Some(&mut rc4_state))
                    } else {
                        self.process_block(block, num_rounds, &pairs, None)
                    }
                } else if pos_in_cycle == 31 {
                    // ESI1: IP-only, no RC4
                    self.process_block(block, 0, &[], None)
                } else if pos_in_cycle == 32 {
                    // ESI3: IP-only, with RC4
                    self.process_block(block, 0, &[], Some(&mut rc4_state))
                } else {
                    // pos_in_cycle == 33: block 1 again
                    let pairs = [(self.subkeys[0], self.subkeys[1])];
                    self.process_block(block, 1, &pairs, None)
                }
            };

            result.extend_from_slice(&decrypted);
        }

        // Zero padding for non-DLC when not decrypting last block
        if num_blocks != 32 && !decrypt_last_block {
            result.extend_from_slice(&[0u8; 8]);
        }

        result
    }
}

impl Default for GarCipher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_blocks_1_to_5() {
        let cipher = GarCipher::new();

        // Ciphertexts from /tmp/gar_test.gar (encrypts zeros)
        let blocks: [[u8; 8]; 5] = [
            [0x14, 0x51, 0x14, 0x15, 0x55, 0x41, 0x41, 0x10], // Block 1
            [0x38, 0xf4, 0x92, 0xa2, 0x7f, 0x9b, 0xb8, 0x43], // Block 2
            [0x39, 0xf7, 0x29, 0x7f, 0xbf, 0x97, 0x97, 0x34], // Block 3
            [0x69, 0x67, 0xfc, 0x76, 0x1f, 0x55, 0x18, 0x00], // Block 4
            [0x33, 0xbf, 0x03, 0xab, 0x6f, 0x3f, 0x3b, 0x3d], // Block 5
        ];

        // Full-stream decrypt (all 5 blocks = 40 bytes)
        let mut input = Vec::new();
        for block in &blocks {
            input.extend_from_slice(block);
        }
        let result = cipher.decrypt(&input);

        for i in 0..5 {
            assert_eq!(
                &result[i * 8..(i + 1) * 8],
                &[0u8; 8],
                "Block {} should decrypt to zeros",
                i + 1
            );
        }
    }

    #[test]
    fn test_block2_decryption() {
        // Block 2 standalone: need block 1 first to advance stream position
        let cipher = GarCipher::new();

        // Two blocks: block 1 (dummy) + block 2 (the one we care about)
        let block1 = [0x14u8, 0x51, 0x14, 0x15, 0x55, 0x41, 0x41, 0x10];
        let block2 = [0x18u8, 0xf4, 0x82, 0xa2, 0x7b, 0xdb, 0xb9, 0x43];

        let mut input = Vec::new();
        input.extend_from_slice(&block1);
        input.extend_from_slice(&block2);
        let result = cipher.decrypt(&input);

        assert_eq!(&result[8..16], &[0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_block3_decryption() {
        let cipher = GarCipher::new();

        // Need blocks 1-2 first, then block 3
        let block1 = [0x14u8, 0x51, 0x14, 0x15, 0x55, 0x41, 0x41, 0x10];
        let block2 = [0x38u8, 0xf4, 0x92, 0xa2, 0x7f, 0x9b, 0xb8, 0x43];
        let block3 = [0x5eu8, 0xc2, 0x28, 0xff, 0xaf, 0x97, 0x47, 0x08];

        let mut input = Vec::new();
        input.extend_from_slice(&block1);
        input.extend_from_slice(&block2);
        input.extend_from_slice(&block3);
        let result = cipher.decrypt(&input);

        assert_eq!(&result[16..24], &[0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}

#[cfg(test)]
mod derive_keys_tests {
    use super::*;
    use crate::tables::KEYS_FS15_25;

    #[test]
    fn test_derive_keys_fs15_25() {
        let (k1, k2, k3, k4) = KEYS_FS15_25;
        let (derived_subkeys, derived_sbox) = derive_keys(k1, k2, k3, k4);

        // S-box must be a valid permutation
        let mut seen = [false; 256];
        for &b in &derived_sbox {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&x| x), "S-box should be a valid permutation");
        assert!(derived_subkeys.iter().any(|&k| k != 0), "Subkeys should not be all zeros");
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let (k1, k2, k3, k4) = KEYS_FS15_25;
        let (subkeys1, sbox1) = derive_keys(k1, k2, k3, k4);
        let (subkeys2, sbox2) = derive_keys(k1, k2, k3, k4);

        assert_eq!(subkeys1, subkeys2, "Subkeys should be deterministic");
        assert_eq!(sbox1, sbox2, "S-box should be deterministic");
    }

    #[test]
    fn test_from_keys_decryption() {
        let (k1, k2, k3, k4) = KEYS_FS15_25;
        let cipher = GarCipher::from_keys(k1, k2, k3, k4);

        let blocks: [[u8; 8]; 3] = [
            [0x14, 0x51, 0x14, 0x15, 0x55, 0x41, 0x41, 0x10],
            [0x38, 0xf4, 0x92, 0xa2, 0x7f, 0x9b, 0xb8, 0x43],
            [0x39, 0xf7, 0x29, 0x7f, 0xbf, 0x97, 0x97, 0x34],
        ];

        let mut input = Vec::new();
        for block in &blocks {
            input.extend_from_slice(block);
        }

        let result = cipher.decrypt(&input);

        assert_eq!(&result[0..8], &[0u8; 8], "Block 1 should decrypt to zeros");
        assert_eq!(&result[8..16], &[0u8; 8], "Block 2 should decrypt to zeros");
        assert_eq!(&result[16..24], &[0u8; 8], "Block 3 should decrypt to zeros");
    }
}

#[cfg(test)]
mod fs13b_tests {
    use super::*;
    use crate::tables::KEYS_FS13_B;

    #[test]
    fn test_fs13b_first_entry() {
        let (k1, k2, k3, k4) = KEYS_FS13_B;
        let cipher = GarCipher::from_keys(k1, k2, k3, k4);

        let encrypted: [u8; 24] = [
            0x15, 0x45, 0x14, 0x10, 0x50, 0x11, 0x45, 0x04,
            0x09, 0xef, 0x6b, 0xd0, 0x3d, 0xb4, 0xcd, 0x91,
            0xc9, 0x99, 0x39, 0x2b, 0xe0, 0x53, 0x0b, 0x45,
        ];

        let result = cipher.decrypt(&encrypted);

        let expected: [u8; 24] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x58, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x52, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(result, expected, "Should match Unicorn output");
    }
}

