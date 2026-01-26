//! GAR Cipher decryption implementation
//!
//! This implements the defarm cipher used in Farming Simulator GAR archives.
//! Ported from native_cipher_full.py

use crate::tables::*;

/// Rotate right by n bits (32-bit)
#[inline]
fn ror32(val: u32, n: u32) -> u32 {
    val.rotate_right(n)
}

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
/// Key derivation:
/// - RC4 S-box: Standard RC4 KSA with key = k3||k4||k1||k2 (16 bytes)
/// - DES subkeys: Standard DES key schedule from k1||k2 (64 bits)
pub fn derive_keys(k1: u32, k2: u32, k3: u32, k4: u32) -> ([u32; 32], [u8; 256]) {
    // RC4 S-box initialization
    // Key schedule is k3||k4||k1||k2 (little-endian)
    let key_sched: [u8; 16] = [
        (k3 & 0xFF) as u8, ((k3 >> 8) & 0xFF) as u8, ((k3 >> 16) & 0xFF) as u8, ((k3 >> 24) & 0xFF) as u8,
        (k4 & 0xFF) as u8, ((k4 >> 8) & 0xFF) as u8, ((k4 >> 16) & 0xFF) as u8, ((k4 >> 24) & 0xFF) as u8,
        (k1 & 0xFF) as u8, ((k1 >> 8) & 0xFF) as u8, ((k1 >> 16) & 0xFF) as u8, ((k1 >> 24) & 0xFF) as u8,
        (k2 & 0xFF) as u8, ((k2 >> 8) & 0xFF) as u8, ((k2 >> 16) & 0xFF) as u8, ((k2 >> 24) & 0xFF) as u8,
    ];

    // RC4 KSA
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

    // Helper to get a bit (1-indexed like DES spec)
    let get_bit = |bit_num: u8| -> u8 {
        let byte_idx = (bit_num - 1) / 8;
        let bit_idx = 7 - ((bit_num - 1) % 8);
        (key_64[byte_idx as usize] >> bit_idx) & 1
    };

    // PC-1 permutation (64 -> 56 bits)
    let mut cd: u64 = 0;
    for &pos in &DES_PC1 {
        cd = (cd << 1) | (get_bit(pos) as u64);
    }
    let mut c = (cd >> 28) as u32 & 0x0FFFFFFF;
    let mut d = cd as u32 & 0x0FFFFFFF;

    let mut subkeys: [u32; 32] = [0; 32];

    for round in 0..16 {
        // Left rotate C and D
        let rot = DES_ROTATIONS[round] as u32;
        c = ((c << rot) | (c >> (28 - rot))) & 0x0FFFFFFF;
        d = ((d << rot) | (d >> (28 - rot))) & 0x0FFFFFFF;

        // Combine for PC-2 permutation
        let cd_combined = ((c as u64) << 28) | (d as u64);

        // Helper to get bit from combined CD
        let get_cd_bit = |pos: u8| -> u8 {
            ((cd_combined >> (56 - pos)) & 1) as u8
        };

        // PC-2 permutation (56 -> 48 bits = 8 x 6-bit values)
        let mut six_bits: [u8; 8] = [0; 8];
        for i in 0..48 {
            let bit = get_cd_bit(DES_PC2[i]);
            six_bits[i / 6] = (six_bits[i / 6] << 1) | bit;
        }

        // Pack into 2 u32s: [v3,v2,v1,v0] and [v7,v6,v5,v4]
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

    /// Convenience accessors for first 4 subkeys (k1-k4)
    #[inline]
    fn k1(&self) -> u32 { self.subkeys[0] }
    #[inline]
    fn k2(&self) -> u32 { self.subkeys[1] }
    #[inline]
    fn k3(&self) -> u32 { self.subkeys[2] }
    #[inline]
    fn k4(&self) -> u32 { self.subkeys[3] }

    /// Process 8 input bytes through sbox7. Common to ALL blocks.
    /// Returns (edx_stored, esi)
    fn process_input(&self, block: &[u8]) -> (u32, u32) {
        let b7 = block[7] as usize;
        let ecx = SBOX7[(b7 >> 1) & 0x55];
        let mut esi = SBOX7[b7 & 0x55];

        let b6 = block[6] as usize;
        esi = (esi << 1) | SBOX7[b6 & 0x55];
        let edi = (ecx << 1) | SBOX7[(b6 >> 1) & 0x55];

        let b5 = block[5] as usize;
        let mut edx = esi << 1;
        esi = (edi << 1) | SBOX7[(b5 >> 1) & 0x55];

        let b4 = block[4] as usize;
        esi = (esi << 1) | SBOX7[(b4 >> 1) & 0x55];
        edx = edx | SBOX7[b5 & 0x55];
        edx = (edx << 1) | SBOX7[b4 & 0x55];

        let b3 = block[3] as usize;
        esi = (esi << 1) | SBOX7[(b3 >> 1) & 0x55];
        edx = (edx << 1) | SBOX7[b3 & 0x55];

        let b2 = block[2] as usize;
        esi = (esi << 1) | SBOX7[(b2 >> 1) & 0x55];
        edx = (edx << 1) | SBOX7[b2 & 0x55];

        let b1 = block[1] as usize;
        edx = (edx << 1) | SBOX7[b1 & 0x55];

        let b0 = block[0] as usize;
        let edx_stored = edx;
        edx = (esi << 1) | SBOX7[(b1 >> 1) & 0x55];
        esi = (edx << 1) | SBOX7[(b0 >> 1) & 0x55];

        (edx_stored, esi)
    }

    /// Process 8 input bytes for ESI=1 (cycle reset block).
    /// Returns (esi, edi)
    fn process_input_esi1(&self, block: &[u8]) -> (u32, u32) {
        let b7 = block[7] as usize;
        let b6 = block[6] as usize;
        let b5 = block[5] as usize;
        let b4 = block[4] as usize;
        let b3 = block[3] as usize;
        let b2 = block[2] as usize;
        let b1 = block[1] as usize;
        let b0 = block[0] as usize;

        let ecx = SBOX7[(b7 >> 1) & 0x55];
        let mut esi = SBOX7[b7 & 0x55];

        esi = (esi << 1) | SBOX7[b6 & 0x55];
        let mut edi = (ecx << 1) | SBOX7[(b6 >> 1) & 0x55];

        edi = (edi << 1) | SBOX7[(b5 >> 1) & 0x55];
        edi = edi << 1;
        esi = (esi << 1) | SBOX7[b5 & 0x55];
        edi = edi | SBOX7[(b4 >> 1) & 0x55];

        esi = (esi << 1) | SBOX7[b4 & 0x55];
        edi = (edi << 1) | SBOX7[(b3 >> 1) & 0x55];

        esi = (esi << 1) | SBOX7[b3 & 0x55];
        edi = (edi << 1) | SBOX7[(b2 >> 1) & 0x55];

        esi = (esi << 1) | SBOX7[b2 & 0x55];
        edi = (edi << 1) | SBOX7[(b1 >> 1) & 0x55];

        esi = (esi << 1) | SBOX7[b1 & 0x55];
        edi = (edi << 1) | SBOX7[(b0 >> 1) & 0x55];

        // ESI=1 completes this final phase
        esi = (esi << 1) | SBOX7[b0 & 0x55];

        (esi, edi)
    }

    /// Generate 8 output bytes from ESI and EDI. Common to all blocks.
    fn generate_output(&self, esi: u32, edi: u32) -> [u8; 8] {
        let mut out_ecx: u32 = 0;
        let mut out_eax: u32 = 0;

        for shift in [24i32, 16, 8, 0] {
            out_ecx = out_ecx << 1;
            out_ecx |= SBOX8[((esi >> shift) & 0xF) as usize];
            out_ecx = out_ecx << 1;
            out_ecx |= SBOX8[((edi >> shift) & 0xF) as usize];
        }

        for shift in [28i32, 20, 12, 4] {
            out_eax = out_eax << 1;
            out_eax |= SBOX8[((esi >> shift) & 0xF) as usize];
            out_eax = out_eax << 1;
            out_eax |= SBOX8[((edi >> shift) & 0xF) as usize];
        }

        // Big-endian pack
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

    /// Generate 8 bytes of RC4 keystream using custom RC4 variant
    fn rc4_keystream_8bytes(&self, sbox: &mut [u8; 256]) -> [u8; 8] {
        let mut result = [0u8; 8];

        // First 4 bytes
        let mut j: u8 = 0;
        for i in 1u8..=4 {
            j = j.wrapping_add(sbox[i as usize]);
            sbox.swap(i as usize, j as usize);
            let k_idx = sbox[i as usize].wrapping_add(sbox[j as usize]);
            result[(i - 1) as usize] = sbox[k_idx as usize];
        }

        // Second 4 bytes
        j = sbox[1];
        for i in 1u8..=4 {
            if i > 1 {
                j = j.wrapping_add(sbox[i as usize]);
            }
            sbox.swap(i as usize, j as usize);
            let k_idx = sbox[i as usize].wrapping_add(sbox[j as usize]);
            result[(i + 3) as usize] = sbox[k_idx as usize];
        }

        result
    }

    /// Block 1 transform - uses k1/k2
    /// Returns edx_final (the transformed value to pair with original esi)
    fn transform_block1(&self, stored_edx: u32, esi: u32, block: &[u8]) -> u32 {
        let eax_r = ror32(esi, 0xF);

        // S-box 9-12 with k1
        let idx9 = (((self.k1() >> 12) ^ eax_r) >> 12) & 0x3F;
        let idx10 = (((self.k1() >> 8) ^ eax_r) >> 8) & 0x3F;
        let idx11 = (((self.k1() >> 4) ^ eax_r) >> 4) & 0x3F;
        let idx12 = (self.k1() ^ eax_r) & 0x3F;
        let val9 = SBOX9[idx9 as usize];
        let val10 = SBOX10[idx10 as usize];
        let val11 = SBOX11[idx11 as usize];
        let val12 = SBOX12[idx12 as usize];

        // S-box 13-16 with k2
        let idx13 = (((self.k2() >> 13) ^ esi) >> 11) & 0x3F;
        let idx14 = (((self.k2() >> 9) ^ esi) >> 7) & 0x3F;
        let idx15 = (((self.k2() >> 5) ^ esi) >> 3) & 0x3F;
        let idx16 = ((eax_r >> 16) ^ self.k2()) & 0x3F;
        let val13 = SBOX13[idx13 as usize];
        let val14 = SBOX14[idx14 as usize];
        let val15 = SBOX15[idx15 as usize];
        let val16 = SBOX16[idx16 as usize];

        let ecx_combined = val9 | val10 | val11 | val12;
        let edx_combined = val13 | val14 | val15 | val16;

        let b0_val = SBOX7[block[0] as usize & 0x55];
        let eax_final = (stored_edx << 1) | b0_val;

        // Return edx = eax_final ^ edx_combined ^ ecx_combined
        eax_final ^ edx_combined ^ ecx_combined
    }

    /// Decrypt block 1 in multi-block context
    fn decrypt_block1_multiblock(&self, block: &[u8]) -> [u8; 8] {
        let (edx_stored, esi) = self.process_input(block);
        let edx = self.transform_block1(edx_stored, esi, block);
        // Python: return self.generate_output(esi, edx)
        self.generate_output(esi, edx)
    }

    /// Block 2 transform - uses k1/k2, single phase
    fn transform_block2(&self, stored_edx: u32, esi: u32, block: &[u8]) -> (u32, u32) {
        let esi_r = ror32(esi, 0xF);

        // S-box 9-12 with k1
        let idx9 = (((self.k1() >> 12) ^ esi_r) >> 12) & 0x3F;
        let idx10 = (((self.k1() >> 8) ^ esi_r) >> 8) & 0x3F;
        let idx11 = (((self.k1() >> 4) ^ esi_r) >> 4) & 0x3F;
        let idx12 = (self.k1() ^ esi_r) & 0x3F;
        let val9 = SBOX9[idx9 as usize];
        let val10 = SBOX10[idx10 as usize];
        let val11 = SBOX11[idx11 as usize];
        let val12 = SBOX12[idx12 as usize];

        // S-box 13-16 with k2
        let idx13 = (((self.k2() >> 13) ^ esi) >> 11) & 0x3F;
        let idx14 = (((self.k2() >> 9) ^ esi) >> 7) & 0x3F;
        let idx15 = (((self.k2() >> 5) ^ esi) >> 3) & 0x3F;
        let idx16 = ((esi_r >> 16) ^ self.k2()) & 0x3F;
        let val13 = SBOX13[idx13 as usize];
        let val14 = SBOX14[idx14 as usize];
        let val15 = SBOX15[idx15 as usize];
        let val16 = SBOX16[idx16 as usize];

        let ebx = val9 | val10 | val11 | val12;
        let ecx = val13 | val14 | val15 | val16;

        let b0_val = SBOX7[block[0] as usize & 0x55];
        let edi_combined = (stored_edx << 1) | b0_val;
        let ecx_final = ecx ^ edi_combined ^ ebx;

        (ecx_final, ebx)  // Returns (ecx_final, ebx) - ebx unused but matches Python
    }

    /// Decrypt block 2 - WITH RC4
    pub fn decrypt_block2(&self, block: &[u8], sbox: &mut [u8; 256]) -> [u8; 8] {
        let (stored_edx, esi) = self.process_input(block);
        let (ecx_final, _) = self.transform_block2(stored_edx, esi, block);

        let ks = self.rc4_keystream_8bytes(sbox);
        let ks_d1 = u32::from_le_bytes([ks[0], ks[1], ks[2], ks[3]]);
        let ks_d2 = u32::from_le_bytes([ks[4], ks[5], ks[6], ks[7]]);

        #[cfg(test)]
        {
            eprintln!("Block 2 debug:");
            eprintln!("  stored_edx=0x{:08x}, esi=0x{:08x}", stored_edx, esi);
            eprintln!("  ecx_final=0x{:08x}", ecx_final);
            eprintln!("  keystream={:02x?}", ks);
            eprintln!("  ks_d1=0x{:08x}, ks_d2=0x{:08x}", ks_d1, ks_d2);
        }

        let esi_xor = esi ^ ks_d2;
        let ecx_xor = ecx_final ^ ks_d1;

        #[cfg(test)]
        {
            eprintln!("  esi_xor=0x{:08x}, ecx_xor=0x{:08x}", esi_xor, ecx_xor);
        }

        self.generate_output(esi_xor, ecx_xor)
    }

    /// Block 3 transform - uses k3/k4 for phase 1, k1/k2 for phase 2
    fn transform_block3(&self, stored_edx: u32, edx: u32, block: &[u8]) -> (u32, u32) {
        // Phase 1: ROR edx by 0xf, use k3/k4
        let eax_r = ror32(edx, 0xF);

        // S-box 9-12 with k3
        let idx9 = (((self.k3() >> 12) ^ eax_r) >> 12) & 0x3F;
        let idx10 = (((self.k3() >> 8) ^ eax_r) >> 8) & 0x3F;
        let idx11 = (((self.k3() >> 4) ^ eax_r) >> 4) & 0x3F;
        let idx12 = (self.k3() ^ eax_r) & 0x3F;
        let val9 = SBOX9[idx9 as usize];
        let val10 = SBOX10[idx10 as usize];
        let val11 = SBOX11[idx11 as usize];
        let val12 = SBOX12[idx12 as usize];

        // S-box 13-16 with k4
        let idx13 = (((self.k4() >> 13) ^ edx) >> 11) & 0x3F;
        let idx14 = (((self.k4() >> 9) ^ edx) >> 7) & 0x3F;
        let idx15 = (((self.k4() >> 5) ^ edx) >> 3) & 0x3F;
        let idx16 = ((eax_r >> 16) ^ self.k4()) & 0x3F;
        let val13 = SBOX13[idx13 as usize];
        let val14 = SBOX14[idx14 as usize];
        let val15 = SBOX15[idx15 as usize];
        let val16 = SBOX16[idx16 as usize];

        let esi_phase1 = val9 | val10 | val11 | val12;
        let ecx_phase1 = val13 | val14 | val15 | val16;

        let val_final = SBOX7[block[0] as usize & 0x55];
        let ebx = (stored_edx << 1) | val_final;
        let ecx_mid = ecx_phase1 ^ ebx ^ esi_phase1;

        // Phase 2: ROR ecx_mid by 0xf, use k1/k2
        let eax_r2 = ror32(ecx_mid, 0xF);

        // S-box 9-12 with k1
        let idx9_2 = (((self.k1() >> 12) ^ eax_r2) >> 12) & 0x3F;
        let idx10_2 = (((self.k1() >> 8) ^ eax_r2) >> 8) & 0x3F;
        let idx11_2 = (((self.k1() >> 4) ^ eax_r2) >> 4) & 0x3F;
        let idx12_2 = (self.k1() ^ eax_r2) & 0x3F;
        let val9_2 = SBOX9[idx9_2 as usize];
        let val10_2 = SBOX10[idx10_2 as usize];
        let val11_2 = SBOX11[idx11_2 as usize];
        let val12_2 = SBOX12[idx12_2 as usize];

        // S-box 13-16 with k2
        let idx13_2 = (((self.k2() >> 13) ^ ecx_mid) >> 11) & 0x3F;
        let idx14_2 = (((self.k2() >> 9) ^ ecx_mid) >> 7) & 0x3F;
        let idx15_2 = (((self.k2() >> 5) ^ ecx_mid) >> 3) & 0x3F;
        let idx16_2 = ((eax_r2 >> 16) ^ self.k2()) & 0x3F;
        let val13_2 = SBOX13[idx13_2 as usize];
        let val14_2 = SBOX14[idx14_2 as usize];
        let val15_2 = SBOX15[idx15_2 as usize];
        let val16_2 = SBOX16[idx16_2 as usize];

        let ebx_phase2 = val9_2 | val10_2 | val11_2 | val12_2;
        let esi_phase2 = val13_2 | val14_2 | val15_2 | val16_2;

        let esi_final = esi_phase2 ^ ebx_phase2 ^ edx;

        (ecx_mid, esi_final)
    }

    /// Decrypt block 3 - NO RC4
    pub fn decrypt_block3(&self, block: &[u8], _sbox: &mut [u8; 256]) -> [u8; 8] {
        let (stored_edx, esi) = self.process_input(block);
        let edx = esi;  // For block 3, edx = esi (second return from process_input)

        let (ecx_mid, esi_final) = self.transform_block3(stored_edx, edx, block);

        self.generate_output(ecx_mid, esi_final)
    }

    /// Decrypt block 4 - WITH RC4 (same transform as block 3)
    fn decrypt_block4(&self, block: &[u8], sbox: &mut [u8; 256]) -> [u8; 8] {
        let (stored_edx, esi) = self.process_input(block);
        let edx = esi;

        let (ecx_mid, esi_final) = self.transform_block3(stored_edx, edx, block);

        let ks = self.rc4_keystream_8bytes(sbox);
        let ks_d1 = u32::from_le_bytes([ks[0], ks[1], ks[2], ks[3]]);
        let ks_d2 = u32::from_le_bytes([ks[4], ks[5], ks[6], ks[7]]);

        self.generate_output(ecx_mid ^ ks_d2, esi_final ^ ks_d1)
    }

    /// Decrypt ESI=1 block (cycle reset, no RC4)
    fn decrypt_esi1(&self, block: &[u8], _sbox: &mut [u8; 256]) -> [u8; 8] {
        let (esi, edi) = self.process_input_esi1(block);
        self.generate_output(esi, edi)
    }

    /// Decrypt ESI=3 block (cycle restart with RC4)
    fn decrypt_esi3(&self, block: &[u8], sbox: &mut [u8; 256]) -> [u8; 8] {
        let (esi, edi) = self.process_input_esi1(block);

        let ks = self.rc4_keystream_8bytes(sbox);
        let ks_d1 = u32::from_le_bytes([ks[0], ks[1], ks[2], ks[3]]);
        let ks_d2 = u32::from_le_bytes([ks[4], ks[5], ks[6], ks[7]]);

        self.generate_output(esi ^ ks_d2, edi ^ ks_d1)
    }

    /// Multi-phase N transform for blocks 5+
    /// num_phases: 3 for block 5/6, 4 for block 7/8, etc.
    fn decrypt_multi_phase_n(&self, block: &[u8], num_phases: usize, sbox: Option<&mut [u8; 256]>) -> [u8; 8] {
        let (stored_edx, esi) = self.process_input(block);
        let b0_val = SBOX7[block[0] as usize & 0x55];
        let ebx = (stored_edx << 1) | b0_val;
        let edx = esi;

        // For multi-phase, we chain through phases using subkey pairs
        // Key ordering counts DOWN from highest to k0/k1:
        // 3 phases: k5/k6 -> k3/k4 -> k0/k1
        // 4 phases: k7/k8 -> k5/k6 -> k3/k4 -> k0/k1
        // Pattern: start_idx = 2 * (num_phases - 1), decrement by 2 each phase

        let mut prev_ebx = ebx;
        let mut prev_val = edx;

        for phase in 0..num_phases {
            // Key index starts at 2 * (num_phases - 1) and goes down by 2 each phase
            // But the last phase always uses k0/k1
            let key_idx = if phase == num_phases - 1 {
                0  // Last phase always uses k0/k1
            } else {
                2 * (num_phases - 1 - phase)  // Count down: e.g., for 3 phases: 4, 2, 0
            };
            let ka = self.subkeys[key_idx.min(self.subkeys.len() - 2)];
            let kb = self.subkeys[(key_idx + 1).min(self.subkeys.len() - 1)];

            let eax_r = ror32(prev_val, 0xF);

            // S-box 9-12 with ka
            let idx9 = (((ka >> 12) ^ eax_r) >> 12) & 0x3F;
            let idx10 = (((ka >> 8) ^ eax_r) >> 8) & 0x3F;
            let idx11 = (((ka >> 4) ^ eax_r) >> 4) & 0x3F;
            let idx12 = (ka ^ eax_r) & 0x3F;
            let sbox_a = SBOX9[idx9 as usize] | SBOX10[idx10 as usize] | SBOX11[idx11 as usize] | SBOX12[idx12 as usize];

            // S-box 13-16 with kb
            let idx13 = (((kb >> 13) ^ prev_val) >> 11) & 0x3F;
            let idx14 = (((kb >> 9) ^ prev_val) >> 7) & 0x3F;
            let idx15 = (((kb >> 5) ^ prev_val) >> 3) & 0x3F;
            let idx16 = ((eax_r >> 16) ^ kb) & 0x3F;
            let sbox_b = SBOX13[idx13 as usize] | SBOX14[idx14 as usize] | SBOX15[idx15 as usize] | SBOX16[idx16 as usize];

            let new_val = sbox_a ^ sbox_b ^ prev_ebx;
            prev_ebx = prev_val;
            prev_val = new_val;
        }

        let ecx_mid = prev_ebx;
        let esi_final = prev_val;

        if let Some(sbox) = sbox {
            let ks = self.rc4_keystream_8bytes(sbox);
            let ks_d1 = u32::from_le_bytes([ks[0], ks[1], ks[2], ks[3]]);
            let ks_d2 = u32::from_le_bytes([ks[4], ks[5], ks[6], ks[7]]);
            self.generate_output(ecx_mid ^ ks_d2, esi_final ^ ks_d1)
        } else {
            self.generate_output(ecx_mid, esi_final)
        }
    }

    /// Decrypt a block based on block number (2-32)
    fn decrypt_block_n(&self, block: &[u8], sbox: &mut [u8; 256], block_num: usize) -> [u8; 8] {
        match block_num {
            2 => self.decrypt_block2(block, sbox),
            3 => self.decrypt_block3(block, sbox),
            4 => self.decrypt_block4(block, sbox),
            n if n >= 5 && n <= 32 => {
                let num_phases = (n + 1) / 2;  // 5,6->3, 7,8->4, etc.
                let use_rc4 = n % 2 == 0;      // Even blocks use RC4
                if use_rc4 {
                    self.decrypt_multi_phase_n(block, num_phases, Some(sbox))
                } else {
                    self.decrypt_multi_phase_n(block, num_phases, None)
                }
            }
            _ => [0u8; 8],
        }
    }

    /// Decrypt data using the full multi-block cipher
    /// Decrypts all blocks including the last one
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt_internal(data, true)
    }

    /// Decrypt data for DLC files - decrypts all blocks including the last one
    pub fn decrypt_dlc(&self, data: &[u8]) -> Vec<u8> {
        self.decrypt_internal(data, true)
    }

    /// Internal decrypt with option to decrypt last block
    fn decrypt_internal(&self, data: &[u8], decrypt_last_block: bool) -> Vec<u8> {
        if data.len() % 8 != 0 {
            panic!("Data length must be multiple of 8");
        }

        let num_blocks = data.len() / 8;
        if num_blocks == 0 {
            return vec![];
        }

        if num_blocks == 1 {
            return vec![0u8; 8];
        }

        let mut result = Vec::with_capacity(data.len());

        // Block 1 (position 0)
        result.extend_from_slice(&self.decrypt_block1_multiblock(&data[0..8]));

        // Initialize sbox
        let mut sbox = self.rc4_sbox_template;

        // For DLC files, decrypt all blocks including the last one
        // For GAR files, skip the last block (it's padding that gets zeroed)
        let last_pos = if num_blocks == 32 || decrypt_last_block { num_blocks } else { num_blocks - 1 };

        for pos in 1..last_pos {
            let block = &data[pos * 8..(pos + 1) * 8];
            let pos_in_cycle = (pos - 1) % 34;

            let decrypted = if pos_in_cycle < 31 {
                let block_num = pos_in_cycle + 2;
                self.decrypt_block_n(block, &mut sbox, block_num)
            } else if pos_in_cycle == 31 {
                self.decrypt_esi1(block, &mut sbox)
            } else if pos_in_cycle == 32 {
                self.decrypt_esi3(block, &mut sbox)
            } else {
                self.decrypt_block1_multiblock(block)
            };

            result.extend_from_slice(&decrypted);
        }

        // Only add zero padding for GAR files (non-DLC)
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
        // Test sequential decryption like the real cipher does
        let cipher = GarCipher::new();

        // Ciphertexts from /tmp/gar_test.gar (which encrypts zeros)
        let blocks: [[u8; 8]; 5] = [
            [0x14, 0x51, 0x14, 0x15, 0x55, 0x41, 0x41, 0x10], // Block 1
            [0x38, 0xf4, 0x92, 0xa2, 0x7f, 0x9b, 0xb8, 0x43], // Block 2
            [0x39, 0xf7, 0x29, 0x7f, 0xbf, 0x97, 0x97, 0x34], // Block 3
            [0x69, 0x67, 0xfc, 0x76, 0x1f, 0x55, 0x18, 0x00], // Block 4
            [0x33, 0xbf, 0x03, 0xab, 0x6f, 0x3f, 0x3b, 0x3d], // Block 5
        ];

        // Block 1
        let p1 = cipher.decrypt_block1_multiblock(&blocks[0]);
        println!("Block 1: {:02x?} -> {:02x?}", blocks[0], p1);
        assert_eq!(p1, [0u8; 8], "Block 1 should decrypt to zeros");

        // Initialize sbox
        let mut sbox = cipher.rc4_sbox_template;

        // Block 2
        let p2 = cipher.decrypt_block2(&blocks[1], &mut sbox);
        println!("Block 2: {:02x?} -> {:02x?}", blocks[1], p2);
        assert_eq!(p2, [0u8; 8], "Block 2 should decrypt to zeros");

        // Block 3
        let p3 = cipher.decrypt_block3(&blocks[2], &mut sbox);
        println!("Block 3: {:02x?} -> {:02x?}", blocks[2], p3);
        assert_eq!(p3, [0u8; 8], "Block 3 should decrypt to zeros");

        // Block 4
        let p4 = cipher.decrypt_block4(&blocks[3], &mut sbox);
        println!("Block 4: {:02x?} -> {:02x?}", blocks[3], p4);
        assert_eq!(p4, [0u8; 8], "Block 4 should decrypt to zeros");

        // Block 5 uses decrypt_multi_phase_n with 3 phases, no RC4
        let p5 = cipher.decrypt_multi_phase_n(&blocks[4], 3, None);
        println!("Block 5: {:02x?} -> {:02x?}", blocks[4], p5);
        assert_eq!(p5, [0u8; 8], "Block 5 should decrypt to zeros");
    }

    #[test]
    fn test_block2_decryption() {
        let cipher = GarCipher::new();
        let mut sbox = cipher.rc4_sbox_template;

        let ciphertext = [0x18u8, 0xf4, 0x82, 0xa2, 0x7b, 0xdb, 0xb9, 0x43];
        let plaintext = cipher.decrypt_block2(&ciphertext, &mut sbox);

        println!("Ciphertext: {:02x?}", ciphertext);
        println!("Plaintext: {:02x?}", plaintext);

        assert_eq!(plaintext, [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_block3_decryption() {
        let cipher = GarCipher::new();

        let ciphertext = [0x5eu8, 0xc2, 0x28, 0xff, 0xaf, 0x97, 0x47, 0x08];

        // Debug: trace through process_input
        let (stored_edx, esi) = cipher.process_input(&ciphertext);
        println!("After process_input:");
        println!("  stored_edx = 0x{:08x}", stored_edx);
        println!("  esi = 0x{:08x}", esi);

        let edx = esi;  // For block 3, edx = esi
        println!("  edx = 0x{:08x}", edx);

        let (ecx_mid, esi_final) = cipher.transform_block3(stored_edx, edx, &ciphertext);
        println!("After transform_block3:");
        println!("  ecx_mid = 0x{:08x}", ecx_mid);
        println!("  esi_final = 0x{:08x}", esi_final);

        let plaintext = cipher.generate_output(ecx_mid, esi_final);

        println!("Ciphertext: {:02x?}", ciphertext);
        println!("Plaintext: {:02x?}", plaintext);

        assert_eq!(plaintext, [0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}

#[cfg(test)]
mod derive_keys_tests {
    use super::*;
    use crate::tables::KEYS_FS15_25;

    /// Test that derive_keys produces consistent subkeys and S-box for FS15_25
    #[test]
    fn test_derive_keys_fs15_25() {
        let (k1, k2, k3, k4) = KEYS_FS15_25;
        let (derived_subkeys, derived_sbox) = derive_keys(k1, k2, k3, k4);

        // Verify S-box is a valid permutation (all values 0-255 appear exactly once)
        let mut seen = [false; 256];
        for &b in &derived_sbox {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&x| x), "S-box should be a valid permutation");

        // Verify subkeys are non-zero (basic sanity check)
        assert!(derived_subkeys.iter().any(|&k| k != 0), "Subkeys should not be all zeros");

        println!("Derived subkeys (first 8):");
        for i in 0..8 {
            println!("  subkey[{}] = 0x{:08x}", i, derived_subkeys[i]);
        }
    }

    /// Test that derive_keys is deterministic
    #[test]
    fn test_derive_keys_deterministic() {
        let (k1, k2, k3, k4) = KEYS_FS15_25;
        let (subkeys1, sbox1) = derive_keys(k1, k2, k3, k4);
        let (subkeys2, sbox2) = derive_keys(k1, k2, k3, k4);

        assert_eq!(subkeys1, subkeys2, "Subkeys should be deterministic");
        assert_eq!(sbox1, sbox2, "S-box should be deterministic");
    }

    /// Test that from_keys produces a working cipher
    #[test]
    fn test_from_keys_decryption() {
        let (k1, k2, k3, k4) = KEYS_FS15_25;

        // Create cipher using from_keys
        let cipher = GarCipher::from_keys(k1, k2, k3, k4);

        // Test decryption with known ciphertexts (from /tmp/gar_test.gar)
        let blocks: [[u8; 8]; 3] = [
            [0x14, 0x51, 0x14, 0x15, 0x55, 0x41, 0x41, 0x10], // Block 1
            [0x38, 0xf4, 0x92, 0xa2, 0x7f, 0x9b, 0xb8, 0x43], // Block 2
            [0x39, 0xf7, 0x29, 0x7f, 0xbf, 0x97, 0x97, 0x34], // Block 3 (last)
        ];

        // Decrypt 3 blocks (24 bytes)
        let mut input = Vec::new();
        for block in &blocks {
            input.extend_from_slice(block);
        }

        let result = cipher.decrypt(&input);

        // All blocks should be zeros
        assert_eq!(&result[0..8], &[0u8; 8], "Block 1 should decrypt to zeros");
        assert_eq!(&result[8..16], &[0u8; 8], "Block 2 should decrypt to zeros");
        assert_eq!(&result[16..24], &[0u8; 8], "Block 3 should decrypt to zeros");

        println!("from_keys decryption test passed!");
    }
}

#[cfg(test)]
mod fs13b_tests {
    use super::*;
    use crate::tables::KEYS_FS13_B;

    #[test]
    fn test_fs13b_first_entry() {
        // Create cipher by deriving from raw keys
        let (k1, k2, k3, k4) = KEYS_FS13_B;
        let cipher = GarCipher::from_keys(k1, k2, k3, k4);

        // First 24 bytes of encrypted entry from daimlerTruckPack.dlc at 0x200
        let encrypted: [u8; 24] = [
            0x15, 0x45, 0x14, 0x10, 0x50, 0x11, 0x45, 0x04,  // block 1
            0x09, 0xef, 0x6b, 0xd0, 0x3d, 0xb4, 0xcd, 0x91,  // block 2
            0xc9, 0x99, 0x39, 0x2b, 0xe0, 0x53, 0x0b, 0x45,  // block 3
        ];

        let result = cipher.decrypt(&encrypted);
        println!("Rust decrypted: {:02x?}", result);

        // Expected from Python/Unicorn:
        // 0100000000000000580d000000000000520d000000000000
        let expected: [u8; 24] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // block 1: flags=1
            0x58, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // block 2: xsize=3416
            0x52, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // block 3: size=3410
        ];

        assert_eq!(result, expected, "Should match Unicorn output");
    }
}
