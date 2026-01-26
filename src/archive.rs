//! GAR Archive parsing and file extraction

use crate::cipher::GarCipher;
use crate::tables;
use std::collections::HashMap;
use std::path::Path;

/// A file entry in the GAR archive
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,      // Decrypted size
    pub xsize: u64,     // Encrypted size (padded)
}

/// GAR Archive reader
#[derive(Debug)]
pub struct GarArchive {
    /// Raw archive data (memory-mapped or loaded)
    data: Vec<u8>,
    /// File entries indexed by path
    entries: HashMap<String, FileEntry>,
    /// Cipher for decryption
    cipher: GarCipher,
    /// Whether this is a DLC file (affects last-block handling)
    is_dlc: bool,
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

impl GarArchive {
    /// Open a GAR archive from a file path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        // Detect if DLC based on extension
        let is_dlc = path.extension()
            .map(|ext| ext.eq_ignore_ascii_case("dlc"))
            .unwrap_or(false);

        Self::from_bytes(data, is_dlc)
    }

    /// Create archive from raw bytes
    pub fn from_bytes(data: Vec<u8>, is_dlc: bool) -> Result<Self, String> {
        // Verify GAR magic at 0x60
        if data.len() < 0x70 || &data[0x60..0x64] != b"GAR " {
            return Err("Not a valid GAR file (magic mismatch at 0x60)".to_string());
        }

        // Read header
        let version = read_u16_le(&data, 0x64);
        let mut num_files = read_u32_le(&data, 0x68) as usize;

        if version >= 3 {
            num_files += read_u32_le(&data, 0x6C) as usize;
        }

        // File table starts at 0x200
        let file_table_offset = 0x200usize;
        let file_table_size = num_files * 0x200;
        let file_table_end = file_table_offset + file_table_size;

        if file_table_end > data.len() {
            return Err("File table extends beyond file size".to_string());
        }

        // Try to find the correct key set by deriving from raw keys
        let encrypted_table = &data[file_table_offset..file_table_end];

        let mut decrypted_table = Vec::new();
        let mut working_cipher: Option<GarCipher> = None;

        for (k1, k2, k3, k4) in tables::ALL_KEYS {
            let cipher = GarCipher::from_keys(k1, k2, k3, k4);
            let test_decrypt = cipher.decrypt(&encrypted_table[0..0x200]);

            // Check if decryption looks valid (bytes 4-7 should be 0 for a valid entry)
            let check = read_u32_le(&test_decrypt, 4);
            if check == 0 {
                decrypted_table = cipher.decrypt(encrypted_table);
                working_cipher = Some(cipher);
                break;
            }
        }

        let cipher = working_cipher.ok_or("Could not find valid decryption key")?;

        // Parse file entries
        let mut entries = HashMap::new();
        for i in 0..num_files {
            let entry_offset = i * 0x200;
            let entry = &decrypted_table[entry_offset..entry_offset + 0x200];

            // Flags at 0x00 - skip dummy entries with flags=0
            let flags = read_u64_le(entry, 0x00);
            if flags == 0 {
                continue;
            }

            // Format: xsize at 0x08, size at 0x10, offset at 0x18, name at 0x28
            let xsize = read_u64_le(entry, 0x08);
            let size = read_u64_le(entry, 0x10);
            let offset = read_u64_le(entry, 0x18);

            // Read filename (null-terminated at 0x28)
            let name_start = 0x28;
            let name_end = entry[name_start..].iter()
                .position(|&b| b == 0)
                .map(|p| name_start + p)
                .unwrap_or(0x200);

            let name = String::from_utf8_lossy(&entry[name_start..name_end]).to_string();

            if !name.is_empty() {
                // Normalize path separators to forward slashes
                let normalized_name = name.replace('\\', "/");
                entries.insert(normalized_name.clone(), FileEntry {
                    name: normalized_name,
                    offset,
                    size,
                    xsize,
                });
            }
        }

        Ok(Self {
            data,
            entries,
            cipher,
            is_dlc,
        })
    }

    /// Get list of all files in the archive
    pub fn files(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    /// Check if a file exists in the archive
    pub fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path) ||
            (path.contains('\\') && self.entries.contains_key(&path.replace('\\', "/")))
    }

    /// Get file entry metadata
    pub fn get_entry(&self, path: &str) -> Option<&FileEntry> {
        self.entries.get(path).or_else(|| {
            if path.contains('\\') {
                self.entries.get(&path.replace('\\', "/"))
            } else {
                None
            }
        })
    }

    /// Read and decrypt a file from the archive
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        // Fast path: try direct lookup first (avoids allocation when path is already normalized)
        let entry = self.entries.get(path).or_else(|| {
            if path.contains('\\') {
                self.entries.get(&path.replace('\\', "/"))
            } else {
                None
            }
        })
            .ok_or_else(|| format!("File not found: {}", path))?;

        if entry.offset + entry.xsize > self.data.len() as u64 {
            return Err(format!("File {} extends beyond archive", path));
        }

        let encrypted_data = &self.data[entry.offset as usize..(entry.offset + entry.xsize) as usize];

        // Decrypt
        let decrypted = if self.is_dlc {
            self.cipher.decrypt_dlc(encrypted_data)
        } else {
            self.cipher.decrypt(encrypted_data)
        };

        // Truncate to actual size
        let final_size = (entry.size as usize).min(decrypted.len());
        Ok(decrypted[..final_size].to_vec())
    }

    /// Get number of files in archive
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if archive is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List files matching a glob pattern
    ///
    /// Supports `*` (any chars except `/`) and `**` (any chars including `/`).
    ///
    /// # Examples
    /// ```ignore
    /// // All lua files in scripts folder
    /// archive.glob("scripts/*.lua")
    ///
    /// // All lua files recursively
    /// archive.glob("scripts/**/*.lua")
    ///
    /// // All files with specific extension
    /// archive.glob("**/*.i3d")
    /// ```
    pub fn glob(&self, pattern: &str) -> Vec<&str> {
        let matcher = GlobMatcher::new(pattern);
        self.entries
            .keys()
            .filter(|path| matcher.is_match(path))
            .map(|s| s.as_str())
            .collect()
    }

    /// List files with a specific extension under a base path
    ///
    /// # Arguments
    /// * `base` - Base path prefix (empty string for root)
    /// * `extension` - File extension without dot (e.g., "lua", "i3d")
    /// * `recursive` - If true, search subdirectories; if false, only immediate children
    pub fn files_with_extension(&self, base: &str, extension: &str, recursive: bool) -> Vec<&str> {
        let base = base.trim_matches('/');
        let ext_suffix = format!(".{}", extension);

        self.entries
            .keys()
            .filter(|path| {
                // Check extension
                if !path.ends_with(&ext_suffix) {
                    return false;
                }

                // Check base path
                if !base.is_empty() && !path.starts_with(base) {
                    return false;
                }

                // Check recursion
                if !recursive {
                    let rel = if base.is_empty() {
                        path.as_str()
                    } else {
                        path.strip_prefix(base)
                            .unwrap_or(path)
                            .trim_start_matches('/')
                    };
                    // Non-recursive: no slashes in relative path
                    if rel.contains('/') {
                        return false;
                    }
                }

                true
            })
            .map(|s| s.as_str())
            .collect()
    }
}

/// Simple glob matcher without external dependencies
struct GlobMatcher {
    pattern: String,
}

impl GlobMatcher {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
        }
    }

    fn is_match(&self, path: &str) -> bool {
        self.match_recursive(&self.pattern, path)
    }

    fn match_recursive(&self, pattern: &str, path: &str) -> bool {
        let mut pat_chars = pattern.chars().peekable();
        let mut path_chars = path.chars().peekable();

        while let Some(p) = pat_chars.next() {
            match p {
                '*' => {
                    // Check for **
                    if pat_chars.peek() == Some(&'*') {
                        pat_chars.next(); // consume second *

                        // Skip any following /
                        if pat_chars.peek() == Some(&'/') {
                            pat_chars.next();
                        }

                        let remaining_pattern: String = pat_chars.collect();
                        let remaining_path: String = path_chars.collect();

                        // ** matches any path including separators
                        // Try matching at every position
                        if remaining_pattern.is_empty() {
                            return true;
                        }

                        for i in 0..=remaining_path.len() {
                            if self.match_recursive(&remaining_pattern, &remaining_path[i..]) {
                                return true;
                            }
                        }
                        return false;
                    } else {
                        // Single * - match any chars except /
                        let remaining_pattern: String = pat_chars.collect();
                        let remaining_path: String = path_chars.collect();

                        // Try matching at every position up to next /
                        for i in 0..=remaining_path.len() {
                            let consumed = &remaining_path[..i];
                            if consumed.contains('/') {
                                break;
                            }
                            if self.match_recursive(&remaining_pattern, &remaining_path[i..]) {
                                return true;
                            }
                        }
                        return false;
                    }
                }
                '?' => {
                    // Match any single char except /
                    match path_chars.next() {
                        Some('/') | None => return false,
                        _ => {}
                    }
                }
                c => {
                    // Literal match
                    if path_chars.next() != Some(c) {
                        return false;
                    }
                }
            }
        }

        // Pattern exhausted - path should also be exhausted
        path_chars.next().is_none()
    }
}
