//! VFS implementation for GAR archives (read-only)

use crate::archive::GarArchive;
use std::fmt::Debug;
use std::io::{Read, Seek, SeekFrom, Cursor};
use std::sync::Arc;
use vfs::{FileSystem, VfsMetadata, VfsResult, VfsFileType, SeekAndRead, SeekAndWrite};
use vfs::error::VfsErrorKind;

/// Read-only VFS implementation for GAR archives
#[derive(Debug)]
pub struct GarFileSystem {
    archive: Arc<GarArchive>,
}

impl GarFileSystem {
    /// Create a new GAR filesystem from an archive
    pub fn new(archive: GarArchive) -> Self {
        Self {
            archive: Arc::new(archive),
        }
    }

    /// Create from a file path
    pub fn open(path: &str) -> Result<Self, String> {
        let archive = GarArchive::open(path)?;
        Ok(Self::new(archive))
    }
}

/// A file handle for reading from the GAR archive
struct GarFile {
    data: Cursor<Vec<u8>>,
}

impl Debug for GarFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarFile")
            .field("len", &self.data.get_ref().len())
            .field("position", &self.data.position())
            .finish()
    }
}

impl Read for GarFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data.read(buf)
    }
}

impl Seek for GarFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.data.seek(pos)
    }
}

impl FileSystem for GarFileSystem {
    fn read_dir(&self, path: &str) -> VfsResult<Box<dyn Iterator<Item = String> + Send>> {
        let normalized = normalize_path(path);
        let prefix = if normalized.is_empty() || normalized == "/" {
            String::new()
        } else {
            format!("{}/", normalized.trim_start_matches('/'))
        };

        let mut entries: Vec<String> = Vec::new();
        let mut seen_dirs = std::collections::HashSet::new();

        for file_path in self.archive.files() {
            // Check if file is in this directory
            if prefix.is_empty() {
                // Root directory - get first component
                if let Some(first_part) = file_path.split('/').next() {
                    if file_path.contains('/') {
                        // It's a directory
                        if seen_dirs.insert(first_part.to_string()) {
                            entries.push(first_part.to_string());
                        }
                    } else {
                        // It's a file at root
                        entries.push(first_part.to_string());
                    }
                }
            } else if file_path.starts_with(&prefix) {
                // Get the next component after prefix
                let remainder = &file_path[prefix.len()..];
                if let Some(next_part) = remainder.split('/').next() {
                    if remainder.contains('/') {
                        // It's a subdirectory
                        if seen_dirs.insert(next_part.to_string()) {
                            entries.push(next_part.to_string());
                        }
                    } else {
                        // It's a file
                        entries.push(next_part.to_string());
                    }
                }
            }
        }

        Ok(Box::new(entries.into_iter()))
    }

    fn create_dir(&self, _path: &str) -> VfsResult<()> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn open_file(&self, path: &str) -> VfsResult<Box<dyn SeekAndRead + Send>> {
        let normalized = normalize_path(path);
        let data = self.archive.read_file(&normalized)
            .map_err(|_| VfsErrorKind::FileNotFound)?;

        Ok(Box::new(GarFile {
            data: Cursor::new(data),
        }))
    }

    fn create_file(&self, _path: &str) -> VfsResult<Box<dyn SeekAndWrite + Send>> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn append_file(&self, _path: &str) -> VfsResult<Box<dyn SeekAndWrite + Send>> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let normalized = normalize_path(path);

        // Check if it's a file
        if let Some(entry) = self.archive.get_entry(&normalized) {
            return Ok(VfsMetadata {
                file_type: VfsFileType::File,
                len: entry.size,
                created: None,
                modified: None,
                accessed: None,
            });
        }

        // Check if it's a directory (has files with this prefix)
        let dir_prefix = if normalized.is_empty() || normalized == "/" {
            String::new()
        } else {
            format!("{}/", normalized.trim_start_matches('/'))
        };

        let is_dir = if dir_prefix.is_empty() {
            true // Root always exists
        } else {
            self.archive.files().any(|f| f.starts_with(&dir_prefix))
        };

        if is_dir {
            Ok(VfsMetadata {
                file_type: VfsFileType::Directory,
                len: 0,
                created: None,
                modified: None,
                accessed: None,
            })
        } else {
            Err(VfsErrorKind::FileNotFound.into())
        }
    }

    fn exists(&self, path: &str) -> VfsResult<bool> {
        match self.metadata(path) {
            Ok(_) => Ok(true),
            Err(e) => match e.kind() {
                VfsErrorKind::FileNotFound => Ok(false),
                _ => Err(e),
            },
        }
    }

    fn remove_file(&self, _path: &str) -> VfsResult<()> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn remove_dir(&self, _path: &str) -> VfsResult<()> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn copy_file(&self, _src: &str, _dest: &str) -> VfsResult<()> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn move_file(&self, _src: &str, _dest: &str) -> VfsResult<()> {
        Err(VfsErrorKind::NotSupported.into())
    }

    fn move_dir(&self, _src: &str, _dest: &str) -> VfsResult<()> {
        Err(VfsErrorKind::NotSupported.into())
    }
}

/// Normalize a path for lookup
fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let path = path.trim_start_matches('/');
    path.to_string()
}
