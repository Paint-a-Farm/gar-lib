//! GAR path parsing utilities
//!
//! Provides parsing for paths that may reference files inside GAR/DLC archives.
//! Supports syntax like `archive.gar/internal/path/file.ext`.

use std::path::{Path, PathBuf};

/// A path that may reference a file inside a GAR archive or on the filesystem
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GarPath {
    /// Regular filesystem path
    Filesystem(PathBuf),
    /// Path inside a GAR/DLC archive
    Archive {
        /// Path to the .gar or .dlc file
        archive_path: PathBuf,
        /// Path inside the archive (None = root of archive)
        internal_path: Option<String>,
    },
}

impl GarPath {
    /// Parse a path, detecting if it references inside a GAR/DLC archive
    ///
    /// # Examples
    /// ```
    /// use gar_lib::GarPath;
    /// use std::path::Path;
    ///
    /// // Regular filesystem path
    /// let path = GarPath::parse(Path::new("/some/file.txt"));
    /// assert!(matches!(path, GarPath::Filesystem(_)));
    ///
    /// // Path inside a GAR archive
    /// let path = GarPath::parse(Path::new("/game/dataS.gar/scripts/main.lua"));
    /// assert!(matches!(path, GarPath::Archive { .. }));
    /// ```
    pub fn parse(path: &Path) -> Self {
        // Walk up path ancestors looking for .gar or .dlc extension
        for ancestor in path.ancestors() {
            if let Some(ext) = ancestor.extension() {
                if ext == "gar" || ext == "dlc" {
                    let internal = path
                        .strip_prefix(ancestor)
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                        .filter(|s| !s.is_empty());
                    return GarPath::Archive {
                        archive_path: ancestor.to_path_buf(),
                        internal_path: internal,
                    };
                }
            }
        }
        GarPath::Filesystem(path.to_path_buf())
    }

    /// Check if this is an archive path
    pub fn is_archive(&self) -> bool {
        matches!(self, GarPath::Archive { .. })
    }

    /// Check if this is a filesystem path
    pub fn is_filesystem(&self) -> bool {
        matches!(self, GarPath::Filesystem(_))
    }

    /// Get the archive path if this is an archive reference
    pub fn archive_path(&self) -> Option<&Path> {
        match self {
            GarPath::Archive { archive_path, .. } => Some(archive_path),
            GarPath::Filesystem(_) => None,
        }
    }

    /// Get the internal path if this is an archive reference
    pub fn internal_path(&self) -> Option<&str> {
        match self {
            GarPath::Archive { internal_path, .. } => internal_path.as_deref(),
            GarPath::Filesystem(_) => None,
        }
    }
}

impl From<&Path> for GarPath {
    fn from(path: &Path) -> Self {
        Self::parse(path)
    }
}

impl From<PathBuf> for GarPath {
    fn from(path: PathBuf) -> Self {
        Self::parse(&path)
    }
}

impl From<&str> for GarPath {
    fn from(path: &str) -> Self {
        Self::parse(Path::new(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_path() {
        let path = GarPath::parse(Path::new("/some/regular/file.txt"));
        assert!(path.is_filesystem());
        assert!(!path.is_archive());
        assert_eq!(path.archive_path(), None);
    }

    #[test]
    fn test_gar_archive_path() {
        let path = GarPath::parse(Path::new("/game/dataS.gar/scripts/main.lua"));
        assert!(path.is_archive());
        assert_eq!(path.archive_path(), Some(Path::new("/game/dataS.gar")));
        assert_eq!(path.internal_path(), Some("scripts/main.lua"));
    }

    #[test]
    fn test_dlc_archive_path() {
        let path = GarPath::parse(Path::new("/game/content.dlc/vehicles/tractor.i3d"));
        assert!(path.is_archive());
        assert_eq!(path.archive_path(), Some(Path::new("/game/content.dlc")));
        assert_eq!(path.internal_path(), Some("vehicles/tractor.i3d"));
    }

    #[test]
    fn test_archive_root() {
        let path = GarPath::parse(Path::new("/game/dataS.gar"));
        assert!(path.is_archive());
        assert_eq!(path.archive_path(), Some(Path::new("/game/dataS.gar")));
        assert_eq!(path.internal_path(), None);
    }
}
