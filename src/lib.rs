//! GAR Archive Library
//!
//! Provides read access to Giants GAR/DLC archives with VFS integration.
//! Pure Rust, cross-platform, no OS-level filesystem mounting required.

mod tables;
mod cipher;
mod archive;
mod vfs_impl;
mod path;

pub use cipher::GarCipher;
pub use archive::{GarArchive, FileEntry};
pub use vfs_impl::GarFileSystem;
pub use path::GarPath;

// Re-export vfs for convenience
pub use vfs;
