# gar-lib

Rust library for reading GAR and DLC archive files.

## Usage

```rust
use gar_lib::GarArchive;

// Open an archive
let archive = GarArchive::open("data.gar")?;

// List all files
for file in archive.files() {
    println!("{}", file);
}

// Read a file
let data = archive.read_file("scripts/main.lua")?;

// Glob matching
let lua_files = archive.glob("**/*.lua");

// Check if file exists
if archive.exists("textures/icon.dds") {
    // ...
}
```

## Features

- Read-only access to GAR/DLC archives
- Automatic key detection
- Glob pattern matching (`*`, `**`, `?`)
- VFS integration via the `vfs` crate

## License

MIT
