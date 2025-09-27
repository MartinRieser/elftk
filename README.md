# ELFtk - ELF Toolkit for Embedded Software Development

A command-line tool for analyzing ELF binaries and extracting embedded software information from DWARF debug data.

## Usage

```bash
# Analyze ELF file and output variables/constants in CSV format (default)
elftk firmware.elf

# Output in JSON format
elftk --format=json firmware.elf

# Extract function information
elftk --functions firmware.elf

# Show help
elftk --help
```

## Build Instructions

### Prerequisites

**Linux/macOS:**
- GCC or Clang compiler
- libdwarf development libraries
- Make

**Windows (MSYS2):**
- MSYS2 environment
- MinGW64 toolchain
- libdwarf package

### Building

**Linux/macOS:**
```bash
make                    # Build for current platform
make install            # Install to /usr/local/bin
```

**Windows:**
```bash
make windows           # Build with required DLLs
```

**Cross-platform:**
```bash
make macos             # macOS build
make deb               # Create Debian package (requires Docker)
```

### Platform-Specific Notes

**macOS:** Uses Homebrew dependencies. Set `HOMEBREW_PREFIX` if not using default location.

**Windows:** Always use `make windows` to ensure proper DLL inclusion for distribution.

**Linux:** For system-wide installation, use `sudo make install`.

## License

This project is licensed under the Mozilla Public License 2.0. See [LICENSE](LICENSE) for details.