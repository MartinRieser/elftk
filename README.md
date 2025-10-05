# elftk - ELF file tool kit for embedded software development

A powerful tool that analyzes ARM, RISC-V, ARM64, and Xtensa ELF binaries to extract detailed information about variables, functions, and memory layouts. Features enhanced DWARF type resolution for accurate constant analysis and comprehensive type information. Perfect for embedded developers, reverse engineers, and anyone working with compiled code.

## What Does It Do?

elftk automatically discovers and displays:
- **Global variables** with their memory addresses, sizes, and types
- **Constants** with type resolution and its values
- **Function locations** and entry points
- **C++ class members** with precise memory offsets
- **C structure layouts** including nested structures
- **Array dimensions** and element types with accurate size calculations
- **Memory regions** and program layout
- **Enhanced DWARF type information** supporting verbose type names

**No configuration needed** - just point it at any ARM ELF binary compiled with debug info (`-g` flag).

## ? Performance

**35-40x faster than GDB** for symbol extraction with **5x more comprehensive output**:

| Tool | Speed | Coverage | Best For |
|------|-------|----------|----------|
| **elftk** | ?? **Ultra Fast** | ?? **Comprehensive** | Static analysis, automation, CI/CD |
| GDB | ?? Standard | ?? Function-focused | Interactive debugging |

- **Lightning fast**: Processes hundreds of symbols in milliseconds
- **Structured output**: CSV/JSON ready for automation and toolchains
- **Complete analysis**: Variables, constants, struct members, and functions
- **Perfect for**: Firmware analysis, reverse engineering, automated workflows

*Benchmark your own binaries - see [Performance Testing](#performance-testing) below.*

## Quick Example

```bash
./elftk firmware.elf
```

**CSV Output (default):**
```
Name,Address,Size,Type,Value
device_config.sensor_count,0x20000000,4,uint32_t,
device_config.temperature_threshold,0x20000004,4,float,
device_config.device_name,0x20000008,32,char[32],
sensor_data.readings,0x20000028,64,float[16],
sensor_data.timestamp,0x20000068,8,uint64_t,
status_flags.is_enabled,0x20000070,1,bool,
status_flags.error_code,0x20000071,1,uint8_t,
MAX_SENSORS,0x20000072,4,int,16
PI_CONSTANT,0x20000076,4,float,3.141593f
```

**JSON Output:**
```bash
./elftk firmware.elf --json
```
```json
{
  "architecture": "32-bit Little Endian",
  "entryPoint": "0x08000401",
  "parameters": [
    {"name": "device_config.sensor_count", "address": "0x20000000", "size": 4, "type": "uint32_t"},
    {"name": "device_config.temperature_threshold", "address": "0x20000004", "size": 4, "type": "float"},
    {"name": "MAX_SENSORS", "address": "0x20000072", "size": 4, "type": "int", "value": "16"},
    {"name": "PI_CONSTANT", "address": "0x20000076", "size": 4, "type": "float", "value": "3.141593f"}
  ]
}
```

## ?? Usage

elftk provides **clear, helpful command-line interface** with automatic validation:

```bash
# Get help with all options and examples
./elftk --help

# Missing file shows clear guidance
$ ./elftk
file is required
Run with --help for more information.

# Automatic file validation
$ ./elftk nonexistent.elf
file: File does not exist: nonexistent.elf

# Clear error messages for invalid options
$ ./elftk firmware.elf --export=invalid
--export: invalid not in {hex,s19,s28,s37,bin}
```

## Installation and Build

### Prerequisites (All Platforms)

Before building, ensure you have:
- **Git** - for cloning the repository
- **C++ compiler** - with C++17 support
- **Make** - build system

**External Dependencies:**
- **libdwarf** - DWARF debug information parsing library (automatically installed)

### Windows (MSYS2)

1. **Install MSYS2** from https://www.msys2.org/
2. **Open MSYS2 terminal** and install development dependencies:
   ```bash
   pacman -S base-devel mingw-w64-ucrt-x86_64-toolchain git
   pacman -S mingw-w64-ucrt-x86_64-libdwarf
   ```

   **What this installs:**
   - `base-devel` - Make and essential build tools
   - `mingw-w64-ucrt-x86_64-toolchain` - GCC compiler for Windows
   - `git` - version control system for cloning the repository
   - `mingw-w64-ucrt-x86_64-libdwarf` - DWARF debug information library
3. **Build the tool:**
   ```bash
   git clone <repository-url>
   cd elftk
   make windows
   ```
4. **Run anywhere** (PowerShell, Command Prompt, or MSYS2):
   ```bash
   .\build\bin\elftk.exe your_firmware.elf
   ```



### macOS

**Prerequisites:**
- **Xcode Command Line Tools**: `xcode-select --install`
- **Homebrew**: Install from https://brew.sh/

1. **Install development dependencies:**
   ```bash
   # Install Homebrew (if not already installed)
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

   # Install required libraries
   brew install libdwarf git
   ```

2. **Standard build:**
   ```bash
   git clone <repository-url>
   cd elftk
   make
   ./build/bin/elftk your_firmware.elf
   ```

3. **Portable build (recommended for distribution):**
   ```bash
   # Creates a self-contained binary with bundled libraries
   make macos
   ./build/bin/elftk your_firmware.elf

   # Or create a complete distribution package
   make macos-dist
   # Creates dist/elftk-macOS/ - copy this folder to any macOS system
   ```


### Linux (Ubuntu/Debian)

1. **Install development dependencies:**
   ```bash
   sudo apt update
   sudo apt install build-essential git libdwarf-dev libelf-dev
   ```

   **What this installs:**
   - `build-essential` - GCC compiler, make, and essential build tools
   - `git` - version control system for cloning the repository
   - `libdwarf-dev` - DWARF debug information library
   - `libelf-dev` - ELF format handling library
2. **Build and run:**
   ```bash
   git clone <repository-url>
   cd elftk
   make
   ./build/bin/elftk your_firmware.elf
   ```




## License

Mozilla Public License 2.0 (MPL-2.0) - Free for both personal and commercial use.