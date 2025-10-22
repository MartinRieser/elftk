# elftk Development Guidelines

## Build Commands
- `make` - Build the main binary (builds to build/bin/elftk)
- `make debug` - Build with debug flags (-DDEBUG -O0)
- `make clean` - Clean build artifacts
- `make macos` - Build for macOS with bundled libraries
- `make windows` - Build for Windows (MSYS2/MinGW)
- `make install` - Install to system (INSTALL_PREFIX=/usr/local by default)

## Testing
- **Unit Tests**: `cd tests/unit && make test` (uses Google Test framework)
- **Single Test**: `cd tests/unit && make test-filter FILTER=TestName`
- **Verbose Tests**: `cd tests/unit && make test-verbose`
- **Coverage**: `cd tests/unit && make test-coverage` (if gcov available)
- **Validation**: `tests/validation/validation_suite.sh` for external validation

## Linting & Code Quality
- **Clang-tidy**: `make clang-tidy` (runs automatically during builds)
- **Auto-fix**: `make clang-tidy-fix` (fixes applicable issues)
- **Single file**: `make clang-tidy-file FILE=src/YourFile.cpp`
- **Format**: Uses `.clang-format` (LLVM-based style, 100-char limit, 4-space indent)
- **CI-friendly**: `make clang-tidy-ci` (warnings don't fail build)

## Code Style Guidelines

### Formatting & Structure
- Use C++17 standard
- Header guards: `#pragma once` for all headers
- License header: Mozilla Public License 2.0 at top of every file
- Use `/** */` Doxygen-style comments for documentation
- 4-space indentation (no tabs), 100-character line limit
- LLVM-based formatting style (see `.clang-format`)

### Naming Conventions
- Classes: PascalCase (e.g., `ElfReader`, `CLI11Parser`)
- Functions: camelCase (e.g., `extractSymbols`, `initialize`)
- Variables: snake_case (e.g., `build_date`, `include_paths`)
- Constants: UPPER_SNAKE_CASE (e.g., `MAX_SENSORS`, `BUILD_DATE`)
- Private members: trailing underscore (e.g., `filename_`, `debug_context_`)

### Error Handling
- Use custom exception hierarchy from `ElfExceptions.h`
- Prefer specific exception types over generic ones
- Include detailed error messages and suggestions
- Use RAII for resource management

### Imports & Dependencies
- System headers first, then local headers
- Group related includes together
- Use forward declarations where possible
- Prefer `#pragma once` over include guards

### Threading & Performance
- Use thread-safe containers from `ThreadSafeContainers.h`
- Implement lock-free operations where possible
- Use `ThreadPool` for parallel processing
- Follow RAII patterns for resource cleanup

### Platform Compatibility
- Support Windows (MSYS2/MinGW), macOS, and Linux
- Use platform-specific code paths with `#ifdef` guards
- Handle path differences between Windows and Unix systems
- Test on all supported platforms

## Dependencies
- **libdwarf**: DWARF debug information parsing
- **libelf**: ELF format handling (Linux)
- **CLI11**: Command-line interface (third-party/CLI11/)
- **Google Test**: Unit testing framework (for tests)