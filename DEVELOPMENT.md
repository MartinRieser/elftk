# ELF Toolkit Development Guide

This guide explains how to set up a development environment using Docker and VS Code.

## Quick Start

### 1. Prerequisites

- Docker Desktop installed
- VS Code installed
- Git installed

### 2. One-Click Setup

```bash
# Run the setup script
./scripts/setup-dev.sh
```

### 3. Open in VS Codeπ

1. Open this project folder in VS Code
2. Install the **Dev Containers** extension by Microsoft
3. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
4. Select **"Dev Containers: Reopen in Container"**

VS Code will automatically build and connect to the development container.

## Manual Setup

### Option 1: Using Docker Compose

```bash
# Build and start the development container
docker-compose -f docker-compose.dev.yml up --build

# Attach to the running container
docker exec -it elftk-dev-container bash
```

### Option 2: Using Docker directly

```bash
# Build the development image
docker build -f .docker/Dockerfile.dev -t elftk-dev .

# Run the container
docker run -it --rm -v $(pwd):/workspace elftk-dev bash
```

## Development Workflow

### Building the Project

```bash
# Regular build
make

# Debug build
make debug

# Clean build
make clean

# Build tests
cd tests/unit && make
```

### Running Tests

```bash
# Run all tests
cd tests/unit && make test

# Run specific test
cd tests/unit && make test-filter FILTER=TestName

# Run with verbose output
cd tests/unit && make test-verbose
```

### Code Quality

```bash
# Run clang-tidy
make clang-tidy

# Fix clang-tidy issues
make clang-tidy-fix

# Run on single file
make clang-tidy-file FILE=src/YourFile.cpp
```

### Debugging

#### In VS Code

1. Set breakpoints in your code
2. Press `F5` to start debugging
3. Use the debug console for inspection

#### Command Line

```bash
# Debug with GDB
gdb ./build/bin/elftk

# Memory check with Valgrind
valgrind --leak-check=full ./build/bin/elftk --help
```

## VS Code Configuration

The development container includes:

### Extensions
- C/C++ Extension Pack
- CMake Tools
- Makefile Tools
- Python
- Hex Editor
- LLDB Debugger

### Settings
- C++17 standard
- GCC compiler
- Proper include paths
- IntelliSense configuration

### Tasks
- Build tasks (`Ctrl+Shift+B`)
- Test tasks
- Code analysis tasks

### Debug Configurations
- Debug main executable
- Debug with custom arguments
- Debug unit tests

## File Structure

```
.elftk/
├── .devcontainer/
│   └── devcontainer.json     # VS Code Dev Container config
├── .vscode/
│   ├── launch.json          # Debug configurations
│   ├── tasks.json           # Build tasks
│   └── c_cpp_properties.json # C++ IntelliSense config
├── .docker/
│   ├── Dockerfile.dev       # Development container
│   └── Dockerfile.deb       # Release build container
├── scripts/
│   └── setup-dev.sh         # Setup script
└── docker-compose.dev.yml   # Docker Compose for development
```

## Container Features

The development container includes:

- **Build Tools**: GCC, Make, CMake
- **Debugging**: GDB, Valgrind
- **Code Analysis**: Clang, Clang-tidy
- **Libraries**: libdwarf-dev, libelf-dev
- **Utilities**: Git, Vim, Curl, Python3

## Tips

1. **Hot Reload**: Changes are automatically synced to the container
2. **Persistent Build**: Build artifacts are preserved in volume
3. **Terminal Integration**: Use VS Code's integrated terminal
4. **Git Integration**: Git commands work seamlessly
5. **Extension Sync**: VS Code extensions are installed automatically

## Troubleshooting

### Container won't start
```bash
# Check Docker status
docker --version
docker-compose --version

# Rebuild container
docker-compose -f docker-compose.dev.yml build --no-cache
```

### Build errors
```bash
# Clean and rebuild
make clean
make

# Check dependencies
dpkg -l | grep -E "(libdwarf|libelf|build-essential)"
```

### IntelliSense not working
1. Reopen VS Code
2. Press `Ctrl+Shift+P` → "C/C++: Reset IntelliSense Database"
3. Check include paths in `.vscode/c_cpp_properties.json`

### Debugging issues
1. Ensure debug build: `make debug`
2. Check GDB installation: `gdb --version`
3. Verify binary has debug symbols: `file build/bin/elftk`

## Contributing

When contributing:

1. Use the development container for consistency
2. Run tests before submitting: `cd tests/unit && make test`
3. Run code analysis: `make clang-tidy`
4. Follow the code style in `.clang-format`
5. Update documentation as needed