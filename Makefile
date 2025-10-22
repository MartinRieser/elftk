# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# ===============================================
# Configurable Build Environment
# ===============================================
#
# These variables can be overridden via environment variables or command line:
#
# For Windows/MSYS2:
#   MSYS2_ROOT=/d/tools/msys64 make windows
#   MINGW64_PATH=/d/tools/msys64/mingw64 make windows
#
# For macOS:
#   HOMEBREW_PREFIX=/usr/local make macos
#   HOMEBREW_PREFIX=/opt/homebrew make macos  (Apple Silicon default)
#
# For installation:
#   INSTALL_PREFIX=/opt/local make install
#   INSTALL_PREFIX=$HOME/.local make install
#
# Examples:
#   make windows MSYS2_ROOT=/d/msys64
#   make macos HOMEBREW_PREFIX=/usr/local
#   make install INSTALL_PREFIX=$HOME/.local

# OS Detection for early compiler selection
UNAME_S := $(shell uname -s)

# Configurable paths - can be overridden via environment variables or command line
MSYS2_ROOT ?= /c/msys64
HOMEBREW_PREFIX ?= /opt/homebrew
INSTALL_PREFIX ?= /usr/local
MINGW64_PATH ?= $(MSYS2_ROOT)/mingw64
UCRT64_PATH ?= $(MSYS2_ROOT)/ucrt64

# Set compiler based on OS
ifneq (,$(findstring MINGW,$(UNAME_S)))
    # Use MinGW gcc from PATH (requires mingw64/bin in PATH)
    CXX = g++
    export PATH := $(MINGW64_PATH)/bin:$(UCRT64_PATH)/bin:$(PATH)
else ifneq (,$(findstring MSYS_NT,$(UNAME_S)))
    CXX = g++
    export PATH := $(MINGW64_PATH)/bin:$(UCRT64_PATH)/bin:$(PATH)
else
    CXX = g++
endif
BUILD_DATE := $(shell date '+%Y-%m-%d')
BUILD_TIME := $(shell date '+%H:%M:%S')
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -DBUILD_DATE='"$(BUILD_DATE)"' -DBUILD_TIME='"$(BUILD_TIME)"' -DHAVE_LIBDWARF=1

# Windows-specific compiler flags to avoid temp directory permission issues
ifneq (,$(findstring MINGW,$(UNAME_S)))
    CXXFLAGS += -pipe
endif

# Platform-specific settings
ifeq ($(UNAME_S),Darwin)
    # macOS settings (Homebrew) - configurable via HOMEBREW_PREFIX
    LDFLAGS = -L$(HOMEBREW_PREFIX)/lib -ldwarf -lelf
    INCLUDES = -I$(HOMEBREW_PREFIX)/include/libdwarf-2 -I$(HOMEBREW_PREFIX)/include
else ifeq ($(UNAME_S),Linux)
    # Linux settings - prioritize newer libdwarf installation
    LDFLAGS = -ldwarf

    # Check for newer libdwarf in /usr/local (built from source)
    ifneq (,$(wildcard /usr/local/include/libdwarf/libdwarf.h))
        INCLUDES = -I/usr/local/include/libdwarf -I/usr/include/elfutils -I/usr/include
        LDFLAGS = -L/usr/local/lib -ldwarf -lelf -lz
        $(info Using newer libdwarf from /usr/local)
    else
        # Try pkg-config for system libdwarf
        PKG_CONFIG_INCLUDES := $(shell pkg-config --cflags libdwarf 2>/dev/null)
        ifneq ($(PKG_CONFIG_INCLUDES),)
            INCLUDES = $(PKG_CONFIG_INCLUDES)
            LDFLAGS = $(shell pkg-config --libs libdwarf 2>/dev/null)
        else
            # Fallback paths for Ubuntu/Debian - try multiple common locations
            DWARF_HEADER_PATHS := /usr/include/libdwarf /usr/include/elfutils /usr/include/libelf /usr/include
            INCLUDES := $(foreach path,$(DWARF_HEADER_PATHS),-I$(path))
            
            # Check if elfutils headers are available
            ifneq (,$(wildcard /usr/include/elfutils/libelf.h))
                CXXFLAGS += -DHAVE_ELFUTILS_HEADERS=1
            endif
            
            LDFLAGS = -ldwarf -lelf -lz
        endif
    endif
else ifneq (,$(findstring MINGW,$(UNAME_S)))
    # Windows MSYS2/MinGW settings

    # Windows-specific flags (none needed for basic linking)
    WINDOWS_FLAGS =

    # Check for static linking preference
    ifdef STATIC_BUILD
        # Static build configuration
        CXXFLAGS += -static-libgcc -static-libstdc++ -static
        # Try to find static libdwarf library
        ifeq (,$(wildcard $(MINGW64_PATH)/lib/libdwarf.a))
            $(warning Static libdwarf not found. Install it or build from source for fully static builds.)
            $(warning Using dynamic libdwarf as fallback...)
            LDFLAGS = -L$(MINGW64_PATH)/lib -ldwarf
        else
            LDFLAGS = -L$(MINGW64_PATH)/lib -l:libdwarf.a -lz
        endif
    else
        # Dynamic build (default for Windows) - allow override from environment/command line
        LDFLAGS = -L$(MINGW64_PATH)/lib -ldwarf  -lelf -Wl,--unresolved-symbols=ignore-in-object-files
    endif

    # Add Windows-specific linker flags
    LDFLAGS += $(WINDOWS_FLAGS)

    # Include directories - allow override from environment/command line for GitHub Actions
    INCLUDES = -I$(MINGW64_PATH)/include/libdwarf-2 -I$(MINGW64_PATH)/include
    
    # Windows: libelf/elfutils are typically not available
    # Check if elfutils headers are available (unlikely on Windows)
    ifneq (,$(wildcard $(MINGW64_PATH)/include/elfutils/libelf.h))
        INCLUDES += -I$(MINGW64_PATH)/include/elfutils
        CXXFLAGS += -DHAVE_ELFUTILS_HEADERS=1 -DHAVE_LIBELF=1
    else ifneq (,$(wildcard $(MINGW64_PATH)/include/libelf.h))
        CXXFLAGS += -DHAVE_LIBELF=1
    else
        $(warning Windows libelf/elfutils headers not found. Building with limited ELF functionality.)
        CXXFLAGS += -DHAVE_LIBELF=0
    endif

    # Ensure ARM toolchain is available for examples
    export PATH := $(MINGW64_PATH)/bin:$(PATH)

else
    # Default/unknown OS - use minimal settings
    LDFLAGS =
    INCLUDES =
endif

# Directory structure
SRCDIR = src
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin

# Third-party libraries
THIRDPARTY_DIR = third-party
IHEX_DIR = $(THIRDPARTY_DIR)/ihex
SREC_DIR = $(THIRDPARTY_DIR)/srec
CLI11_DIR = $(THIRDPARTY_DIR)/CLI11

# Add third-party include paths
INCLUDES += -I$(IHEX_DIR) -I$(SREC_DIR) -I$(CLI11_DIR)

# Files
SOURCES = $(wildcard $(SRCDIR)/*.cpp) $(wildcard $(SRCDIR)/cli/*.cpp) $(wildcard $(SRCDIR)/output/*.cpp) $(wildcard $(SRCDIR)/dwarf/*.cpp)
OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

# Third-party objects
THIRDPARTY_OBJECTS = $(OBJDIR)/kk_ihex_read.o $(OBJDIR)/kk_ihex_write.o $(OBJDIR)/kk_srec.o

TARGET = $(BINDIR)/elftk

# Library targets
# Library support removed - CLI tool only

.PHONY: all clean debug debug-vars macos macos-dist windows windows-static windows-dist deb deb-build deb-clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS) $(THIRDPARTY_OBJECTS) | $(BINDIR)
ifneq (,$(findstring MINGW,$(UNAME_S)))
	# Windows: Set temp directory and link manually to avoid permission issues
	mkdir -p temp-build && cd $(BINDIR) && TMPDIR=../../temp-build TMP=../../temp-build TEMP=../../temp-build $(CXX) -o $(notdir $@) $(addprefix ../../,$(OBJECTS)) $(addprefix ../../,$(THIRDPARTY_OBJECTS)) $(LDFLAGS)
else
	$(CXX) $(OBJECTS) $(THIRDPARTY_OBJECTS) $(LDFLAGS) -o $@
endif

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Third-party library compilation rules (use C compiler for C files)
$(OBJDIR)/kk_ihex_read.o: $(IHEX_DIR)/kk_ihex_read.c | $(OBJDIR)
ifneq (,$(findstring MINGW,$(UNAME_S)))
	gcc -pipe -c $< -o $@ -I$(IHEX_DIR)
else
	gcc -c $< -o $@ -I$(IHEX_DIR)
endif

$(OBJDIR)/kk_ihex_write.o: $(IHEX_DIR)/kk_ihex_write.c | $(OBJDIR)
ifneq (,$(findstring MINGW,$(UNAME_S)))
	gcc -pipe -c $< -o $@ -I$(IHEX_DIR)
else
	gcc -c $< -o $@ -I$(IHEX_DIR)
endif

$(OBJDIR)/kk_srec.o: $(SREC_DIR)/kk_srec.c | $(OBJDIR)
ifneq (,$(findstring MINGW,$(UNAME_S)))
	gcc -pipe -c $< -o $@ -I$(SREC_DIR)
else
	gcc -c $< -o $@ -I$(SREC_DIR)
endif

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

debug: CXXFLAGS += -DDEBUG -O0
debug: clean $(TARGET)

debug-vars:
	@echo "=== Makefile Variables Debug ==="
	@echo "UNAME_S: $(UNAME_S)"
	@echo "CXX: $(CXX)"
	@echo "CXXFLAGS: $(CXXFLAGS)"
	@echo "INCLUDES: $(INCLUDES)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "PKG_CONFIG_INCLUDES: $(PKG_CONFIG_INCLUDES)"
	@echo "DWARF_HEADER_PATHS: $(DWARF_HEADER_PATHS)"
	@echo "TARGET: $(TARGET)"
	@echo "=========================="

clean:
	rm -rf $(BUILDDIR)

install: $(TARGET)
	cp $(TARGET) $(INSTALL_PREFIX)/bin/elftk

uninstall:
	rm -f $(INSTALL_PREFIX)/bin/elftk

# ==========================================
# Platform-Specific Build Targets
# ==========================================

macos: $(TARGET)
	@echo "Building for macOS..."
	@echo "Copying required dylibs for standalone distribution..."
	@cp $(HOMEBREW_PREFIX)/lib/libdwarf.2.dylib $(BINDIR)/ 2>/dev/null || cp /usr/local/lib/libdwarf.2.dylib $(BINDIR)/ 2>/dev/null || true
	@echo "Updating library paths for portability..."
	@install_name_tool -change $(HOMEBREW_PREFIX)/opt/dwarfutils/lib/libdwarf.2.dylib @executable_path/libdwarf.2.dylib $(TARGET) 2>/dev/null || true
	@install_name_tool -change /usr/local/lib/libdwarf.2.dylib @executable_path/libdwarf.2.dylib $(TARGET) 2>/dev/null || true
	@echo "macOS build completed. Binary: $(TARGET)"
	@echo "Note: Required dylibs have been copied to $(BINDIR) for standalone execution."

# Create distributable macOS package
macos-dist: macos
	@echo "Creating distributable macOS package..."
	@rm -rf dist/ELFSymbolReader-macOS
	@mkdir -p dist/ELFSymbolReader-macOS
	@cp $(BINDIR)/* dist/ELFSymbolReader-macOS/
	@chmod +w dist/ELFSymbolReader-macOS/* 2>/dev/null || true
	@cp README.md dist/ELFSymbolReader-macOS/
	@cp LICENSE dist/ELFSymbolReader-macOS/
	@echo "Distribution package created in dist/ELFSymbolReader-macOS/"
	@echo "This directory can be copied to any macOS system and will work standalone."

# Windows-specific build targets
windows:
	@echo "Building for Windows..."
	@echo "Note: Ensure MinGW64 is in PATH: export PATH=\"/c/msys64/mingw64/bin:\$$PATH\""
	@$(MAKE) $(TARGET)
	@echo "Copying required DLLs for standalone distribution..."
	@cp $(MINGW64_PATH)/bin/libdwarf-2.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/libdwarf-2.dll $(BINDIR)/ 2>/dev/null || true
	@cp $(MINGW64_PATH)/bin/libdwarfp-2.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/libdwarfp-2.dll $(BINDIR)/ 2>/dev/null || true
	@cp $(MINGW64_PATH)/bin/libgcc_s_seh-1.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/libgcc_s_seh-1.dll $(BINDIR)/ 2>/dev/null || true
	@cp $(MINGW64_PATH)/bin/libstdc++-6.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/libstdc++-6.dll $(BINDIR)/ 2>/dev/null || true
	@cp $(MINGW64_PATH)/bin/libwinpthread-1.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/libwinpthread-1.dll $(BINDIR)/ 2>/dev/null || true
	@cp $(MINGW64_PATH)/bin/zlib1.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/zlib1.dll $(BINDIR)/ 2>/dev/null || true
	@cp $(MINGW64_PATH)/bin/libzstd.dll $(BINDIR)/ 2>/dev/null || cp /mingw64/bin/libzstd.dll $(BINDIR)/ 2>/dev/null || true
	@echo "Windows build completed. Binary: $(TARGET).exe"
	@echo "Note: Required DLLs have been copied to $(BINDIR) for standalone execution."

windows-static: STATIC_BUILD=1
windows-static:
	@echo "Building for Windows (static)..."
	@echo "Note: Ensure MinGW64 is in PATH: export PATH=\"/c/msys64/mingw64/bin:\$$PATH\""
	@$(MAKE) clean $(TARGET)
	@echo "Windows static build completed. Binary: $(TARGET).exe"
	@echo "Note: If libdwarf.a is not available, this will fall back to dynamic linking."

# Create distributable Windows package
windows-dist: windows
	@echo "Creating distributable Windows package..."
	@mkdir -p build/dist
	@rm -rf build/dist/elftk-windows-temp
	@mkdir -p build/dist/elftk-windows-temp
	@cp $(BINDIR)/* build/dist/elftk-windows-temp/
	@cp README.md build/dist/elftk-windows-temp/
	@cp LICENSE build/dist/elftk-windows-temp/
	@echo "Creating ZIP archive..."
	@cd build/dist && powershell -Command "Compress-Archive -Path 'elftk-windows-temp/*' -DestinationPath 'elftk-windows-portable.zip' -Force"
	@rm -rf build/dist/elftk-windows-temp
	@echo ""
	@echo "✅ Windows distribution package created successfully!"
	@echo "📁 Location: build/dist/elftk-windows-portable.zip"
	@echo "📦 Size: $$(du -h build/dist/elftk-windows-portable.zip | cut -f1)"
	@echo ""
	@echo "This ZIP file contains elftk.exe and all required DLLs."
	@echo "Users can unpack it anywhere on their Windows PC and use it immediately."
	@echo ""
	@echo "Contents:"
	@echo "  - elftk.exe (main executable)"
	@echo "  - Required DLLs (libdwarf-2.dll, libstdc++-6.dll, etc.)"
	@echo "  - README.md (documentation)"
	@echo "  - LICENSE (license file)"

# ===============================================
# Debian Package Generation
# ===============================================

# Build .deb package using Docker
deb:
	@echo "Building .deb package using Docker..."
	@echo "Note: This requires Docker to be installed and running."
	@echo "Building Docker image for .deb generation..."
	@docker build -f .docker/Dockerfile.deb -t elftk-deb-builder .
	@echo "Creating .deb package..."
	@mkdir -p build/dist
	@echo "Running container to build package..."
	@docker run --name temp-deb-builder elftk-deb-builder
	@echo "Copying .deb package from container..."
	@docker cp temp-deb-builder:/output/elftk_1.0.0_amd64.deb ./build/dist/
	@docker rm temp-deb-builder
	@echo ""
	@echo "✅ .deb package created successfully!"
	@echo "📁 Location: build/dist/elftk_1.0.0_amd64.deb"
	@echo "📦 Size: $$(du -h build/dist/elftk_1.0.0_amd64.deb | cut -f1)"
	@echo ""
	@echo "To install the package:"
	@echo "  sudo dpkg -i build/dist/elftk_1.0.0_amd64.deb"
	@echo "  sudo apt-get install -f  # Install missing dependencies if any"
	@echo ""
	@echo "To verify installation:"
	@echo "  elftk --help"
	@echo "  dpkg -l | grep elftk"
	@echo ""
	@echo "To uninstall:"
	@echo "  sudo apt-get remove elftk"

# Alternative target name for clarity
deb-build: deb

# Clean deb build artifacts
deb-clean:
	@echo "Cleaning .deb build artifacts..."
	@rm -rf build/dist/elftk_*.deb
	@docker rmi elftk-deb-builder 2>/dev/null || true
	@echo ".deb build artifacts cleaned."