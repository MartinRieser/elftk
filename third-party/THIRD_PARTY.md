# Third-Party Libraries

This directory contains third-party libraries used by ELFtk.

## CLI11 - Command Line Parser

**Source:** https://github.com/CLIUtils/CLI11
**Author:** Henry Schreiner (University of Cincinnati)
**Version:** 2.5.0
**License:** 3-Clause BSD License (see license header in CLI11.hpp)
**Purpose:** Modern command-line parsing library

CLI11 is a command line parser for C++11 and beyond that provides a rich feature set with a simple and intuitive interface. This is a single-header version included for convenience.

## Intel HEX Library (ihex)

**Source:** https://github.com/arkku/ihex
**Author:** Kimmo Kulovesi (arkku)
**License:** MIT License (see ihex/LICENSE)
**Purpose:** Reading and writing Intel HEX format files

Small library for reading and writing the Intel HEX (or IHEX) format, mainly intended for embedded systems and microcontrollers.

## Motorola S-Record Library (srec)

**Source:** https://github.com/arkku/srec
**Author:** Kimmo Kulovesi (arkku)
**License:** MIT License (see srec/LICENSE)
**Purpose:** Reading Motorola S-Record format files

Small library for reading the Motorola S-Record (or SREC) format, mainly intended for embedded systems and microcontrollers.

## License Compliance

All libraries are licensed under permissive open source licenses (3-Clause BSD and MIT) which are compatible with the Mozilla Public License 2.0 used by ELFtk:

- `CLI11/CLI11.hpp` - 3-Clause BSD License (header-only library)
- `ihex/LICENSE` - MIT License for Intel HEX library
- `srec/LICENSE` - MIT License for Motorola S-Record library

These libraries are included directly in the repository (not as git submodules) for simplicity and to ensure a self-contained build process.