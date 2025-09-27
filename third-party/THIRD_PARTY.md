# Third-Party Libraries

This directory contains third-party libraries used by ELFtk.

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

Both libraries are licensed under the MIT License, which is compatible with the Mozilla Public License 2.0 used by ELFtk. The original license files are preserved in their respective subdirectories:

- `ihex/LICENSE` - MIT License for Intel HEX library
- `srec/LICENSE` - MIT License for Motorola S-Record library

These libraries are included directly in the repository (not as git submodules) for simplicity and to ensure a self-contained build process.