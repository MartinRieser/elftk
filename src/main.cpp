/**
 * @file main.cpp
 * @brief Modern command-line interface for elftk using CLI11 library
 *
 * This file provides a clean, maintainable entry point using the robust
 * CLI11 library for argument parsing. The main function focuses solely
 * on analysis coordination with professional-grade CLI handling.
 *
 * @section architecture_improvements Architectural Improvements
 * - **CLI11Parser**: Modern CLI parsing with automatic help/error handling
 * - **ConfigValidator**: Comprehensive option conflict detection
 * - **Automatic Features**: Help generation, error messages, validation
 * - **Standards Compliance**: Professional CLI behavior and conventions
 *
 * @section usage_examples Usage Examples
 * @code
 * // Basic usage - analyze ARM, RISC-V, ARM64, or Xtensa ELF binary
 * ./elftk firmware.elf
 *
 * // Show version information
 * ./elftk --version
 *
 * // Show help information
 * ./elftk --help
 *
 * // JSON output with constants only
 * ./elftk --json --constants firmware.elf
 * @endcode
 *
 * @author elftk Development Team
 * @date 2025
 * @copyright Mozilla Public License 2.0
 */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ElfReader.h"
#include "ElfExceptions.h"
#include "cli/CLI11Parser.h"
#include "cli/ConfigValidator.h"
#include <iostream>
#include <stdexcept>



/**
 * @brief Modern main entry point using CLI11 library
 *
 * This function provides a clean, maintainable entry point using the
 * industry-standard CLI11 library for robust argument parsing:
 * - CLI11Parser: Professional CLI parsing with automatic help/error handling
 * - ConfigValidator: Validates option combinations and conflicts
 * - ElfReader: Performs the actual ELF analysis
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return Exit status code (0 = success, 1 = error)
 *
 * @section modern_workflow CLI11-Based Workflow
 * 1. Parse arguments with CLI11 (automatic help/version/error handling)
 * 2. Validate configuration with comprehensive checks
 * 3. Execute analysis with proper error handling
 *
 * @section benefits Architectural Benefits
 * - **Professional**: Industry-standard CLI behavior and error messages
 * - **Automatic**: Help generation, validation, and error formatting
 * - **Robust**: Handles all edge cases (invalid options, file checks, etc.)
 * - **Maintainable**: Clean separation of concerns with minimal boilerplate
 */
int main(int argc, char* argv[]) {
    try {
        // Parse command-line arguments using CLI11
        // Note: CLI11 automatically handles help, version, errors, and exits appropriately
        Config config = CLI11Parser::parse(argc, argv);

        // Validate configuration for option conflicts
        auto validation_result = ConfigValidator::validate(config);
        if (!validation_result.is_valid) {
            std::cerr << "Configuration error: " << validation_result.error_message << std::endl;
            return 1;
        }

        // Display warnings if any (non-fatal issues)
        for (const auto& warning : validation_result.warnings) {
            std::cerr << "Warning: " << warning << std::endl;
        }

        // Execute ELF analysis with robust error handling
        ElfReader elf_reader(config);
        elf_reader.analyzeMemberParameters();

    } catch (const ElfReaderExceptions::ElfParsingError& e) {
        std::cerr << "ELF Analysis Error: " << e.getDetailedMessage() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

