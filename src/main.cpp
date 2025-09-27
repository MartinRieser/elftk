/**
 * @file main.cpp
 * @brief Streamlined command-line interface for elftk (ELF file tool kit for embedded software development)
 *
 * This file provides a clean, maintainable entry point that delegates
 * complex operations to specialized components. The main function focuses
 * solely on coordination between parsing, validation, and analysis.
 *
 * @section architecture_improvements Architectural Improvements
 * - **CommandLineParser**: Type-safe argument parsing with validation
 * - **ConfigValidator**: Comprehensive option conflict detection
 * - **VersionInfo**: Centralized version and help text management
 * - **Minimal main()**: Clean separation of concerns
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
#include "cli/CommandLineParser.h"
#include "cli/VersionInfo.h"
#include "cli/ConfigValidator.h"
#include <iostream>
#include <stdexcept>



/**
 * @brief Streamlined main entry point for ELF Symbol Reader
 *
 * This function provides a clean, maintainable entry point that delegates
 * complex operations to specialized components:
 * - CommandLineParser: Handles all argument parsing and validation
 * - VersionInfo: Manages version and help text display
 * - ConfigValidator: Validates option combinations and conflicts
 * - ElfReader: Performs the actual ELF analysis
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return Exit status code (0 = success, 1 = error)
 *
 * @section improved_workflow Modern Workflow
 * 1. Parse arguments with type-safe CommandLineParser
 * 2. Handle help/version requests via VersionInfo
 * 3. Validate configuration with comprehensive checks
 * 4. Execute analysis with proper error handling
 *
 * @section benefits Architectural Benefits
 * - **Testable**: Each component can be unit tested independently
 * - **Maintainable**: Clear separation of concerns
 * - **Extensible**: Easy to add new options without code duplication
 * - **Robust**: Comprehensive validation and error handling
 */
int main(int argc, char* argv[]) {
    // Parse command-line arguments with comprehensive validation
    auto parse_result = CommandLineParser::parse(argc, argv);

    // Handle immediate exit requests (help, version, or errors)
    if (parse_result.should_exit) {
        if (parse_result.help_requested) {
            VersionInfo::showHelp(argv[0]);
        } else if (parse_result.version_requested) {
            VersionInfo::showVersion();
        }
        return parse_result.exit_code;
    }

    // Handle parsing errors
    if (!parse_result.error_message.empty()) {
        std::cerr << parse_result.error_message << std::endl;
        std::cerr << "Use --help for usage information." << std::endl;
        return 1;
    }

    // Additional validation (redundant check, but provides detailed warnings)
    auto validation_result = ConfigValidator::validate(parse_result.config);
    if (!validation_result.is_valid) {
        std::cerr << "Configuration error: " << validation_result.error_message << std::endl;
        return 1;
    }

    // Display warnings if any (non-fatal issues)
    for (const auto& warning : validation_result.warnings) {
        std::cerr << "Warning: " << warning << std::endl;
    }

    // Execute ELF analysis with robust error handling
    try {
        ElfReader elf_reader(parse_result.config);
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

