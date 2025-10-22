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

#include <iostream>
#include <stdexcept>
#include "ElfExceptions.h"
#include "ElfReader.h"
#include "ElfSymbolExtractor.h"
#include "cli/CLI11Parser.h"
#include "cli/ConfigValidator.h"

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
        // Note: CLI11 automatically handles help, version, errors, and returns appropriate codes
        auto config_result = CLI11Parser::parse(argc, argv);
        if (!config_result) {
            // CLI11 already printed the error/help message
            return 1;
        }
        Config config = *config_result;

        // Validate configuration for option conflicts
        auto validationResult = ConfigValidator::validate(config);
        if (!validationResult.is_valid) {
            std::cerr << "Configuration error: " << validationResult.error_message << '\n';
            return 1;
        }

        // Display warnings if any (non-fatal issues)
        for (const auto& warning : validationResult.warnings) {
            std::cerr << "Warning: " << warning << '\n';
        }

        // Extract additional symbols from ELF symbol table and sections
        if (!config.functionsOnly && config.enableElfSymbolExtraction) {
            auto extractedSymbols = ElfSymbolExtractor::extractSymbols(config.inputFile);
            auto variables = ElfSymbolExtractor::getVariables(extractedSymbols);
            auto linkerSymbols = ElfSymbolExtractor::getLinkerSymbols(extractedSymbols);

            // Extract section information and discover additional variables
            auto sections = ElfSymbolExtractor::extractSections(config.inputFile);
            auto memoryLayout = ElfSymbolExtractor::getMemoryLayout(config.inputFile);
            auto discoveredVars =
                ElfSymbolExtractor::discoverSectionVariables(sections, extractedSymbols);

            // Detect array bounds and enhance symbols with element count
            auto enhancedSymbols =
                ElfSymbolExtractor::detectArrayBounds(extractedSymbols, sections);

            // Extract cross-reference symbols from relocation entries
            auto xrefSymbols = ElfSymbolExtractor::extractCrossReferenceSymbols(config.inputFile);

            // Extract weak symbols (interrupt handlers, default implementations) from
            // enhanced symbols
            auto weakSymbols = ElfSymbolExtractor::getWeakSymbols(enhancedSymbols);
            auto enhancedVariables = ElfSymbolExtractor::getVariables(enhancedSymbols);

            // Execute ELF analysis with enhanced symbols integration
            ElfReader elfReader(config);
            elfReader.addEnhancedSymbols(enhancedSymbols);
            elfReader.analyzeMemberParameters();

            // Combine all variables for output
            // (The enhanced symbols will be used by the OutputGenerator)
        } else {
            // Execute ELF analysis without enhanced symbols
            ElfReader elfReader(config);
            elfReader.analyzeMemberParameters();
        }

    } catch (const ElfReaderExceptions::ElfParsingError& e) {
        std::cerr << "ELF Analysis Error: " << e.getDetailedMessage() << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
