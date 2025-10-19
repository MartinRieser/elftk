/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "../ElfStructures.h"
#include "../ElfSymbolExtractor.h"
#include <vector>
#include <string>
#include <cstdint>
#include <functional>

// Forward declaration
struct Config;

/**
 * @class OutputGenerator
 * @brief Generates formatted output (JSON/CSV) for ELF analysis results
 *
 * This module handles all output generation for ELF symbol and function analysis.
 * It supports multiple output formats (JSON, CSV) and can include optional metadata
 * like section names.
 *
 * ## Design Pattern: Dependency Injection
 * OutputGenerator uses dependency injection to minimize coupling with ElfReader.
 * Architecture information is provided via constructor, and symbol tables are
 * optionally passed to methods that need them.
 *
 * ## Supported Output Formats:
 * - **JSON**: Structured format with architecture metadata
 *   ```json
 *   {
 *     "architecture": "32-bit Little Endian",
 *     "entryPoint": "0x08000100",
 *     "parameters": [...]
 *   }
 *   ```
 * - **CSV**: Tabular format with headers for spreadsheet compatibility
 *   ```
 *   Name,Address,Size,Type,Value
 *   variable,0x20000000,4,int,42
 *   ```
 *
 * ## Features:
 * - Member/variable output with addresses and types
 * - Function symbol output
 * - Constant value display
 * - Optional section name display
 * - Architecture and entry point metadata
 *
 * ## Usage Example:
 * ```cpp
 * OutputGenerator generator(is_32bit, is_little_endian, entry_point);
 * generator.generateJsonOutput(members, config);
 * ```
 *
 * ## Extracted from ElfReader
 * This module was extracted from ElfReader.cpp (Phase 3, Task 3.1, October 2025)
 * to improve modularity and reduce file size. See doc/TASK_3.1_COMPLETE.md for details.
 *
 * @author ELF Symbol Reader Project
 * @date October 2025
 * @see ElfReader
 * @see MemberInfo
 * @see FunctionInfo
 */
class OutputGenerator {
public:
    /**
     * @brief Construct OutputGenerator with ELF binary metadata
     *
     * Stores architecture information needed for output generation.
     * This constructor uses dependency injection to avoid coupling with ElfReader internals.
     *
     * @param is_32bit Whether the ELF is 32-bit (true) or 64-bit (false)
     * @param is_little_endian Whether the ELF is little-endian (true) or big-endian (false)
     * @param entry_point The entry point address of the ELF binary
     *
     * @note Architecture string generated: "32-bit Little Endian", "64-bit Big Endian", etc.
     */
    OutputGenerator(bool is_32bit, bool is_little_endian, uint64_t entry_point);

    /**
     * @brief Generate JSON output for variables and members
     *
     * Produces JSON output with the following structure:
     * ```json
     * {
     *   "architecture": "32-bit Little Endian",
     *   "entryPoint": "0x08000100",
     *   "parameters": [
     *     {
     *       "name": "variable",
     *       "address": "0x20000000",
     *       "size": 4,
     *       "type": "int",
     *       "value": "42"
     *     }
     *   ]
     * }
     * ```
     *
     * @param members Vector of MemberInfo structures to output
     * @param config Configuration containing output options (showSections, variablesOnly)
     * @param get_section_name_fn Optional function to get section name for an address (currently unused)
     * @param symbols32 Optional 32-bit symbol table (reserved for future use)
     * @param symbols64 Optional 64-bit symbol table (reserved for future use)
     *
     * @note Output is written to stdout
     * @note get_section_name_fn parameter reserved for future section name display feature
     *
     * @see generateCsvOutput() for CSV format alternative
     */
    void generateJsonOutput(
        const std::vector<MemberInfo>& members,
        const Config& config,
        std::function<std::string(uint64_t)> get_section_name_fn = nullptr,
        const std::vector<Elf32_Sym>* symbols32 = nullptr,
        const std::vector<Elf64_Sym>* symbols64 = nullptr
    ) const;

    /**
     * @brief Generate CSV output for variables and members
     *
     * Produces CSV output with headers for spreadsheet compatibility:
     * ```
     * Name,Address,Size,Type,Value
     * CHAR_CONST,0x08000010,1,signed char,-120
     * variable,0x20000000,4,int,
     * ```
     *
     * @param members Vector of MemberInfo structures to output
     * @param config Configuration containing output options (showSections)
     *
     * @note Output is written to stdout
     * @note Values are properly escaped for CSV (commas, quotes)
     * @note Empty value field for variables without constant values
     *
     * @see generateJsonOutput() for JSON format alternative
     */
    void generateCsvOutput(
        const std::vector<MemberInfo>& members,
        const Config& config
    ) const;

    /**
     * @brief Generate CSV output for functions only
     *
     * Produces CSV output specifically for function symbols:
     * ```
     * Name,Address,Type
     * main,0x08000100,function
     * setup,0x08000200,function
     * ```
     *
     * @param functions Vector of FunctionInfo structures to output
     * @param config Configuration containing output options (showSections)
     * @param get_section_name_fn Function to get section name for an address
     *
     * @note Output is written to stdout
     * @note Includes optional Section column if config.showSections is true
     *
     * @see generateFunctionJsonOutput() for JSON format alternative
     */
    void generateFunctionCsvOutput(
        const std::vector<FunctionInfo>& functions,
        const Config& config,
        std::function<std::string(uint64_t)> get_section_name_fn
    ) const;

    /**
     * @brief Generate JSON output for functions only
     *
     * Produces JSON output specifically for function symbols:
     * ```json
     * {
     *   "architecture": "32-bit Little Endian",
     *   "entryPoint": "0x08000100",
     *   "functions": [
     *     {"name": "main", "address": "0x08000100", "type": "function"}
     *   ]
     * }
     * ```
     *
     * @param functions Vector of FunctionInfo structures to output
     * @param config Configuration containing output options (showSections)
     * @param get_section_name_fn Function to get section name for an address
     *
     * @note Output is written to stdout
     * @note Includes optional "section" field if config.showSections is true
     *
     * @see generateFunctionCsvOutput() for CSV format alternative
     */
    void generateFunctionJsonOutput(
        const std::vector<FunctionInfo>& functions,
        const Config& config,
        std::function<std::string(uint64_t)> get_section_name_fn
    ) const;

    /**
     * @brief Convert enhanced ELF symbols to MemberInfo format for output
     *
     * Converts ExtractedSymbol structures from ElfSymbolExtractor into MemberInfo
     * structures that can be used with existing output methods.
     *
     * @param enhanced_symbols Vector of enhanced symbols to convert
     * @param config Configuration for output options
     * @return Vector of MemberInfo structures for output
     */
    std::vector<MemberInfo> convertEnhancedSymbols(
        const std::vector<ExtractedSymbol>& enhanced_symbols,
        const Config& config
    ) const;

private:
    bool is_32bit_;              ///< Whether ELF is 32-bit
    bool is_little_endian_;      ///< Whether ELF is little-endian
    uint64_t entry_point_;       ///< ELF entry point address
};
