/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @file OutputGenerator.cpp
 * @brief Implementation of output formatting for ELF analysis results
 *
 * This file implements JSON and CSV output generation for ELF symbol analysis.
 * Extracted from ElfReader.cpp during Phase 3 refactoring (October 2025).
 *
 * ## Key Methods:
 * - generateJsonOutput() - Structured JSON with architecture metadata
 * - generateCsvOutput() - Tabular CSV with headers
 * - generateFunctionJsonOutput() - Function-specific JSON
 * - generateFunctionCsvOutput() - Function-specific CSV
 *
 * ## Design:
 * Uses dependency injection pattern to minimize coupling with ElfReader.
 * Architecture info provided via constructor, symbol tables optionally passed to methods.
 *
 * @see OutputGenerator.h for class documentation
 * @see doc/TASK_3.1_COMPLETE.md for extraction details
 */

#include "OutputGenerator.h"
#include <functional>
#include <iomanip>
#include <iostream>
#include "../ElfReader.h"  // For Config struct

OutputGenerator::OutputGenerator(bool is_32bit, bool is_little_endian, uint64_t entry_point)
    : is_32bit_(is_32bit), is_little_endian_(is_little_endian), entry_point_(entry_point) {}

void OutputGenerator::generateJsonOutput(const std::vector<MemberInfo>& members,
                                         const Config& config,
                                         std::function<std::string(uint64_t)> get_section_name_fn,
                                         const std::vector<Elf32_Sym>* symbols32,
                                         const std::vector<Elf64_Sym>* symbols64) const {
    (void)get_section_name_fn;  // Unused: reserved for future expansion
    std::cout << "{\n";
    std::cout << "  \"architecture\": \"" << (is_32bit_ ? "32-bit" : "64-bit") << " "
              << (is_little_endian_ ? "Little" : "Big") << " Endian\",\n";
    std::cout << "  \"entryPoint\": \"0x" << std::hex << std::setw(8) << std::setfill('0')
              << entry_point_ << "\",\n";

    std::cout << "  \"parameters\": [\n";
    for (size_t i = 0; i < members.size(); ++i) {
        const auto& member = members[i];
        std::cout << "    {\n";
        std::cout << "      \"name\": \"" << member.name << "\",\n";
        std::cout << "      \"address\": \"0x" << std::hex << std::setw(8) << std::setfill('0')
                  << member.address << "\",\n";
        std::cout << "      \"size\": " << std::dec << member.byte_size << ",\n";
        std::cout << "      \"type\": \"" << member.type << "\"";

        if (member.is_constant) {
            std::cout << ",\n      \"is_constant\": true";
            if (!member.constant_value.empty()) {
                std::cout << ",\n      \"constant_value\": \"" << member.constant_value << "\"";
            }
        }

        if (config.showSections && !member.section_name.empty()) {
            std::cout << ",\n      \"section\": \"" << member.section_name << "\"";
        }

        std::cout << "\n    }" << (i == members.size() - 1 ? "" : ",") << "\n";
    }
    std::cout << "  ]";

    // Include functions if not variables-only mode
    if (!config.variablesOnly && (symbols32 || symbols64)) {
        std::cout << ",\n";
        std::cout << "  \"functions\": [\n";

        if (is_32bit_ && symbols32) {
            for (size_t i = 0; i < symbols32->size(); ++i) {
                const auto& symbol = (*symbols32)[i];
                if (!symbol.name.empty() &&
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) &&
                    symbol.st_value != 0) {
                    std::cout << "    {\n";
                    std::cout << "      \"name\": \"" << symbol.name << "\",\n";
                    std::cout << "      \"address\": \"0x" << std::hex << std::setw(8)
                              << std::setfill('0') << symbol.st_value << "\"\n";
                    std::cout << "    }" << (i == symbols32->size() - 1 ? "" : ",") << "\n";
                }
            }
        } else if (!is_32bit_ && symbols64) {
            for (size_t i = 0; i < symbols64->size(); ++i) {
                const auto& symbol = (*symbols64)[i];
                if (!symbol.name.empty() &&
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) &&
                    symbol.st_value != 0) {
                    std::cout << "    {\n";
                    std::cout << "      \"name\": \"" << symbol.name << "\",\n";
                    std::cout << "      \"address\": \"0x" << std::hex << std::setw(8)
                              << std::setfill('0') << symbol.st_value << "\"\n";
                    std::cout << "    }" << (i == symbols64->size() - 1 ? "" : ",") << "\n";
                }
            }
        }
        std::cout << "  ]\n";
    } else {
        std::cout << "\n";
    }

    std::cout << "}\n";
}

void OutputGenerator::generateCsvOutput(const std::vector<MemberInfo>& members,
                                        const Config& config) const {
    // CSV Header
    std::cout << "Name,Address,Size,Type";
    if (config.showSections) {
        std::cout << ",Section";
    }
    std::cout << ",Value";  // Always include Value column for constants
    std::cout << "\n";

    // CSV Data rows
    for (const auto& member : members) {
        std::cout << member.name << ",0x" << std::hex << std::setw(8) << std::setfill('0')
                  << member.address << "," << std::dec << member.byte_size << "," << member.type;

        if (config.showSections) {
            std::cout << ",";
            if (!member.section_name.empty()) {
                std::cout << member.section_name;
            }
        }

        std::cout << ",";
        if (member.is_constant && !member.constant_value.empty()) {
            std::cout << member.constant_value;
        }

        std::cout << "\n";
    }
}

void OutputGenerator::generateFunctionCsvOutput(
    const std::vector<FunctionInfo>& functions,
    const Config& config,
    std::function<std::string(uint64_t)> get_section_name_fn) const {
    // CSV Header for functions
    std::cout << "Name,Address,Type";
    if (config.showSections) {
        std::cout << ",Section";
    }
    std::cout << "\n";

    // CSV Data rows for functions
    for (const auto& function : functions) {
        std::cout << function.name << ",0x" << std::hex << std::setw(8) << std::setfill('0')
                  << function.start_address << ",function";

        if (config.showSections && get_section_name_fn) {
            std::cout << ",";
            std::string section_name = get_section_name_fn(function.start_address);
            if (!section_name.empty()) {
                std::cout << section_name;
            }
        }

        std::cout << "\n";
    }
}

void OutputGenerator::generateFunctionJsonOutput(
    const std::vector<FunctionInfo>& functions,
    const Config& config,
    std::function<std::string(uint64_t)> get_section_name_fn) const {
    std::cout << "{\n";
    std::cout << "  \"architecture\": \"" << (is_32bit_ ? "32-bit" : "64-bit") << " "
              << (is_little_endian_ ? "Little" : "Big") << " Endian\",\n";
    std::cout << "  \"entryPoint\": \"0x" << std::hex << std::setw(8) << std::setfill('0')
              << entry_point_ << "\",\n";

    std::cout << "  \"functions\": [\n";
    for (size_t i = 0; i < functions.size(); ++i) {
        const auto& function = functions[i];
        std::cout << "    {\n";
        std::cout << "      \"name\": \"" << function.name << "\",\n";
        std::cout << "      \"address\": \"0x" << std::hex << std::setw(8) << std::setfill('0')
                  << function.start_address << "\",\n";
        std::cout << "      \"type\": \"function\"";

        if (config.showSections && get_section_name_fn) {
            std::string section_name = get_section_name_fn(function.start_address);
            if (!section_name.empty()) {
                std::cout << ",\n      \"section\": \"" << section_name << "\"";
            }
        }

        std::cout << "\n    }" << (i == functions.size() - 1 ? "" : ",") << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

std::vector<MemberInfo> OutputGenerator::convertEnhancedSymbols(
    const std::vector<ExtractedSymbol>& enhanced_symbols,
    const Config& config
) const {
    std::vector<MemberInfo> converted_members;
    converted_members.reserve(enhanced_symbols.size());

    for (const auto& symbol : enhanced_symbols) {
        // Only include variable symbols, not functions
        if (!symbol.isVariable || symbol.name.empty()) {
            continue;
        }

        // Create display name with demangled version if available
        std::string display_name = symbol.name;
        if (config.enableCxxDemangling && !symbol.demangledName.empty() &&
            symbol.demangledName != symbol.name) {
            display_name = symbol.demangledName;
            if (config.showMangledNames) {
                display_name += " (" + symbol.name + ")";
            }
        }

        // Convert symbol type to readable type string
        std::string type_str = "unknown";
        if (!symbol.section.empty()) {
            type_str = symbol.section;
        }
        if (symbol.elementCount > 1) {
            type_str += "[" + std::to_string(symbol.elementCount) + "]";
        }

        // Create MemberInfo structure
        MemberInfo member_info(
            display_name,           // Use interned string or raw string
            symbol.address,         // Symbol address
            type_str               // Type information
        );

        member_info.byte_size = symbol.size;

        // Add constant value if available
        if (symbol.isGlobal && symbol.size > 0 && symbol.size <= 8) {
            // For small global variables, we could try to read values
            // but for now, leave empty unless it's a known constant
            member_info.is_constant = false;
        }

        // Set section name if available
        if (config.showSections && !symbol.section.empty()) {
            member_info.section_name = symbol.section;
        }

        // Add to converted list
        converted_members.push_back(member_info);
    }

    return converted_members;
}
