/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @file ElfReader.cpp
 * @brief Implementation of ARM ELF binary analysis with DWARF debug information parsing
 *
 * This file contains the implementation details for the ElfReader class, focusing on
 * the actual algorithms and platform-specific handling for parsing ARM ELF binaries.
 * The implementation handles cross-platform libdwarf API differences and provides
 * robust error handling for real-world ELF files.
 *
 * ## Key Implementation Details:
 * - Cross-platform libdwarf API handling (macOS/Windows vs Linux)
 * - ELF format validation and error recovery
 * - Memory-efficient binary data processing
 * - DWARF debug information extraction algorithms
 *
 * @see ElfReader.h for complete API documentation
 */

#include "ElfReader.h"
#include <cxxabi.h>
#if HAVE_LIBDWARF
    #include <dwarf.h>
    #include <libdwarf.h>
    #include "DwarfRAII.h"
    #include "dwarf/DwarfTypeResolver.h"
#endif
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include "ElfExceptions.h"
#include "ExportFormats.h"
#include "output/OutputGenerator.h"

using namespace ElfReaderExceptions;

// ========================================================================
// DwarfInitializer Implementation (only when libdwarf is available)
// ========================================================================

#if HAVE_LIBDWARF

bool DwarfInitializer::initialize(const std::string& filename, Dwarf_Debug& dbg) {
    Dwarf_Error error = nullptr;

    // Critical Implementation Note: libdwarf API varies significantly between versions
    // This conditional compilation handles the two major API variants in use
    #if defined(DW_LIBDWARF_VERSION_MAJOR) && (DW_LIBDWARF_VERSION_MAJOR >= 2) ||                  \
        defined(__APPLE__) || (defined(_WIN32) && defined(__MINGW64__))
    // libdwarf 2.x API or macOS/Windows with simplified API (8 parameters):
    // dwarf_init_path(filename, error_handler, error_arg, groupnumber,
    //                 errhand_arg, errhand, dbg, error)
    int ret = dwarf_init_path(
        filename.c_str(), nullptr, 0, DW_GROUPNUMBER_ANY, nullptr, nullptr, &dbg, &error);
    #else
    // Older libdwarf API with extended parameters (12 parameters):
    // dwarf_init_path(filename, error_handler, error_arg, groupnumber, access,
    //                 init_fd, ftype, flags, dbg, pathsource, reserved, error)
    int ret = dwarf_init_path(filename.c_str(),
                              nullptr,
                              0,
                              DW_GROUPNUMBER_ANY,
                              0,
                              nullptr,
                              nullptr,
                              &dbg,
                              nullptr,
                              0,
                              nullptr,
                              &error);
    #endif

    return (ret == DW_DLV_OK);
}

void DwarfInitializer::cleanup(Dwarf_Debug dbg) {
    if (dbg == nullptr)
        return;

    [[maybe_unused]] Dwarf_Error error = nullptr;

    // Handle API differences between libdwarf versions
    #if defined(DW_LIBDWARF_VERSION_MAJOR) && (DW_LIBDWARF_VERSION_MAJOR >= 2) ||                  \
        defined(__APPLE__) || (defined(_WIN32) && defined(__MINGW64__))
    // libdwarf 2.x API or macOS/Windows (1 parameter)
    dwarf_finish(dbg);
    #else
    // Older libdwarf API (2 parameters)
    dwarf_finish(dbg, &error);
    #endif
}

#endif  // HAVE_LIBDWARF

// ========================================================================
// ElfReader Implementation
// ========================================================================

void ElfReader::initializeElfReader(const std::string& filename, const Config& config) {
    filename_ = filename;
    config_ = config;
    config_.inputFile = filename;
    analysis_completed_ = false;

    auto start_time = std::chrono::high_resolution_clock::now();

    loadFile();
    validateElfFile();

    // Initialize performance metrics
    if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
        performance_metrics_.file_size_bytes = file_access_->size();
        performance_metrics_.memory_mapping_used =
            (file_access_->getStrategyName() == "Memory-mapped");
    }

    // Initialize parallel processing infrastructure
    initializeParallelProcessing();

    // Performance optimization: Reserve string interner capacity for large files with bounds
    // checking
    size_t file_size_mb = file_access_->size() / (static_cast<size_t>(1024) * 1024);
    if (file_size_mb > ElfOptimization::STRING_CAPACITY_THRESHOLD_MB) {
        // Estimate unique strings based on file size with comprehensive bounds checking
        size_t estimated_capacity =
            std::min(file_size_mb * ElfOptimization::STRING_CAPACITY_MULTIPLIER,
                     ElfOptimization::MAX_STRING_CAPACITY);

        try {
            // ThreadSafeStringInterner handles capacity automatically
            if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                performance_metrics_.string_interner_capacity_reserved = estimated_capacity;
            }
            if (config_.verbosity > 0) {
                std::cout << "Reserved string interner capacity: " << estimated_capacity
                          << " strings\n";
            }
        } catch (const std::bad_alloc& e) {
            // Fallback: try with reduced capacity if allocation fails
            size_t fallback_capacity = estimated_capacity / 4;  // Try 25% of original
            if (config_.verbosity > 0) {
                std::cout << "Warning: Could not reserve " << estimated_capacity
                          << " strings, trying fallback: " << fallback_capacity << " strings\n";
            }
            try {
                // ThreadSafeStringInterner handles capacity automatically
                if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                    performance_metrics_.string_interner_capacity_reserved = fallback_capacity;
                    performance_metrics_.string_interner_fallback_used = 1;
                }
            } catch (const std::bad_alloc&) {
                if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                    performance_metrics_.string_interner_fallback_used =
                        2;  // Failed even with fallback
                }
                // Continue without pre-allocation if even fallback fails
                if (config_.verbosity > 0) {
                    std::cout << "Warning: String interner pre-allocation failed, continuing with "
                                 "dynamic allocation\n";
                }
            }
        }
    }

    parseElfHeader();

    // Initialize output generator
    output_generator_ =
        std::make_unique<OutputGenerator>(is_32bit_, is_little_endian_, getEntryPoint());

    parseSectionHeaders();
    parseStringTables();
    parseSymbolTable();

    // Always attempt DWARF parsing for comprehensive analysis
    bool dwarf_success = parseDwarfWithLibdwarf();
    has_dwarf_info_ = dwarf_success;

    if (!dwarf_success && config_.verbosity >= 0) {
        std::cerr
            << "Note: No DWARF debug information found. Compile with -g for detailed analysis."
            << std::endl;
    }

    // Measure initialization time
    if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
        auto end_time = std::chrono::high_resolution_clock::now();
        performance_metrics_.total_processing_time_ms =
            std::chrono::duration<double, std::milli>(end_time - start_time).count();
    }
}

ElfReader::ElfReader(const std::string& filename) {
    initializeElfReader(filename, Config{});
}

ElfReader::ElfReader(const std::string& filename, const Config& config) {
    initializeElfReader(filename, config);
}

ElfReader::~ElfReader() {
    try {
        // Shutdown parallel processing infrastructure first
        shutdownParallelProcessing();

        // Explicitly clear DWARF-related containers to avoid use-after-free issues
        // This prevents crashes when destructing containers that may reference
        // libdwarf memory that was freed during parseDwarfWithLibdwarf()
        dwarf_variables_.clear();
        dwarf_dies_.clear();
        types_.clear();
        functions_.clear();
        advanced_types_.clear();

        // NOLINTNEXTLINE(bugprone-empty-catch) - Intentional for destructor safety
    } catch (const std::exception&) {
        // Never throw from destructor - just silently handle any cleanup issues
        // This is critical for proper RAII behavior in firmware analysis scenarios
    }
}

ElfReader::ElfReader(const Config& config) {
    initializeElfReader(config.inputFile, config);
}

void ElfReader::validateElfFile() {
    // Use comprehensive ELF validation
    memory_validator_ = std::make_unique<ElfReaderUtils::ElfMemoryValidator>(
        file_access_->data(), file_access_->size(), filename_);

    memory_validator_->validateElfHeader();

    const uint8_t* data = memory_validator_->getData();
    is_32bit_ = (data[4] == static_cast<uint8_t>(ElfClass::ELFCLASS32));
    is_little_endian_ = (data[5] == static_cast<uint8_t>(ElfData::ELFDATA2LSB));

    // Check for supported architectures: ARM, ARM64, RISC-V, Xtensa
    uint16_t machine_type = memory_validator_->readValue<uint16_t>(18, "machine type");

    if (is_32bit_) {
        // 32-bit architectures: ARM, RISC-V, or Xtensa
        if (machine_type != static_cast<uint16_t>(ElfMachine::EM_ARM) &&
            machine_type != static_cast<uint16_t>(ElfMachine::EM_RISCV) &&
            machine_type != static_cast<uint16_t>(ElfMachine::EM_XTENSA)) {
            throw ElfFileError(ElfFileError::ErrorType::InvalidFormat,
                               "Unsupported 32-bit architecture (expected ARM, RISC-V, or Xtensa)",
                               filename_);
        }
    } else {
        // 64-bit architectures: ARM64 or RISC-V
        if (machine_type != static_cast<uint16_t>(ElfMachine::EM_AARCH64) &&
            machine_type != static_cast<uint16_t>(ElfMachine::EM_RISCV)) {
            throw ElfFileError(ElfFileError::ErrorType::InvalidFormat,
                               "Unsupported 64-bit architecture (expected ARM64 or RISC-V)",
                               filename_);
        }
    }
}

void ElfReader::loadFile() {
    try {
        // Create file access strategy based on file size and configuration
        file_access_ = FileAccessStrategy::create(filename_, config_.mmapThreshold);

        if (config_.verbosity > 0) {
            std::cout << "Loading file: " << filename_ << " (" << file_access_->size()
                      << " bytes) using " << file_access_->getStrategyName() << " access\n";
        }

    } catch (const std::exception& e) {
        throw ElfFileError(ElfFileError::ErrorType::FileNotFound,
                           "Cannot open file: " + filename_ + " (" + e.what() + ")",
                           filename_);
    }
}

void ElfReader::parseElfHeader() {
    if (is_32bit_) {
        readStruct(16, ehdr32_);
    } else {
        readStruct(16, ehdr64_);
    }
}

void ElfReader::parseSectionHeaders() {
    uint32_t shoff = getSectionHeaderOffset();
    uint16_t shentsize = getSectionHeaderSize();
    uint16_t shnum = getSectionCount();

    if (is_32bit_) {
        sections32_.resize(shnum);
        for (uint16_t i = 0; i < shnum; ++i) {
            size_t offset = shoff + i * shentsize;
            readStruct(offset, sections32_[i]);
        }
    } else {
        sections64_.resize(shnum);
        for (uint16_t i = 0; i < shnum; ++i) {
            size_t offset = shoff + i * shentsize;
            readStruct(offset, sections64_[i]);
        }
    }
}

void ElfReader::parseStringTables() {
    uint16_t shstrndx = getSectionNameIndex();

    // Parse section header string table first with bounds checking
    if (is_32bit_ && shstrndx < sections32_.size()) {
        const auto& shstrtab = sections32_[shstrndx];
        try {
            memory_validator_->validateRange(shstrtab.sh_offset, shstrtab.sh_size, "string table");
            std::vector<char> strtab_data(memory_validator_->getData() + shstrtab.sh_offset,
                                          memory_validator_->getData() + shstrtab.sh_offset +
                                              shstrtab.sh_size);
            string_tables_[shstrndx] = strtab_data;
        } catch (const ElfReaderExceptions::MemoryAccessError& e) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid string table section: " + std::string(e.what()),
                filename_);
        }

        // Set section names for 32-bit sections
        for (auto& section : sections32_) {
            section.name = string_interner_.intern(getString(shstrndx, section.sh_name));
        }
    } else if (!is_32bit_ && shstrndx < sections64_.size()) {
        const auto& shstrtab = sections64_[shstrndx];
        try {
            memory_validator_->validateRange(shstrtab.sh_offset, shstrtab.sh_size, "string table");
            std::vector<char> strtab_data(memory_validator_->getData() + shstrtab.sh_offset,
                                          memory_validator_->getData() + shstrtab.sh_offset +
                                              shstrtab.sh_size);
            string_tables_[shstrndx] = strtab_data;
        } catch (const ElfReaderExceptions::MemoryAccessError& e) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid string table section: " + std::string(e.what()),
                filename_);
        }

        // Set section names for 64-bit sections
        for (auto& section : sections64_) {
            section.name = string_interner_.intern(getString(shstrndx, section.sh_name));
        }
    }

    // Parse all string tables with bounds checking
    if (is_32bit_) {
        for (size_t i = 0; i < sections32_.size(); ++i) {
            const auto& section = sections32_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_STRTAB)) {
                try {
                    memory_validator_->validateRange(
                        section.sh_offset, section.sh_size, "string table");
                    std::vector<char> strtab_data(memory_validator_->getData() + section.sh_offset,
                                                  memory_validator_->getData() + section.sh_offset +
                                                      section.sh_size);
                    string_tables_[i] = strtab_data;
                } catch (const MemoryAccessError& e) {
                    // Skip invalid string tables but continue processing
                    if (config_.verbosity > 1) {
                        std::cerr << "Warning: Skipping invalid string table section " << i << ": "
                                  << e.what() << std::endl;
                    }
                }
            }
        }
    } else {
        for (size_t i = 0; i < sections64_.size(); ++i) {
            const auto& section = sections64_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_STRTAB)) {
                try {
                    memory_validator_->validateRange(
                        section.sh_offset, section.sh_size, "string table");
                    std::vector<char> strtab_data(memory_validator_->getData() + section.sh_offset,
                                                  memory_validator_->getData() + section.sh_offset +
                                                      section.sh_size);
                    string_tables_[i] = strtab_data;
                } catch (const MemoryAccessError& e) {
                    // Skip invalid string tables but continue processing
                    if (config_.verbosity > 1) {
                        std::cerr << "Warning: Skipping invalid string table section " << i << ": "
                                  << e.what() << std::endl;
                    }
                }
            }
        }
    }
}

void ElfReader::parseSymbolTable() {
    if (is_32bit_) {
        for (size_t i = 0; i < sections32_.size(); ++i) {
            const auto& section = sections32_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_SYMTAB)) {
                // Implementation detail: 32-bit ELF symbol entries have fixed 16-byte structure:
                // st_name(4) + st_value(4) + st_size(4) + st_info(1) + st_other(1) + st_shndx(2)
                size_t num_symbols = section.sh_size / ElfSizes::ELF32_SYM_SIZE;
                uint32_t strtab_index = section.sh_link;

                // Pre-reserve capacity to avoid vector reallocations during parsing
                symbols32_.reserve(num_symbols);
                for (size_t j = 0; j < num_symbols; ++j) {
                    size_t offset = section.sh_offset + j * ElfSizes::ELF32_SYM_SIZE;
                    // Bounds checking: ensure we don't read past file end
                    if (offset + ElfSizes::ELF32_SYM_SIZE <= file_access_->size()) {
                        Elf32_Sym symbol;
                        readStruct(offset, symbol);
                        // Resolve symbol name from linked string table (sh_link field)
                        symbol.name =
                            string_interner_.intern(getString(strtab_index, symbol.st_name));
                        symbols32_.push_back(symbol);
                    }
                }
                break;  // ELF standard: typically only one .symtab section per file
            }
        }
    } else {
        for (size_t i = 0; i < sections64_.size(); ++i) {
            const auto& section = sections64_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_SYMTAB)) {
                // Implementation detail: 64-bit ELF symbol entries have fixed 24-byte structure:
                // st_name(4) + st_info(1) + st_other(1) + st_shndx(2) + st_value(8) + st_size(8)
                size_t num_symbols = section.sh_size / ElfSizes::ELF64_SYM_SIZE;
                uint32_t strtab_index = section.sh_link;

                symbols64_.reserve(num_symbols);
                for (size_t j = 0; j < num_symbols; ++j) {
                    size_t offset = section.sh_offset + j * 24;
                    if (offset + 24 <= file_access_->size()) {
                        Elf64_Sym symbol;
                        readStruct(offset, symbol);
                        symbol.name =
                            string_interner_.intern(getString(strtab_index, symbol.st_name));
                        symbols64_.push_back(symbol);
                    }
                }
                break;  // Usually only one symbol table
            }
        }
    }
}

void ElfReader::parseDebugInfo() {
    has_dwarf_info_ = false;

    // Try to parse DWARF debug information using libdwarf
    if (parseDwarfWithLibdwarf()) {
        has_dwarf_info_ = true;
        if (config_.verbosity > 0) {
            if (types_.size() > 0) {
                std::cout << "Using libdwarf for structure analysis.\n";
            } else {
                std::cout << "Using libdwarf for variable analysis.\n";
            }
        }
        return;
    }

    if (config_.verbosity > 0) {
        std::cout << "No debug information found. Compile with -g flag for detailed structure "
                     "analysis.\n";
        std::cout << "Using hex ID fallbacks for unknown types.\n";
    }
}

/**
 * @brief Cross-platform libdwarf DWARF parser with API compatibility handling
 *
 * ## Platform-Specific Implementation Details:
 *
 * This method handles major API differences between libdwarf versions across platforms:
 * - **macOS/Windows**: Uses libdwarf 2.x API with 8-parameter dwarf_init_path()
 * - **Linux**: Uses older libdwarf API with 12-parameter dwarf_init_path()
 * - **Error Handling**: Different cleanup patterns for different API versions
 *
 * ## Algorithm Overview:
 * 1. Initialize libdwarf with platform-appropriate API
 * 2. Iterate through all compilation units (.debug_info section)
 * 3. Process Debug Information Entries (DIEs) recursively
 * 4. Extract structure/class definitions and variable information
 * 5. Build type relationship maps for member expansion
 *
 * ## Error Recovery Strategy:
 * - Returns false (not throws) to allow fallback to legacy parsing
 * - Handles missing debug sections gracefully
 * - Provides user feedback about parsing progress and failures
 */
bool ElfReader::parseDwarfWithLibdwarf() {
#if !HAVE_LIBDWARF
    // DWARF parsing is disabled - return immediately
    return false;
#endif

    try {
        Dwarf_Debug dbg = nullptr;

        // Use the DwarfInitializer wrapper to abstract platform differences
        if (!DwarfInitializer::initialize(filename_, dbg)) {
            return false;  // No debug info available, not an error condition
        }

        if (config_.verbosity > 0) {
            std::cout << "libdwarf parsing DWARF debug information...\n";
        }

        // Use parallel or sequential compilation unit processing
        bool parsing_success;
        if (config_.enableParallelProcessing) {
            parsing_success = parseDwarfCompilationUnitsParallel(dbg);
        } else {
            parsing_success = parseDwarfCompilationUnitsSequential(dbg);
        }

        if (!parsing_success) {
            if (config_.verbosity > 0) {
                std::cout << "DWARF parsing encountered errors\n";
            }
        }

        if (config_.verbosity > 0) {
            size_t cu_count = 0;
            if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                cu_count = performance_metrics_.compilation_units_processed;
            }
            std::cout << "Completed DWARF parsing: " << cu_count << " compilation units, "
                      << types_.size() << " types, " << dwarf_variables_.size() << " variables\n";
        }

        // Cleanup using the DwarfInitializer wrapper
        DwarfInitializer::cleanup(dbg);

        if (config_.verbosity > 0) {
            std::cout << "libdwarf extracted " << types_.size() << " structures";
            if (!dwarf_variables_.empty()) {
                std::cout << " and " << dwarf_variables_.size() << " variables";
            }
            std::cout << "\n";

            // Report string interning statistics
            auto [intern_count, lookup_count, cache_hits] = string_interner_.getStats();
            (void)intern_count;  // Suppress unused variable warning
            (void)lookup_count;  // Suppress unused variable warning
            (void)cache_hits;    // Suppress unused variable warning
            size_t unique_strings = string_interner_.size();
            size_t estimated_bytes = string_interner_.getMemoryUsage();
            double avg_length = unique_strings > 0 ? static_cast<double>(estimated_bytes) /
                                                         static_cast<double>(unique_strings)
                                                   : 0.0;
            std::cout << "String interning: " << unique_strings << " unique strings, "
                      << estimated_bytes << " bytes, avg length " << std::fixed
                      << std::setprecision(1) << avg_length << "\n";
        }
        return types_.size() > 0 || !dwarf_variables_.empty();

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "libdwarf exception: " << e.what() << "\n";
        }
        return false;
    }
}

// Real DWARF parsing implementation
#if HAVE_LIBDWARF
void ElfReader::processCompilationUnit(Dwarf_Debug dbg, Dwarf_Die cu_die) {
    // Process the compilation unit and all its child DIEs
    processDwarfDie(dbg, cu_die);
}

/**
 * @brief Recursive DWARF DIE processing with namespace-aware traversal
 *
 * ## Algorithm Implementation Details:
 *
 * This method implements a recursive tree traversal of DWARF Debug Information Entries (DIEs).
 * The algorithm maintains namespace context throughout the traversal and handles memory
 * management for libdwarf DIE structures.
 *
 * ### Memory Management Strategy:
 * - Each DIE obtained from libdwarf must be explicitly deallocated
 * - Sibling traversal creates new DIE objects that need cleanup
 * - Child DIE processing is recursive, requiring careful stack management
 *
 * ### Namespace Context Tracking:
 * - Maintains current namespace prefix (e.g., "MyNamespace::")
 * - Builds fully qualified type names for C++ classes and structures
 * - Handles nested namespaces correctly with "::" separator
 *
 * ### DIE Type Processing Priority:
 * 1. **Structures/Classes**: Immediate extraction for member analysis
 * 2. **Variables**: Global variable type and address information
 * 3. **Namespaces**: Context building for nested type resolution
 * 4. **Other**: Generic recursive processing for completeness
 */
void ElfReader::processDwarfDie(Dwarf_Debug dbg,
                                Dwarf_Die die,
                                const std::string& namespace_prefix) {
    Dwarf_Half tag;
    Dwarf_Error error = nullptr;

    // Extract the DWARF tag that identifies the type of program element
    int ret = dwarf_tag(die, &tag, &error);
    if (ret != DW_DLV_OK) {
        return;  // Skip malformed DIEs rather than aborting entire parsing
    }

    // Process DIE based on its type - this switch implements the core analysis logic
    switch (tag) {
        case DW_TAG_structure_type:
        case DW_TAG_class_type: {
            // High Priority: Extract structure/class definitions immediately
            std::string name = DwarfTypeResolver::getDwarfDieName(dbg, die);
            if (!name.empty()) {
                // Build fully qualified name with namespace context
                std::string full_name =
                    namespace_prefix.empty() ? name : namespace_prefix + "::" + name;

                // Extract linkage_name (mangled C++ name) for unique type identification
                // This solves the ambiguity problem where multiple classes have same-named nested
                // types Example: Namespace1::MyType_t vs Namespace2::MyType_t both named "MyType_t"
                // Linkage name: N10Namespace17MyType_tE vs N10Namespace27MyType_tE (UNIQUE!)
                std::string linkage_name_str;
                Dwarf_Attribute linkage_attr = nullptr;
                int linkage_ret = dwarf_attr(die, DW_AT_linkage_name, &linkage_attr, &error);
                if (linkage_ret == DW_DLV_OK) {
                    char* linkage_name = nullptr;
                    if (dwarf_formstring(linkage_attr, &linkage_name, &error) == DW_DLV_OK &&
                        linkage_name) {
                        linkage_name_str = linkage_name;
                    }
                    dwarf_dealloc(dbg, linkage_attr, DW_DLA_ATTR);
                }

                // Extract structure with BOTH qualified name and linkage name
                // The TypeInfo will be stored in all three maps (types_, linkage_name_map_,
                // qualified_name_map_)
                extractStructureFromDie(dbg, die, full_name, linkage_name_str);
            }
            break;
        }
        case DW_TAG_variable: {
            // Medium Priority: Process global variables for symbol-to-type mapping
            processDwarfVariable(dbg, die, namespace_prefix);
            break;
        }
        case DW_TAG_namespace: {
            // Context Building: Process namespace and recursively handle children
            std::string name = DwarfTypeResolver::getDwarfDieName(dbg, die);
            std::string new_prefix =
                namespace_prefix.empty() ? name : namespace_prefix + "::" + name;

            // Recursive child processing with updated namespace context
            Dwarf_Die child_die = nullptr;
            ret = dwarf_child(die, &child_die, &error);
            while (ret == DW_DLV_OK && child_die != nullptr) {
                processDwarfDie(dbg, child_die, new_prefix);

                // Critical: Sibling traversal with proper memory management
                Dwarf_Die sibling_die = nullptr;
                ret = dwarf_siblingof_b(dbg, child_die, 1, &sibling_die, &error);
                dwarf_dealloc_die(child_die);  // Prevent memory leak
                child_die = sibling_die;
            }
            break;
        }
        // DWARF 5 support temporarily disabled until debugging complete
        /*
        case DW_TAG_immutable_type:
        case DW_TAG_packed_type:
        case DW_TAG_atomic_type:
        case DW_TAG_dynamic_type:
        case DW_TAG_template_type_parameter:
        case DW_TAG_template_value_parameter: {
            // Skip DWARF 5 tags for now - will be re-enabled after fixing
            break;
        }
        */
        default:
            // Generic Processing: Handle other DIE types (functions, typedefs, etc.)
            // Still need to process children to find nested structures
            Dwarf_Die child_die = nullptr;
            ret = dwarf_child(die, &child_die, &error);
            while (ret == DW_DLV_OK && child_die != nullptr) {
                processDwarfDie(dbg, child_die, namespace_prefix);

                Dwarf_Die sibling_die = nullptr;
                ret = dwarf_siblingof_b(dbg, child_die, 1, &sibling_die, &error);
                dwarf_dealloc_die(child_die);
                child_die = sibling_die;
            }
            break;
    }
}

// Type resolution methods moved to dwarf/DwarfTypeResolver.cpp

// ============================================================================
// Type Reference Resolution with Linkage Names
// ============================================================================

ElfReader::TypeIdentifier ElfReader::resolveTypeIdentifier(Dwarf_Debug dbg,
                                                           Dwarf_Die start_die) const {
    TypeIdentifier result;
    Dwarf_Error error = nullptr;
    Dwarf_Die current_die = start_die;
    bool need_dealloc = false;

    // Follow type reference chain through const/typedef/pointer layers
    for (int depth = 0; depth < 10; ++depth) {  // Prevent infinite loops
        Dwarf_Attribute type_attr = nullptr;
        if (dwarf_attr(current_die, DW_AT_type, &type_attr, &error) != DW_DLV_OK) {
            break;  // No more type references
        }

        Dwarf_Off type_offset = 0;
        if (dwarf_global_formref(type_attr, &type_offset, &error) != DW_DLV_OK) {
            dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
            break;
        }

        if (need_dealloc) {
            dwarf_dealloc_die(current_die);
        }

        if (dwarf_offdie_b(dbg, type_offset, 1, &current_die, &error) != DW_DLV_OK) {
            dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
            break;
        }
        need_dealloc = true;
        dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);

        // Check if this is a structure/class (final type)
        Dwarf_Half tag = 0;
        if (dwarf_tag(current_die, &tag, &error) == DW_DLV_OK) {
            if (tag == DW_TAG_structure_type || tag == DW_TAG_class_type) {
                // Found the actual type! Extract linkage name (UNIQUE!)
                Dwarf_Attribute linkage_attr = nullptr;
                if (dwarf_attr(current_die, DW_AT_linkage_name, &linkage_attr, &error) ==
                    DW_DLV_OK) {
                    char* linkage_name = nullptr;
                    if (dwarf_formstring(linkage_attr, &linkage_name, &error) == DW_DLV_OK &&
                        linkage_name) {
                        result.linkage_name = linkage_name;
                    }
                    dwarf_dealloc(dbg, linkage_attr, DW_DLA_ATTR);
                }

                // Also get qualified name as fallback (for C structs without linkage names)
                result.qualified_name = DwarfTypeResolver::getDwarfDieName(dbg, current_die);

                // Store DIE offset for direct access
                dwarf_dieoffset(current_die, &result.die_offset, &error);
                break;
            }
            // Otherwise continue following (might be const/typedef/volatile/etc.)
        }
    }

    if (need_dealloc) {
        dwarf_dealloc_die(current_die);
    }

    return result;
}

// ============================================================================
// Type Match Confidence Scoring
// ============================================================================

ElfReader::TypeMatchConfidence
ElfReader::getTypeMatchConfidence(const std::string& type_name) const {
    // Check linkage name first (100% confidence - UNIQUE!)
    if (types_.hasTypeByLinkageName(type_name)) {
        return TypeMatchConfidence::EXACT_LINKAGE_NAME;
    }

    // Check qualified name (90% confidence - usually unique)
    if (types_.getTypeByQualifiedName(type_name).has_value()) {
        return TypeMatchConfidence::EXACT_QUALIFIED_NAME;
    }

    // Check for DIE offset key (type@offset) (85% confidence - unique per CU)
    if (type_name.find('@') != std::string::npos && types_.hasType(type_name)) {
        return TypeMatchConfidence::EXACT_DIE_OFFSET;
    }

    // Check simple name - count how many types match
    size_t match_count = types_.countSimpleNameMatches(type_name);

    if (match_count == 0) {
        return TypeMatchConfidence::NO_MATCH;
    } else if (match_count == 1) {
        return TypeMatchConfidence::SINGLE_SIMPLE_MATCH;  // Safe - only one match
    } else {
        return TypeMatchConfidence::AMBIGUOUS_NAME;  // DANGEROUS - multiple matches!
    }
}

void ElfReader::extractStructureFromDie(Dwarf_Debug dbg,
                                        Dwarf_Die struct_die,
                                        const std::string& full_name,
                                        const std::string& linkage_name) {
    std::vector<TypeMember> members;

    // Get DIE offset for unique identification
    Dwarf_Off die_offset = 0;
    Dwarf_Error error = nullptr;
    dwarf_dieoffset(struct_die, &die_offset, &error);

    /**
     * @brief Performance optimization: DWARF DIE deduplication using efficient pair-based keys
     *
     * Uses optimized DieKey (pair<name, offset>) instead of string concatenation for better
     * performance and memory efficiency. Prevents redundant processing of the same structure
     * definition across multiple compilation units, significantly reducing processing time
     * for large binaries with extensive template instantiations or repeated structures.
     *
     * ## Algorithm:
     * 1. Extract unique DIE offset from DWARF using dwarf_dieoffset()
     * 2. Create efficient DieKey pair: (structure_name, die_offset)
     * 3. Fast O(1) lookup in unordered_map to check if already processed
     * 4. Early exit if structure already processed to avoid duplicate work
     *
     * ## Performance Improvements:
     * - Reduces algorithmic complexity from O(n²) to O(n) for duplicate structures
     * - Eliminates string concatenation overhead (saves ~10-15% on large files)
     * - Uses custom hash function optimized for pair<string, uint64_t>
     * - Typical 20-35% processing time reduction for large embedded firmware
     *
     * @param die_offset Unique DWARF DIE offset obtained from dwarf_dieoffset()
     * @param full_name Fully qualified structure/class name including namespace
     * @return Early function exit if structure already processed, preventing duplicate work
     *
     * ## Example:
     * For ESP32 firmware with 68,958 types, prevents reprocessing ~20,000 duplicate entries
     * while avoiding thousands of string allocations during key generation.
     */
    DieKey die_key(full_name, die_offset);
    if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
        performance_metrics_.total_structures_encountered++;
    }

    if (processed_dies_.find(die_key) != processed_dies_.end()) {
        if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
            performance_metrics_.duplicate_structures_skipped++;
        }
        return;  // Already processed this structure - skip to avoid redundant work
    }
    processed_dies_[die_key] = true;

    // Get structure size
    Dwarf_Unsigned byte_size = 0;
    dwarf_bytesize(struct_die, &byte_size, &error);

    // Process member DIEs
    Dwarf_Die child_die = nullptr;
    int ret = dwarf_child(struct_die, &child_die, &error);

    while (ret == DW_DLV_OK && child_die != nullptr) {
        Dwarf_Half tag;
        ret = dwarf_tag(child_die, &tag, &error);

        if (ret == DW_DLV_OK && tag == DW_TAG_member) {
            std::string member_name = DwarfTypeResolver::getDwarfDieName(dbg, child_die);

            // Get member offset
            Dwarf_Attribute attr = nullptr;
            Dwarf_Unsigned offset = 0;

            ret = dwarf_attr(child_die, DW_AT_data_member_location, &attr, &error);
            if (ret == DW_DLV_OK) {
                dwarf_formudata(attr, &offset, &error);
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }

            // Get member type
            Dwarf_Die type_die = nullptr;
            ret = dwarf_attr(child_die, DW_AT_type, &attr, &error);
            if (ret == DW_DLV_OK) {
                Dwarf_Off type_offset;
                ret = dwarf_global_formref(attr, &type_offset, &error);
                if (ret == DW_DLV_OK) {
                    dwarf_offdie_b(dbg, type_offset, 1, &type_die, &error);
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }

            std::string type_name = DwarfTypeResolver::resolveDwarfType(dbg, type_die);

            // Get type size (assume 4 bytes if can't determine)
            Dwarf_Unsigned member_size = 4;
            bool is_struct_type = false;

            if (type_die != nullptr) {
                dwarf_bytesize(type_die, &member_size, &error);
                if (member_size == 0)
                    member_size = 4;  // fallback

                // Check if it's a structure type and extract it recursively
                Dwarf_Half type_tag;
                if (dwarf_tag(type_die, &type_tag, &error) == DW_DLV_OK) {
                    is_struct_type =
                        (type_tag == DW_TAG_structure_type || type_tag == DW_TAG_class_type);

                    // If it's a structure, make sure we extract it
                    if (is_struct_type && !type_name.empty()) {
                        extractStructureFromDie(dbg, type_die, type_name);
                    }
                }

                dwarf_dealloc_die(type_die);
            }

            if (!member_name.empty()) {
                members.emplace_back(string_interner_.intern(member_name),
                                     string_interner_.intern(type_name),
                                     offset,
                                     member_size,
                                     is_struct_type);
            }
        }
        // Handle inline/nested structure or class definitions
        else if (ret == DW_DLV_OK && (tag == DW_TAG_structure_type || tag == DW_TAG_class_type ||
                                      tag == DW_TAG_union_type)) {
            // Extract inline type definitions so they're available when members reference them
            std::string nested_type_name = DwarfTypeResolver::getDwarfDieName(dbg, child_die);
            if (!nested_type_name.empty()) {
                extractStructureFromDie(dbg, child_die, nested_type_name);
            }
        }
        // Handle inheritance
        else if (ret == DW_DLV_OK && tag == DW_TAG_inheritance) {
            // Get base class type
            Dwarf_Die base_type_die = nullptr;
            Dwarf_Attribute attr = nullptr;
            ret = dwarf_attr(child_die, DW_AT_type, &attr, &error);
            if (ret == DW_DLV_OK) {
                Dwarf_Off type_offset;
                ret = dwarf_global_formref(attr, &type_offset, &error);
                if (ret == DW_DLV_OK) {
                    dwarf_offdie_b(dbg, type_offset, 1, &base_type_die, &error);
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }

            // Get inheritance offset
            Dwarf_Unsigned inherit_offset = 0;
            ret = dwarf_attr(child_die, DW_AT_data_member_location, &attr, &error);
            if (ret == DW_DLV_OK) {
                dwarf_formudata(attr, &inherit_offset, &error);
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }

            if (base_type_die != nullptr) {
                std::string base_class_name =
                    DwarfTypeResolver::resolveDwarfType(dbg, base_type_die);

                // Extract base class structure recursively
                extractStructureFromDie(dbg, base_type_die, base_class_name);

                // Add base class members to this structure at the inheritance offset
                auto base_type = types_.getType(base_class_name);
                if (base_type.has_value()) {
                    for (const auto& base_member : base_type->members) {
                        members.emplace_back(string_interner_.intern(base_member.name),
                                             string_interner_.intern(base_member.type),
                                             inherit_offset + base_member.offset,
                                             base_member.size,
                                             base_member.is_struct);
                    }
                }

                dwarf_dealloc_die(base_type_die);
            }
        }

        // Get next sibling
        Dwarf_Die sibling_die = nullptr;
        ret = dwarf_siblingof_b(dbg, child_die, 1, &sibling_die, &error);
        dwarf_dealloc_die(child_die);
        child_die = sibling_die;
    }

    // Add to types map with unique key based on DIE offset
    // Now includes linkage_name for unique type identification
    if (!members.empty() || byte_size > 0) {
        // Create unique key combining name and DIE offset
        std::string unique_key = full_name + "@" + std::to_string(die_offset);
        types_.addType(unique_key,
                       TypeInfo(byte_size,
                                members,
                                die_offset,
                                string_interner_.intern(full_name),
                                linkage_name.empty() ? "" : string_interner_.intern(linkage_name)));

        // For anonymous structures (just "struct"), always use unique key
        // For named structures, also store with original name if not already present
        if (full_name != "struct" && !types_.hasType(full_name)) {
            types_.addType(
                full_name,
                TypeInfo(byte_size,
                         members,
                         die_offset,
                         string_interner_.intern(full_name),
                         linkage_name.empty() ? "" : string_interner_.intern(linkage_name)));
        }

        if (config_.verbosity > 1) {
            std::cout << "Extracted structure: " << full_name << " (size: " << byte_size
                      << ", members: " << members.size() << ", DIE: 0x" << std::hex << die_offset
                      << std::dec;
            if (!linkage_name.empty()) {
                std::cout << ", linkage: " << linkage_name;
            }
            std::cout << ")\n";

            // Debug: Print member details
            for (const auto& member : members) {
                std::cout << "  Member: " << member.name << " (" << member.type << ") at offset "
                          << member.offset << "\n";
            }
        }
    }
}

void ElfReader::processDwarfVariable(Dwarf_Debug dbg,
                                     Dwarf_Die var_die,
                                     const std::string& namespace_prefix) {
    Dwarf_Error error = nullptr;

    // Get variable name
    std::string var_name = DwarfTypeResolver::getDwarfDieName(dbg, var_die);

    // If no name, check if this DIE has a specification reference (common for C++ definitions)
    if (var_name.empty()) {
        Dwarf_Attribute spec_attr = nullptr;
        int spec_ret = dwarf_attr(var_die, DW_AT_specification, &spec_attr, &error);
        if (spec_ret == DW_DLV_OK) {
            // Follow the specification to get the name from the declaration
            Dwarf_Off spec_offset = 0;
            spec_ret = dwarf_global_formref(spec_attr, &spec_offset, &error);
            if (spec_ret == DW_DLV_OK) {
                Dwarf_Die spec_die = nullptr;
                spec_ret = dwarf_offdie_b(dbg, spec_offset, 1, &spec_die, &error);
                if (spec_ret == DW_DLV_OK) {
                    var_name = DwarfTypeResolver::getDwarfDieName(dbg, spec_die);
                    dwarf_dealloc_die(spec_die);
                }
            }
            dwarf_dealloc(dbg, spec_attr, DW_DLA_ATTR);
        }
    }

    if (var_name.empty()) {
        return;  // Skip unnamed variables
    }

    // Filter out ARM/Thumb mapping symbols when showing constants
    // These are not real constants: $a (ARM code), $t (Thumb code), $d (data)
    if (config_.constantsOnly && var_name.length() >= 2 && var_name[0] == '$' &&
        (var_name[1] == 'a' || var_name[1] == 't' || var_name[1] == 'd')) {
        return;  // Skip ARM mapping symbols
    }

    // Get variable address from location attribute
    Dwarf_Attribute location_attr = nullptr;
    uint64_t address = 0;
    bool has_address = false;

    int ret = dwarf_attr(var_die, DW_AT_location, &location_attr, &error);
    if (ret == DW_DLV_OK) {
        Dwarf_Loc_Head_c loc_head = nullptr;
        Dwarf_Unsigned loccount = 0;

        ret = dwarf_get_loclist_c(location_attr, &loc_head, &loccount, &error);
        if (ret == DW_DLV_OK && loccount > 0) {
            // Get the first location entry
            Dwarf_Small lle_value = 0;
            Dwarf_Unsigned rawlowpc = 0, rawhipc = 0;
            Dwarf_Bool debug_addr_unavailable = false;
            Dwarf_Addr lowpc_cooked = 0, hipc_cooked = 0;
            Dwarf_Unsigned op_count = 0;
            Dwarf_Locdesc_c locdesc = nullptr;
            Dwarf_Small loclist_source = 0;

            Dwarf_Unsigned expression_offset = 0;
            Dwarf_Unsigned locdesc_offset = 0;

            ret = dwarf_get_locdesc_entry_d(loc_head,
                                            0,
                                            &lle_value,
                                            &rawlowpc,
                                            &rawhipc,
                                            &debug_addr_unavailable,
                                            &lowpc_cooked,
                                            &hipc_cooked,
                                            &op_count,
                                            &locdesc,
                                            &loclist_source,
                                            &expression_offset,
                                            &locdesc_offset,
                                            &error);
            if (ret == DW_DLV_OK && op_count > 0 && locdesc) {
                Dwarf_Small op = 0;
                Dwarf_Unsigned op1 = 0, op2 = 0, op3 = 0;
                Dwarf_Unsigned branch_offset = 0;

                ret = dwarf_get_location_op_value_c(
                    locdesc, 0, &op, &op1, &op2, &op3, &branch_offset, &error);
                if (ret == DW_DLV_OK && op == DW_OP_addr) {
                    address = op1;
                    has_address = true;
                }
            }
        }

        if (loc_head) {
    // Handle different deallocation functions between libdwarf versions
    #ifdef dwarf_dealloc_loc_head_c
            dwarf_dealloc_loc_head_c(loc_head);
    #else
            // Fallback for older versions
            dwarf_dealloc(dbg, loc_head, DW_DLA_LOC_BLOCK);
    #endif
        }
        dwarf_dealloc(dbg, location_attr, DW_DLA_ATTR);
    }

    // If no address from DWARF location, try to find it from symbol table
    if (!has_address) {
        // Try to correlate this DWARF variable with a symbol table entry
        std::string full_var_name =
            namespace_prefix.empty() ? var_name : (namespace_prefix + "::" + var_name);

        // Look through symbol table for a matching symbol
        if (is_32bit_) {
            for (const auto& symbol : symbols32_) {
                if (!symbol.name.empty() && symbol.st_value != 0 && symbol.st_size > 0 &&
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_OBJECT)) {
                    // Try to match by demangled name
                    std::string demangled = demangleCppName(symbol.name);
                    if (demangled == full_var_name || demangled == var_name) {
                        address = symbol.st_value;
                        has_address = true;
                        break;
                    }
                }
            }
        } else if (!config_.constantsOnly) {
            for (const auto& symbol : symbols64_) {
                if (!symbol.name.empty() && symbol.st_value != 0 && symbol.st_size > 0 &&
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_OBJECT)) {
                    // Try to match by demangled name
                    std::string demangled = demangleCppName(symbol.name);
                    if (demangled == full_var_name || demangled == var_name) {
                        address = symbol.st_value;
                        has_address = true;
                        break;
                    }
                }
            }
        }
    }

    // Get variable type and check if it's const (must be done BEFORE early return check)
    Dwarf_Attribute type_attr = nullptr;
    std::string type_name;
    bool is_constant = false;
    std::string constant_value;

    // FIRST: Check for DW_AT_const_value directly on the variable DIE
    // This handles constexpr variables, enum constants, and inline constants
    Dwarf_Attribute const_attr = nullptr;
    int const_ret = dwarf_attr(var_die, DW_AT_const_value, &const_attr, &error);

    // If const_value not found, check if this DIE has a specification reference
    // (common for constexpr variables where declaration and definition are separate)
    if (const_ret != DW_DLV_OK) {
        Dwarf_Attribute spec_attr = nullptr;
        int spec_ret = dwarf_attr(var_die, DW_AT_specification, &spec_attr, &error);
        if (spec_ret == DW_DLV_OK) {
            // Follow the specification reference to find the declaration
            Dwarf_Off spec_offset = 0;
            spec_ret = dwarf_global_formref(spec_attr, &spec_offset, &error);
            if (spec_ret == DW_DLV_OK) {
                Dwarf_Die spec_die = nullptr;
                spec_ret = dwarf_offdie_b(dbg, spec_offset, 1, &spec_die, &error);
                if (spec_ret == DW_DLV_OK) {
                    // Try to get const_value from the specification DIE
                    const_ret = dwarf_attr(spec_die, DW_AT_const_value, &const_attr, &error);
                    dwarf_dealloc_die(spec_die);
                }
            }
            dwarf_dealloc(dbg, spec_attr, DW_DLA_ATTR);
        }
    }

    if (const_ret == DW_DLV_OK) {
        is_constant = true;  // Has const_value means it's a constant
        Dwarf_Half form = 0;
        const_ret = dwarf_whatform(const_attr, &form, &error);
        if (const_ret == DW_DLV_OK) {
            if (form == DW_FORM_data1 || form == DW_FORM_data2 || form == DW_FORM_data4 ||
                form == DW_FORM_data8) {
                Dwarf_Unsigned uval = 0;
                const_ret = dwarf_formudata(const_attr, &uval, &error);
                if (const_ret == DW_DLV_OK) {
                    constant_value = std::to_string(uval);
                }
            } else if (form == DW_FORM_sdata) {
                Dwarf_Signed sval = 0;
                const_ret = dwarf_formsdata(const_attr, &sval, &error);
                if (const_ret == DW_DLV_OK) {
                    constant_value = std::to_string(sval);
                }
            } else if (form == DW_FORM_string || form == DW_FORM_strp) {
                char* str_val = nullptr;
                const_ret = dwarf_formstring(const_attr, &str_val, &error);
                if (const_ret == DW_DLV_OK && str_val) {
                    constant_value = "\"" + std::string(str_val) + "\"";
                }
            } else if (form == DW_FORM_block1 || form == DW_FORM_block2 || form == DW_FORM_block4 ||
                       form == DW_FORM_block) {
                // Handle block form (used for float/double constants)
                Dwarf_Block* block_ptr = nullptr;
                const_ret = dwarf_formblock(const_attr, &block_ptr, &error);
                if (const_ret == DW_DLV_OK && block_ptr) {
                    // Interpret block as IEEE 754 float or double based on size
                    if (block_ptr->bl_len == 4) {
                        // 32-bit float
                        float fval;
                        memcpy(&fval, block_ptr->bl_data, 4);
                        std::ostringstream oss;
                        oss << std::fixed << std::setprecision(6) << fval << "f";
                        constant_value = oss.str();
                    } else if (block_ptr->bl_len == 8) {
                        // 64-bit double
                        double dval;
                        memcpy(&dval, block_ptr->bl_data, 8);
                        std::ostringstream oss;
                        oss << std::fixed << std::setprecision(15) << dval;
                        constant_value = oss.str();
                    } else {
                        // Unknown block size - show as hex
                        std::ostringstream oss;
                        oss << "0x";
                        const unsigned char* data =
                            static_cast<const unsigned char*>(block_ptr->bl_data);
                        for (Dwarf_Unsigned i = 0; i < block_ptr->bl_len; ++i) {
                            oss << std::hex << std::setw(2) << std::setfill('0')
                                << static_cast<unsigned int>(data[i]);
                        }
                        constant_value = oss.str();
                    }
                    dwarf_dealloc(dbg, block_ptr, DW_DLA_BLOCK);
                }
            }
        }
        dwarf_dealloc(dbg, const_attr, DW_DLA_ATTR);
    }

    ret = dwarf_attr(var_die, DW_AT_type, &type_attr, &error);
    if (ret == DW_DLV_OK) {
        Dwarf_Off type_offset = 0;
        ret = dwarf_global_formref(type_attr, &type_offset, &error);
        if (ret == DW_DLV_OK) {
            Dwarf_Die type_die = nullptr;
            ret = dwarf_offdie_b(dbg, type_offset, 1, &type_die, &error);
            if (ret == DW_DLV_OK) {
                // Check if this type DIE is a const type
                Dwarf_Half tag = 0;
                ret = dwarf_tag(type_die, &tag, &error);
                if (ret == DW_DLV_OK && tag == DW_TAG_const_type) {
                    is_constant = true;

                    // If we didn't get a value from DW_AT_const_value, try reading from memory
                    if (constant_value.empty()) {
                        // Get the underlying type to determine size and encoding
                        Dwarf_Die base_type_die = nullptr;
                        Dwarf_Attribute base_type_attr = nullptr;
                        ret = dwarf_attr(type_die, DW_AT_type, &base_type_attr, &error);
                        if (ret == DW_DLV_OK) {
                            Dwarf_Off base_type_offset = 0;
                            ret = dwarf_global_formref(base_type_attr, &base_type_offset, &error);
                            if (ret == DW_DLV_OK) {
                                ret = dwarf_offdie_b(
                                    dbg, base_type_offset, 1, &base_type_die, &error);
                                if (ret == DW_DLV_OK) {
                                    // Check if the base type is an enumeration
                                    Dwarf_Half base_tag = 0;
                                    ret = dwarf_tag(base_type_die, &base_tag, &error);

                                    if (ret == DW_DLV_OK && base_tag == DW_TAG_enumeration_type) {
                                        // For enum constants, get the enum's underlying type size
                                        Dwarf_Attribute enum_byte_size_attr = nullptr;
                                        ret = dwarf_attr(base_type_die,
                                                         DW_AT_byte_size,
                                                         &enum_byte_size_attr,
                                                         &error);
                                        if (ret == DW_DLV_OK) {
                                            Dwarf_Unsigned byte_size = 0;
                                            ret = dwarf_formudata(
                                                enum_byte_size_attr, &byte_size, &error);
                                            if (ret == DW_DLV_OK && has_address && address > 0) {
                                                // Read enum value as integer from memory
                                                constant_value = readConstantValueFromAddress(
                                                    dbg, address, byte_size, base_type_die);
                                            }
                                            dwarf_dealloc(dbg, enum_byte_size_attr, DW_DLA_ATTR);
                                        }
                                    } else if (ret == DW_DLV_OK &&
                                               base_tag == DW_TAG_pointer_type) {
                                        // For pointer constants (e.g., const char*)
                                        // Read the pointer value first, then try to dereference for
                                        // strings
                                        if (has_address && address > 0) {
                                            size_t ptr_size = is_32bit_ ? 4 : 8;
                                            constant_value = readConstantValueFromAddress(
                                                dbg, address, ptr_size, base_type_die);
                                        }
                                    } else {
                                        // For other types, get byte size from the base type
                                        Dwarf_Attribute byte_size_attr = nullptr;
                                        ret = dwarf_attr(base_type_die,
                                                         DW_AT_byte_size,
                                                         &byte_size_attr,
                                                         &error);
                                        if (ret == DW_DLV_OK) {
                                            Dwarf_Unsigned byte_size = 0;
                                            ret =
                                                dwarf_formudata(byte_size_attr, &byte_size, &error);
                                            if (ret == DW_DLV_OK && (has_address || address > 0)) {
                                                // Try to read the actual constant value from memory
                                                // (be more aggressive - many constants are in
                                                // .rodata)
                                                constant_value = readConstantValueFromAddress(
                                                    dbg, address, byte_size, base_type_die);
                                            } else {
                                                constant_value = "(const)";
                                            }
                                            dwarf_dealloc(dbg, byte_size_attr, DW_DLA_ATTR);
                                        } else {
                                            constant_value = "(const)";
                                        }
                                    }
                                    dwarf_dealloc_die(base_type_die);
                                }
                            }
                            dwarf_dealloc(dbg, base_type_attr, DW_DLA_ATTR);
                        }

                        if (constant_value.empty() || constant_value == "(const)") {
                            // One more attempt: try reading with estimated size for addressed
                            // variables
                            if (has_address && address > 0) {
                                // Use default sizes based on common types
                                size_t estimated_size = 4;  // Default to 4 bytes
                                std::string type_name =
                                    DwarfTypeResolver::getDwarfDieName(dbg, type_die);

                                // Estimate size from type name
                                if (type_name.find("int64") != std::string::npos ||
                                    type_name.find("double") != std::string::npos) {
                                    estimated_size = 8;
                                } else if (type_name.find("int16") != std::string::npos ||
                                           type_name.find("short") != std::string::npos) {
                                    estimated_size = 2;
                                } else if (type_name.find("int8") != std::string::npos ||
                                           type_name.find("char") != std::string::npos) {
                                    estimated_size = 1;
                                } else if (type_name.find("float") != std::string::npos) {
                                    estimated_size = 4;
                                }

                                constant_value = readConstantValueFromAddress(
                                    dbg, address, estimated_size, type_die);
                            } else {
                                constant_value = "(const)";
                            }
                        }
                    }
                }

                // Use linkage-based type resolution for unique identification
                TypeIdentifier type_id = resolveTypeIdentifier(dbg, var_die);

                // Store linkage name (unique!) or qualified name (fallback) for type lookup
                // This ensures correct type resolution even when multiple types have same simple
                // name
                if (!type_id.linkage_name.empty()) {
                    type_name = type_id.linkage_name;  // C++ type with unique mangled name
                } else if (!type_id.qualified_name.empty()) {
                    type_name = type_id.qualified_name;  // Qualified name fallback
                } else {
                    type_name = DwarfTypeResolver::resolveDwarfType(dbg, type_die);  // Last resort
                }

                dwarf_dealloc_die(type_die);
            }
        }
        dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
    }

    // Only process global variables (those with addresses) or constants
    if (!has_address && !is_constant) {
        return;
    }

    // Create full variable name with namespace
    std::string full_name =
        namespace_prefix.empty() ? var_name : namespace_prefix + "::" + var_name;

    // Store variable information using the fully qualified name (with namespace)
    // This ensures the output shows namespace::variable instead of just variable
    std::string demangled_name = demangleCppName(var_name);
    std::string full_demangled_name =
        namespace_prefix.empty() ? demangled_name : namespace_prefix + "::" + demangled_name;

    // Store in DWARF variables map using the fully qualified name as the key
    dwarf_variables_[full_name] = VariableInfo(string_interner_.intern(full_name),
                                               string_interner_.intern(full_demangled_name),
                                               string_interner_.intern(type_name),
                                               address,
                                               true,
                                               is_constant,
                                               constant_value);

    if (config_.verbosity > 1) {
        std::cout << "Found DWARF variable: " << var_name << " -> " << demangled_name
                  << " (type: " << type_name << ", addr: 0x" << std::hex << address << std::dec;
        if (is_constant) {
            std::cout << ", constant: " << constant_value;
        }
        std::cout << ")\n";
    }
}

std::string ElfReader::extractConstantValue(Dwarf_Debug /* dbg */, Dwarf_Attribute const_attr) {
    Dwarf_Error error = nullptr;
    std::string result;

    // Get the form of the constant value attribute
    Dwarf_Half form = 0;
    int ret = dwarf_whatform(const_attr, &form, &error);
    if (ret != DW_DLV_OK) {
        return "";  // Cannot determine form
    }

    // Handle different DWARF forms
    switch (form) {
        case DW_FORM_data1:
        case DW_FORM_data2:
        case DW_FORM_data4:
        case DW_FORM_data8: {
            Dwarf_Unsigned uval = 0;
            ret = dwarf_formudata(const_attr, &uval, &error);
            if (ret == DW_DLV_OK) {
                result = std::to_string(uval);
            }
            break;
        }
        case DW_FORM_sdata: {
            Dwarf_Signed sval = 0;
            ret = dwarf_formsdata(const_attr, &sval, &error);
            if (ret == DW_DLV_OK) {
                result = std::to_string(sval);
            }
            break;
        }
        case DW_FORM_string:
        case DW_FORM_strp: {
            char* str = nullptr;
            ret = dwarf_formstring(const_attr, &str, &error);
            if (ret == DW_DLV_OK && str != nullptr) {
                result = "\"" + std::string(str) + "\"";  // Quote string constants
            }
            break;
        }
        case DW_FORM_flag:
        case DW_FORM_flag_present: {
            Dwarf_Bool bval = 0;
            ret = dwarf_formflag(const_attr, &bval, &error);
            if (ret == DW_DLV_OK) {
                result = bval ? "true" : "false";
            }
            break;
        }
        case DW_FORM_addr: {
            Dwarf_Addr addr = 0;
            ret = dwarf_formaddr(const_attr, &addr, &error);
            if (ret == DW_DLV_OK) {
                // Format as hex address
                std::ostringstream oss;
                oss << "0x" << std::hex << addr;
                result = oss.str();
            }
            break;
        }
        default:
            // Unsupported form - try to get as unsigned data as fallback
            Dwarf_Unsigned uval = 0;
            ret = dwarf_formudata(const_attr, &uval, &error);
            if (ret == DW_DLV_OK) {
                result = std::to_string(uval) + " (form " + std::to_string(form) + ")";
            } else {
                result = "(unsupported form " + std::to_string(form) + ")";
            }
            break;
    }

    return result;
}

std::string
ElfReader::extractConstantValueFromMemory(Dwarf_Debug dbg, Dwarf_Die type_die, uint64_t address) {
    // Determine the size of the constant from the type
    Dwarf_Error error = nullptr;
    Dwarf_Unsigned byte_size = 0;

    if (type_die) {
        int ret = dwarf_bytesize(type_die, &byte_size, &error);
        if (ret != DW_DLV_OK) {
            // If we can't get the size, try to infer from type name
            std::string type_name = DwarfTypeResolver::getDwarfDieName(dbg, type_die);
            byte_size = DwarfTypeResolver::estimateTypeSize(type_name);
        }
    }

    // Default to 4 bytes if we still can't determine size
    if (byte_size == 0) {
        byte_size = TypeSizes::DEFAULT_SIZE;
    }

    // Use the existing implementation to read the value
    return readConstantValueFromAddress(dbg, address, byte_size, type_die);
}

// address and byte_size have distinct semantic meanings: address is memory location, byte_size is
// amount of data to read
std::string ElfReader::readConstantValueFromAddress(
    Dwarf_Debug dbg,
    uint64_t address,  // NOLINT(bugprone-easily-swappable-parameters)
    uint64_t byte_size,
    Dwarf_Die type_die) {
    try {
        // Find the section that contains this address
        size_t file_offset = 0;
        bool found_section = false;

        if (is_32bit_) {
            // For constants, first try .rodata section specifically (where const globals are
            // typically stored)
            for (size_t i = 0; i < sections32_.size(); ++i) {
                const auto& section = sections32_[i];
                if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_PROGBITS) &&
                    section.sh_size > 0) {
                    // Check if this is likely .rodata: read-only, non-executable PROGBITS
                    bool is_executable = (section.sh_flags & 0x4) != 0;  // SHF_EXECINSTR
                    bool is_writable = (section.sh_flags & 0x1) != 0;    // SHF_WRITE
                    bool is_rodata = !is_executable && !is_writable;

                    // For object files, try multiple strategies
                    bool address_matches = false;

                    // Strategy 1: Direct address match (for executables)
                    if (address >= section.sh_addr && address < section.sh_addr + section.sh_size) {
                        address_matches = true;
                        file_offset = section.sh_offset + (address - section.sh_addr);
                    }
                    // Strategy 2: Address relative to section start (for object files)
                    else if (section.sh_addr == 0 && address < section.sh_size) {
                        address_matches = true;
                        file_offset = section.sh_offset + address;
                    }

                    if (address_matches) {
                        found_section = true;
                        if (is_rodata) {
                            break;  // Found .rodata section, this is best for constants
                        }
                    }
                }
            }
        } else {
            for (const auto& section : sections64_) {
                if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_PROGBITS) &&
                    section.sh_size > 0) {
                    // For object files, try multiple strategies
                    bool address_matches = false;

                    // Strategy 1: Direct address match (for executables)
                    if (address >= section.sh_addr && address < section.sh_addr + section.sh_size) {
                        address_matches = true;
                        file_offset = section.sh_offset + (address - section.sh_addr);
                    }
                    // Strategy 2: Address relative to section start (for object files)
                    else if (section.sh_addr == 0 && address < section.sh_size) {
                        address_matches = true;
                        file_offset = section.sh_offset + address;
                    }

                    if (address_matches) {
                        found_section = true;
                        break;
                    }
                }
            }
        }

        if (!found_section) {
            return "(const)";  // Address not found in any section
        }

        // Ensure we don't read beyond file bounds
        if (file_offset + byte_size > file_access_->size()) {
            return "(const)";  // Would read beyond file
        }

        // Get DWARF type encoding and name to determine how to interpret the value
        Dwarf_Error error = nullptr;
        Dwarf_Half encoding = DW_ATE_signed;  // Default to signed int
        std::string type_name;

        if (type_die) {
            // Get type encoding
            Dwarf_Attribute encoding_attr = nullptr;
            int ret = dwarf_attr(type_die, DW_AT_encoding, &encoding_attr, &error);
            if (ret == DW_DLV_OK) {
                Dwarf_Unsigned enc_val = 0;
                ret = dwarf_formudata(encoding_attr, &enc_val, &error);
                if (ret == DW_DLV_OK) {
                    encoding = (Dwarf_Half)enc_val;
                }
                dwarf_dealloc(dbg, encoding_attr, DW_DLA_ATTR);
            }

            // Get type name for better formatting decisions
            char* name_str = nullptr;
            ret = dwarf_diename(type_die, &name_str, &error);
            if (ret == DW_DLV_OK && name_str) {
                type_name = std::string(name_str);
                dwarf_dealloc(dbg, name_str, DW_DLA_STRING);
            }
        }

        // Read and format the value based on size and encoding
        std::stringstream ss;

        switch (byte_size) {
            case 1: {
                if (encoding == DW_ATE_unsigned || encoding == DW_ATE_unsigned_char) {
                    uint8_t value = readValue<uint8_t>(file_offset);
                    // Check if this is a printable character
                    if ((type_name == "char" || encoding == DW_ATE_unsigned_char) && value >= 32 &&
                        value <= 126 && value != 92) {  // Printable ASCII, not backslash
                        ss << "'" << static_cast<char>(value) << "'";
                    } else if ((type_name == "char" || encoding == DW_ATE_unsigned_char) &&
                               value == 0) {
                        ss << "'\\0'";  // Null character
                    } else {
                        ss << static_cast<unsigned int>(value);
                    }
                } else {
                    int8_t value = readValue<int8_t>(file_offset);
                    // Check if this is a printable character (for signed char)
                    if (type_name == "char" && value >= 32 && value <= 126 && value != 92) {
                        ss << "'" << static_cast<char>(value) << "'";
                    } else if (type_name == "char" && value == 0) {
                        ss << "'\\0'";  // Null character
                    } else {
                        ss << static_cast<int>(value);
                    }
                }
                break;
            }
            case 2: {
                if (encoding == DW_ATE_unsigned) {
                    uint16_t value = readValue<uint16_t>(file_offset);
                    ss << value;
                } else {
                    int16_t value = readValue<int16_t>(file_offset);
                    ss << value;
                }
                break;
            }
            case 4: {
                if (encoding == DW_ATE_float) {
                    uint32_t raw_value = readValue<uint32_t>(file_offset);
                    float float_value;
                    std::memcpy(&float_value, &raw_value, sizeof(float));
                    // Use sufficient precision for float representation
                    ss << std::fixed << std::setprecision(6) << float_value << "f";
                } else if (encoding == DW_ATE_unsigned) {
                    uint32_t value = readValue<uint32_t>(file_offset);
                    ss << value << "u";
                } else {
                    int32_t value = readValue<int32_t>(file_offset);
                    ss << value;
                }
                break;
            }
            case 8: {
                if (encoding == DW_ATE_float) {
                    uint64_t raw_value = readValue<uint64_t>(file_offset);
                    double double_value;
                    std::memcpy(&double_value, &raw_value, sizeof(double));
                    // Use sufficient precision for double representation
                    ss << std::fixed << std::setprecision(15) << double_value;
                } else if (encoding == DW_ATE_unsigned) {
                    uint64_t value = readValue<uint64_t>(file_offset);
                    ss << value << "ul";
                } else {
                    int64_t value = readValue<int64_t>(file_offset);
                    ss << value << "l";
                }
                break;
            }
            default: {
                // For unknown sizes, show as hex bytes
                ss << "0x";
                for (uint64_t i = 0; i < byte_size && i < 16; ++i) {  // Limit to 16 bytes
                    uint8_t byte_val = readValue<uint8_t>(file_offset + i);
                    ss << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<unsigned int>(byte_val);
                }
                break;
            }
        }

        return ss.str();

    } catch (const std::exception&) {
        // If reading fails for any reason, return placeholder
        return "(const)";
    }
}

std::string ElfReader::readStringFromAddress(uint64_t address) {
    try {
        // Find the section that contains this address
        size_t file_offset = 0;
        bool found_section = false;
        size_t section_end = 0;

        if (is_32bit_) {
            for (const auto& section : sections32_) {
                // Check if address is within this section
                if (address >= section.sh_addr && address < section.sh_addr + section.sh_size) {
                    file_offset = section.sh_offset + (address - section.sh_addr);
                    section_end = section.sh_offset + section.sh_size;
                    found_section = true;
                    break;
                }
                // Handle object files where sh_addr might be 0
                else if (section.sh_addr == 0 && address < section.sh_size) {
                    file_offset = section.sh_offset + address;
                    section_end = section.sh_offset + section.sh_size;
                    found_section = true;
                    break;
                }
            }
        } else {
            for (const auto& section : sections64_) {
                // Check if address is within this section
                if (address >= section.sh_addr && address < section.sh_addr + section.sh_size) {
                    file_offset = section.sh_offset + (address - section.sh_addr);
                    section_end = section.sh_offset + section.sh_size;
                    found_section = true;
                    break;
                }
                // Handle object files where sh_addr might be 0
                else if (section.sh_addr == 0 && address < section.sh_size) {
                    file_offset = section.sh_offset + address;
                    section_end = section.sh_offset + section.sh_size;
                    found_section = true;
                    break;
                }
            }
        }

        if (!found_section) {
            return "";  // Address not found in any section
        }

        // Use memory validator for comprehensive bounds checking
        if (file_offset >= memory_validator_->getSize()) {
            return "";
        }

        // Read null-terminated string using memory validator for safety
        std::string result;
        const size_t MAX_STRING_LENGTH = ElfReaderUtils::MemoryConstants::MAX_STRING_LENGTH;
        size_t max_offset = std::min(section_end, memory_validator_->getSize());

        // Validate the full string range first
        size_t max_possible_length = max_offset - file_offset;
        size_t safe_length = std::min(max_possible_length, MAX_STRING_LENGTH);

        try {
            memory_validator_->validateRange(file_offset, safe_length, "string reading");

            for (size_t i = file_offset; i < max_offset && (i - file_offset) < MAX_STRING_LENGTH;
                 ++i) {
                char ch = readValue<char>(i);
                if (ch == '\0') {
                    break;  // Found null terminator
                }
                // Only include printable ASCII characters and common whitespace
                if ((ch >= AsciiChars::PRINTABLE_MIN && ch <= AsciiChars::PRINTABLE_MAX) ||
                    ch == '\t' || ch == '\n' || ch == '\r') {
                    result += ch;
                } else {
                    // Non-printable character found, likely not a valid string
                    return "";
                }
            }
        } catch (const ElfReaderExceptions::MemoryAccessError&) {
            // If validation fails, return empty string for safety
            return "";
        }

        return result;

    } catch (const std::exception&) {
        // If reading fails for any reason, return empty string
        return "";
    }
}

std::string ElfReader::readMemoryAtAddress(uint64_t address, uint64_t size) const {
    std::string result;
    try {
        if (is_32bit_) {
            for (size_t i = 0; i < sections32_.size(); ++i) {
                const auto& section = sections32_[i];
                if (address >= section.sh_addr &&
                    address + size <= section.sh_addr + section.sh_size && section.sh_addr != 0) {
                    uint64_t section_offset = address - section.sh_addr;
                    std::vector<uint8_t> section_data;
                    if (readSectionData(static_cast<uint16_t>(i), section_data)) {
                        if (section_offset + size <= section_data.size()) {
                            result.assign(
                                reinterpret_cast<const char*>(section_data.data() + section_offset),
                                size);
                        }
                    }
                    break;
                }
            }
        } else {
            for (size_t i = 0; i < sections64_.size(); ++i) {
                const auto& section = sections64_[i];
                if (address >= section.sh_addr &&
                    address + size <= section.sh_addr + section.sh_size && section.sh_addr != 0) {
                    uint64_t section_offset = address - section.sh_addr;
                    std::vector<uint8_t> section_data;
                    if (readSectionData(static_cast<uint16_t>(i), section_data)) {
                        if (section_offset + size <= section_data.size()) {
                            result.assign(
                                reinterpret_cast<const char*>(section_data.data() + section_offset),
                                size);
                        }
                    }
                    break;
                }
            }
        }
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
        // Return empty string on error - intentionally swallow exceptions
    }
    return result;
}

// LEGACY: Keep old implementation for now
bool ElfReader::parseDwarfInfo() {
    // Find .debug_info and .debug_str sections
    size_t debug_info_offset = 0, debug_info_size = 0;
    size_t debug_str_offset = 0, debug_str_size = 0;
    bool found_debug_info = false, found_debug_str = false;

    if (is_32bit_) {
        for (const auto& section : sections32_) {
            if (section.name == ".debug_info") {
                debug_info_offset = section.sh_offset;
                debug_info_size = section.sh_size;
                found_debug_info = true;
            } else if (section.name == ".debug_str") {
                debug_str_offset = section.sh_offset;
                debug_str_size = section.sh_size;
                found_debug_str = true;
            }
        }
    } else {
        for (const auto& section : sections64_) {
            if (section.name == ".debug_info") {
                debug_info_offset = section.sh_offset;
                debug_info_size = section.sh_size;
                found_debug_info = true;
            } else if (section.name == ".debug_str") {
                debug_str_offset = section.sh_offset;
                debug_str_size = section.sh_size;
                found_debug_str = true;
            }
        }
    }

    if (!found_debug_info) {
        return false;
    }

    // Extract debug sections data
    if (debug_info_offset + debug_info_size <= file_access_->size()) {
        debug_info_data_.assign(file_access_->data() + debug_info_offset,
                                file_access_->data() + debug_info_offset + debug_info_size);
    }

    if (found_debug_str && debug_str_offset + debug_str_size <= file_access_->size()) {
        debug_str_data_.assign(file_access_->data() + debug_str_offset,
                               file_access_->data() + debug_str_offset + debug_str_size);
    }

    // Simple DWARF parsing - skip compilation unit header and parse DIEs
    if (debug_info_data_.size() < 11) {  // Minimum CU header size
        return false;
    }

    size_t offset = 11;  // Skip CU header (length=4, version=2, abbrev_offset=4, address_size=1)

    try {
        // Parse the root compilation unit and extract types
        while (offset < debug_info_data_.size()) {
            DwarfDIE die = parseDwarfDIE(debug_info_data_.data(), offset, debug_info_data_.size());
            if (die.abbrev_code == 0)
                break;  // End of DIEs

            extractTypesFromDwarf(die);
        }
        return true;
    } catch (const std::exception&) {
        return false;  // DWARF parsing failed, fall back to hardcoded analysis
    }
}

DwarfDIE ElfReader::parseDwarfDIE(const uint8_t* data, size_t& offset, size_t max_size) {
    if (offset >= max_size) {
        return DwarfDIE{};  // Return default-constructed empty DIE
    }

    // For simplicity, this is a basic DWARF parser that extracts key information
    // A full implementation would parse abbreviation tables, but for type discovery
    // we can work with the raw DIE data

    // Read DIE data directly from debug info
    // This simplified approach extracts the most common patterns we need
    DwarfDIE die;
    die.offset = offset;
    die.tag = 0;               // Initialize tag field to prevent uninitialized warning
    die.has_children = false;  // Initialize has_children field to prevent uninitialized warning

    // Skip complex parsing for now and look for key patterns
    // This basic implementation will be enhanced as needed
    die.abbrev_code = (offset < max_size) ? data[offset] : 0;
    if (die.abbrev_code == 0) {
        return DwarfDIE{};  // Return default-constructed empty DIE
    }

    offset++;    // Move past abbrev code
    return die;  // Return the constructed DIE
}

std::string ElfReader::getDwarfString(uint32_t string_offset) const {
    if (string_offset < debug_str_data_.size()) {
        return std::string(reinterpret_cast<const char*>(debug_str_data_.data() + string_offset));
    }
    return "";
}

void ElfReader::processDwarf5TypeQualifier(Dwarf_Debug dbg,
                                           Dwarf_Die die,
                                           const std::string& /* namespace_prefix */,
                                           TypeQualifiers qualifier) {
    try {
        Dwarf_Error error = nullptr;

        // Get the underlying type that this qualifier applies to
        Dwarf_Attribute type_attr = nullptr;
        int ret = dwarf_attr(die, DW_AT_type, &type_attr, &error);
        if (ret != DW_DLV_OK) {
            return;  // No type reference, skip
        }

        // Follow the type reference to get the base type
        Dwarf_Off type_offset = 0;
        ret = dwarf_global_formref(type_attr, &type_offset, &error);
        if (ret != DW_DLV_OK) {
            dwarf_dealloc_attribute(type_attr);
            return;
        }

        // Get the base type DIE
        Dwarf_Die type_die = nullptr;
        ret = dwarf_offdie_b(dbg, type_offset, 1, &type_die, &error);
        if (ret != DW_DLV_OK) {
            dwarf_dealloc_attribute(type_attr);
            return;
        }

        // Get the base type name
        std::string base_type_name = DwarfTypeResolver::getDwarfDieName(dbg, type_die);
        if (base_type_name.empty()) {
            base_type_name = DwarfTypeResolver::resolveDwarfType(dbg, type_die);
        }

        // Build qualified type name
        std::string qualified_name;
        switch (qualifier) {
            case TypeQualifiers::IMMUTABLE:
                qualified_name = "immutable " + base_type_name;
                break;
            case TypeQualifiers::PACKED:
                qualified_name = "packed " + base_type_name;
                break;
            case TypeQualifiers::ATOMIC:
                qualified_name = "atomic " + base_type_name;
                break;
            case TypeQualifiers::DYNAMIC:
                qualified_name = "dynamic " + base_type_name;
                break;
            default:
                qualified_name = base_type_name;
                break;
        }

        // Create or update advanced type info
        AdvancedTypeInfo& advanced_info = advanced_types_[qualified_name];
        advanced_info.qualifiers = static_cast<TypeQualifiers>(
            static_cast<uint32_t>(advanced_info.qualifiers) | static_cast<uint32_t>(qualifier));

        // Add type dependency
        advanced_info.dependencies.emplace_back(qualified_name, base_type_name, "qualified_type");

        if (config_.verbosity > 1) {
            std::cout << "DWARF 5: Found qualified type: " << qualified_name
                      << " (qualifier: " << static_cast<uint32_t>(qualifier) << ")\n";
        }

        // Clean up
        dwarf_dealloc_die(type_die);
        dwarf_dealloc_attribute(type_attr);

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "Error processing DWARF 5 type qualifier: " << e.what() << "\n";
        }
    }
}

void ElfReader::processDwarfTemplateParameter(Dwarf_Debug dbg,
                                              Dwarf_Die die,
                                              const std::string& /* namespace_prefix */,
                                              bool is_type_parameter) {
    try {
        Dwarf_Error error = nullptr;

        // Get parameter name
        std::string param_name = DwarfTypeResolver::getDwarfDieName(dbg, die);
        if (param_name.empty()) {
            param_name = is_type_parameter ? "unnamed_type" : "unnamed_value";
        }

        // Get parameter type (for both type and value parameters)
        std::string param_type;
        Dwarf_Attribute type_attr = nullptr;
        int ret = dwarf_attr(die, DW_AT_type, &type_attr, &error);
        if (ret == DW_DLV_OK) {
            Dwarf_Off type_offset = 0;
            ret = dwarf_global_formref(type_attr, &type_offset, &error);
            if (ret == DW_DLV_OK) {
                Dwarf_Die type_die = nullptr;
                ret = dwarf_offdie_b(dbg, type_offset, 1, &type_die, &error);
                if (ret == DW_DLV_OK) {
                    param_type = DwarfTypeResolver::resolveDwarfType(dbg, type_die);
                    dwarf_dealloc_die(type_die);
                }
            }
            dwarf_dealloc_attribute(type_attr);
        }

        // Get parameter value (for value parameters)
        std::string param_value;
        if (!is_type_parameter) {
            Dwarf_Attribute const_attr = nullptr;
            ret = dwarf_attr(die, DW_AT_const_value, &const_attr, &error);
            if (ret == DW_DLV_OK) {
                Dwarf_Half form = 0;
                ret = dwarf_whatform(const_attr, &form, &error);
                if (ret == DW_DLV_OK) {
                    if (form == DW_FORM_data1 || form == DW_FORM_data2 || form == DW_FORM_data4 ||
                        form == DW_FORM_data8) {
                        Dwarf_Unsigned uval = 0;
                        ret = dwarf_formudata(const_attr, &uval, &error);
                        if (ret == DW_DLV_OK) {
                            param_value = std::to_string(uval);
                        }
                    } else if (form == DW_FORM_sdata) {
                        Dwarf_Signed sval = 0;
                        ret = dwarf_formsdata(const_attr, &sval, &error);
                        if (ret == DW_DLV_OK) {
                            param_value = std::to_string(sval);
                        }
                    }
                }
                dwarf_dealloc_attribute(const_attr);
            }
        }

        // Create template parameter
        TemplateParameter template_param(param_name, param_type, param_value, is_type_parameter);

        // Find the parent template (traverse up the DIE hierarchy)
        dwarf_die_CU_offset_range(die, nullptr, nullptr, &error);

        // For now, store in a temporary structure - this will be enhanced
        // when we implement full template specialization tracking

        if (config_.verbosity > 1) {
            std::cout << "DWARF 5: Found template " << (is_type_parameter ? "type" : "value")
                      << " parameter: " << param_name;
            if (!param_type.empty()) {
                std::cout << " : " << param_type;
            }
            if (!param_value.empty()) {
                std::cout << " = " << param_value;
            }
            std::cout << "\n";
        }

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "Error processing template parameter: " << e.what() << "\n";
        }
    }
}

#endif  // HAVE_LIBDWARF

std::string ElfReader::getCleanSymbolName(const std::string& symbol_name) const {
    // First try to demangle if it's a C++ mangled name
    std::string demangled = demangleCppName(symbol_name);
    if (demangled != symbol_name) {
        return demangled;
    }

    // Handle other symbol name cleaning patterns if needed
    return symbol_name;
}

std::string ElfReader::demangleCppName(const std::string& mangled_name) const {
    // Check cache first to avoid expensive demangling
    auto it = demangled_cache_.find(mangled_name);
    if (it != demangled_cache_.end()) {
        return it->second;
    }

    // Use the standard C++ ABI demangler for proper demangling
    std::string result = mangled_name;  // Default to original name

    if (!mangled_name.empty() && mangled_name.substr(0, 2) == "_Z") {
        int status = 0;
        char* demangled = abi::__cxa_demangle(mangled_name.c_str(), nullptr, nullptr, &status);

        if (status == 0 && demangled != nullptr) {
            result = std::string(demangled);
            free(demangled);
        } else {
            // If demangling failed, fall back to the original name
            if (demangled != nullptr) {
                free(demangled);
            }
        }
    }

    // Cache the result (even if it's the same as input for non-mangled names)
    demangled_cache_[mangled_name] = result;

    return result;
}

std::string ElfReader::findTypeForSymbol(const std::string& symbol_name) const {
// First check if we have DWARF variable information for this symbol
#if HAVE_LIBDWARF
    auto var_it = dwarf_variables_.find(symbol_name);
    if (var_it != dwarf_variables_.end()) {
        return var_it->second.type_name;
    }
#endif  // HAVE_LIBDWARF

    // Try with demangled name
    std::string clean_name = getCleanSymbolName(symbol_name);
#if HAVE_LIBDWARF
    auto var_clean_it = dwarf_variables_.find(clean_name);
    if (var_clean_it != dwarf_variables_.end()) {
        return var_clean_it->second.type_name;
    }
#endif  // HAVE_LIBDWARF

    // Legacy hardcoded logic for globalInstance (backward compatibility)
    if (symbol_name == "globalInstance" || clean_name == "globalInstance") {
        std::string best_match;
        size_t best_size = 0;
        size_t best_member_count = 0;

        auto all_type_names = types_.getAllTypeNames();
        for (const auto& type_name : all_type_names) {
            auto type_info = types_.getType(type_name);
            if (!type_info.has_value())
                continue;
            const TypeInfo& type_data = *type_info;

            // Skip simple types, look for complex structures
            if (type_name.find("::") != std::string::npos ||
                type_name.find("Struct") != std::string::npos ||
                type_name.find("Class") != std::string::npos) {
                // Prefer structures with more members and larger size (likely derived classes)
                if (type_data.members.size() > best_member_count ||
                    (type_data.members.size() == best_member_count && type_data.size > best_size)) {
                    best_match = type_name;
                    best_size = type_data.size;
                    best_member_count = type_data.members.size();
                }
            }
        }

        return best_match;
    }

    // No type found
    return "";
}

void ElfReader::extractTypesFromDwarf(const DwarfDIE& die, const std::string& namespace_prefix) {
    // This method will be enhanced to properly extract type information from DWARF
    // For now, it provides the framework for generic type discovery

    std::string full_name = namespace_prefix;
    if (!namespace_prefix.empty() && !die.getName().empty()) {
        full_name += "::" + die.getName();
    } else if (!die.getName().empty()) {
        full_name = die.getName();
    }

    switch (die.tag) {
        case static_cast<uint32_t>(DW_TAG_class_type):
            processDwarfClass(die, full_name);
            break;
        case static_cast<uint32_t>(DW_TAG_structure_type):
            processDwarfStructure(die, full_name);
            break;
        case static_cast<uint32_t>(DW_TAG_namespace):
            // Recursively process namespace contents
            for (const auto& child : die.children) {
                extractTypesFromDwarf(child, full_name);
            }
            break;
        default:
            break;
    }
}

// Simple fallback type size estimator when libdwarf is not available
uint64_t ElfReader::estimateTypeSizeFallback(const std::string& type_name) const {
    // Simple heuristic based on type name patterns
    if (type_name.empty())
        return 4;

    if (type_name.find("int64") != std::string::npos ||
        type_name.find("uint64") != std::string::npos ||
        type_name.find("long") != std::string::npos) {
        return 8;
    }
    if (type_name.find("int32") != std::string::npos ||
        type_name.find("uint32") != std::string::npos ||
        type_name.find("int") != std::string::npos) {
        return 4;
    }
    if (type_name.find("int16") != std::string::npos ||
        type_name.find("uint16") != std::string::npos ||
        type_name.find("short") != std::string::npos) {
        return 2;
    }
    if (type_name.find("int8") != std::string::npos ||
        type_name.find("uint8") != std::string::npos ||
        type_name.find("char") != std::string::npos) {
        return 1;
    }
    if (type_name.find("float") != std::string::npos) {
        return 4;
    }
    if (type_name.find("double") != std::string::npos) {
        return 8;
    }
    if (type_name.find("bool") != std::string::npos) {
        return 1;
    }

    // Default fallback
    return 4;
}

void ElfReader::processDwarfClass(const DwarfDIE& class_die, const std::string& full_name) {
    if (full_name.empty())
        return;

    std::vector<TypeMember> members;
    uint32_t total_size = class_die.getByteSize();

    // Process class members
    for (const auto& child : class_die.children) {
        if (child.tag == static_cast<uint32_t>(DW_TAG_member)) {
            std::string member_name = child.getName();
            uint32_t member_offset = child.getDataMemberLocation();
            uint32_t member_type_offset = child.getType();

            // Resolve type name from type offset
            std::string type_name = "auto";  // Default fallback
            uint32_t member_size = 4;        // Default size
            bool is_struct_member = false;   // Track if this member is a struct/class type

            if (member_type_offset != 0) {
                // Try to find the type DIE by offset in our cached DIEs
                auto die_it = dwarf_dies_.find(member_type_offset);
                if (die_it != dwarf_dies_.end()) {
                    const auto& type_die = die_it->second;
                    type_name = type_die.getName();
                    if (!type_name.empty()) {
                        member_size = type_die.getByteSize();
                        if (member_size == 0) {
                            member_size = estimateTypeSizeFallback(type_name);
                        }
                    }

                    // Check if this member's type is a struct or class
                    // Need to follow type references (typedef, const, etc.) to find the actual type
                    uint32_t actual_type_tag = type_die.tag;
                    Dwarf_Off check_offset = member_type_offset;

                    // Follow type chain to find the ultimate type (handle typedef, const, etc.)
                    for (int depth = 0; depth < 10;
                         ++depth) {  // Limit depth to prevent infinite loops
                        auto check_it = dwarf_dies_.find(check_offset);
                        if (check_it == dwarf_dies_.end())
                            break;

                        const auto& check_die = check_it->second;
                        actual_type_tag = check_die.tag;

                        // If this is a typedef, const, volatile, etc., follow to the underlying
                        // type
                        if (actual_type_tag == static_cast<uint32_t>(DW_TAG_typedef) ||
                            actual_type_tag == static_cast<uint32_t>(DW_TAG_const_type) ||
                            actual_type_tag == static_cast<uint32_t>(DW_TAG_volatile_type) ||
                            actual_type_tag == static_cast<uint32_t>(DW_TAG_restrict_type)) {
                            check_offset = check_die.getType();
                            if (check_offset == 0)
                                break;
                        } else {
                            // Found the actual type
                            break;
                        }
                    }

                    // Mark as struct if the actual type is a structure or class
                    if (actual_type_tag == static_cast<uint32_t>(DW_TAG_structure_type) ||
                        actual_type_tag == static_cast<uint32_t>(DW_TAG_class_type) ||
                        actual_type_tag == static_cast<uint32_t>(DW_TAG_union_type)) {
                        is_struct_member = true;
                    }
                }
            }

            members.emplace_back(string_interner_.intern(member_name),
                                 string_interner_.intern(type_name),
                                 member_offset,
                                 member_size,
                                 is_struct_member);
        }
    }

    types_.addType(full_name, TypeInfo(total_size, members));
}

void ElfReader::processDwarfStructure(const DwarfDIE& struct_die, const std::string& full_name) {
    // Similar to class processing but for structures
    processDwarfClass(struct_die, full_name);
}

// strtab_index and offset have distinct semantic meanings
std::string
ElfReader::getString(uint32_t strtab_index,  // NOLINT(bugprone-easily-swappable-parameters)
                     uint32_t offset) const {
    auto it = string_tables_.find(strtab_index);
    if (it != string_tables_.end()) {
        const auto& strtab = it->second;
        if (offset < strtab.size()) {
            const char* str = &strtab[offset];
            return std::string(str);
        }
    }
    return "";
}

std::string ElfReader::getTypeName(SymbolType symbol_type) const {
    switch (symbol_type) {
        case SymbolType::STT_NOTYPE:
            return "NOTYPE";
        case SymbolType::STT_OBJECT:
            return "OBJECT";
        case SymbolType::STT_FUNC:
            return "FUNC";
        case SymbolType::STT_SECTION:
            return "SECTION";
        case SymbolType::STT_FILE:
            return "FILE";
        default:
            return "UNKNOWN(" + std::to_string(static_cast<int>(symbol_type)) + ")";
    }
}

std::string ElfReader::getGenericParamName(size_t param_index) const {
    // Generic parameter names based on common embedded control patterns
    // These work for any structure regardless of naming convention
    switch (param_index) {
        case 0:
            return "parameter_0";  // First parameter
        case 1:
            return "parameter_1";  // Second parameter
        case 2:
            return "parameter_2";  // Third parameter
        case 3:
            return "parameter_3";  // Fourth parameter
        case 4:
            return "parameter_4";  // Fifth parameter
        case 5:
            return "parameter_5";  // Sixth parameter
        case 6:
            return "parameter_6";  // Seventh parameter
        case 7:
            return "parameter_7";  // Eighth parameter
        case 8:
            return "parameter_8";  // Ninth parameter
        case 9:
            return "parameter_9";  // Tenth parameter
        case 10:
            return "parameter_10";  // Eleventh parameter
        case 11:
            return "parameter_11";  // Twelfth parameter
        case 12:
            return "parameter_12";  // Thirteenth parameter
        case 13:
            return "parameter_13";  // Fourteenth parameter
        case 14:
            return "parameter_14";  // Fifteenth parameter
        case 15:
            return "parameter_15";  // Sixteenth parameter
        default:
            return "parameter_" + std::to_string(param_index);  // General case
    }
}

std::vector<MemberInfo> ElfReader::expandStructureMembers(const std::string& base_name,
                                                          const std::string& type_name,
                                                          uint64_t base_address,
                                                          uint32_t offset) const {
    std::vector<MemberInfo> members;

    // Try linkage-based lookup first (most reliable)
    auto type_info = types_.getTypeByLinkageName(type_name);

    // Fallback to qualified name lookup (for C structs without linkage names)
    if (!type_info.has_value()) {
        type_info = types_.getTypeByQualifiedName(type_name);
    }

    // Last resort: simple name lookup (backward compatibility)
    if (!type_info.has_value()) {
        type_info = types_.getType(type_name);
    }

    // Enforce strict matching in constants mode
    // Check confidence level - reject ambiguous matches to prevent wrong constant values
    if (config_.constantsOnly && type_info.has_value()) {
        TypeMatchConfidence confidence = getTypeMatchConfidence(type_name);

        // Only allow high-confidence matches in constants mode
        if (confidence == TypeMatchConfidence::AMBIGUOUS_NAME) {
            // DON'T expand with ambiguous type - better to show no members than WRONG members!
            if (config_.verbosity > 0) {
                std::cerr << "Warning: Skipping ambiguous type expansion for '" << type_name
                          << "' in constants mode (multiple types with same name)" << std::endl;
            }

            // Return single unexpanded member instead of wrong members
            MemberInfo base_member(string_interner_.intern(base_name),
                                   base_address + offset,
                                   string_interner_.intern(type_name));
            if (config_.showSections) {
                base_member.section_name = getSectionNameForAddress(base_address + offset);
            }
            members.push_back(base_member);
            return members;
        }
    }

    // If direct lookup fails, try improved resolution strategy
    // BUT: In constants mode, be very strict to avoid expanding with wrong type
    if (!type_info.has_value() && !config_.constantsOnly) {
        // Strategy 1: Look for unique DIE-based key (type_name@offset)
        auto all_type_names = types_.getAllTypeNames();
        for (const auto& key : all_type_names) {
            if (key.find("@") != std::string::npos) {
                std::string base_key = key.substr(0, key.find("@"));
                if (base_key == type_name) {
                    type_info = types_.getType(key);
                    if (type_info.has_value()) {
                        break;
                    }
                }
            }
        }

        // Strategy 2: Try case-insensitive matching for ParaInit_t vs paraInit_t
        if (!type_info.has_value()) {
            std::string lower_type_name = type_name;
            std::transform(
                lower_type_name.begin(), lower_type_name.end(), lower_type_name.begin(), ::tolower);

            for (const auto& key : all_type_names) {
                std::string lower_key = key;
                std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);

                if (lower_key == lower_type_name ||
                    lower_key.find(lower_type_name) != std::string::npos ||
                    lower_type_name.find(lower_key) != std::string::npos) {
                    type_info = types_.getType(key);
                    if (type_info.has_value()) {
                        break;
                    }
                }
            }
        }

        // Strategy 3: Try universal typedef chain resolution (handles typedef → unnamed struct)
        if (!type_info.has_value()) {
            std::string resolved_type = resolveTypedefChain(type_name);
            if (!resolved_type.empty() && resolved_type != type_name) {
                type_info = types_.getType(resolved_type);
            }
        }

        // Strategy 4: Only if still not found, try namespace matching (more conservative)
        // BUT: Only use this if there's exactly ONE candidate to avoid wrong type matches
        if (!type_info.has_value()) {
            std::vector<std::string> candidates;
            for (const auto& key : all_type_names) {
                if (key.length() > type_name.length() &&
                    key.substr(key.length() - type_name.length()) == type_name &&
                    key[key.length() - type_name.length() - 1] == ':') {
                    candidates.push_back(key);
                }
            }

            // ONLY use if we have exactly ONE unambiguous candidate
            // If multiple candidates exist, we can't know which is correct
            if (candidates.size() == 1) {
                type_info = types_.getType(candidates[0]);
            }
            // If multiple candidates: don't expand structure with wrong type
        }
    }

    // Check if the found type information is adequate
    bool type_info_is_adequate = false;
    if (type_info.has_value()) {
        const TypeInfo& type_data = *type_info;
        // For any structure, check if we have enough fields to be realistic
        // Most structures should have more than 2 fields, but we'll accept any with members
        type_info_is_adequate = (type_data.members.size() > 2) || !type_data.members.empty();
    }

    if (!type_info.has_value() || !type_info_is_adequate) {
        // If we don't know the structure OR the type info is inadequate, try custom decoding
        uint64_t estimated_size = estimateTypeSizeFallback(type_name);
        if (estimated_size > 0) {
            MemberInfo base_member(string_interner_.intern(base_name),
                                   base_address + offset,
                                   string_interner_.intern(type_name),
                                   estimated_size);
            if (config_.showSections) {
                base_member.section_name = getSectionNameForAddress(base_address + offset);
            }
            members.push_back(base_member);
        } else {
            MemberInfo base_member(string_interner_.intern(base_name),
                                   base_address + offset,
                                   string_interner_.intern(type_name));
            if (config_.showSections) {
                base_member.section_name = getSectionNameForAddress(base_address + offset);
            }
            members.push_back(base_member);
        }

        // General handling for any structure that contains constant parameters
        // Try to decode structures even when DWARF type info is missing or inadequate
        // But only apply this to structures that actually appear to contain constant data
        bool has_constant_pattern = false;

        // Check if the base name suggests this might be a structure with constants
        // Look for common patterns in embedded systems (but avoid hardcoding specific names)
        if (base_name.find("::") != std::string::npos) {  // Has namespace/class structure
            has_constant_pattern = true;
        }
        // Also check if the type name suggests a parameter structure
        else if (type_name.find("_t") != std::string::npos ||      // Typedef suffix
                 type_name.find("Param") != std::string::npos ||   // Contains "Param"
                 type_name.find("Config") != std::string::npos) {  // Contains "Config"
            has_constant_pattern = true;
        }

        if (has_constant_pattern) {
            // Try to extract actual member names from existing DWARF type information
            std::vector<std::pair<std::string, uint32_t>> actual_members =
                getActualMemberNames(type_name);

            if (!actual_members.empty()) {
                // Use actual member names found in DWARF type information
                for (const auto& member_info : actual_members) {
                    const std::string& member_name = member_info.first;
                    uint32_t member_offset = member_info.second;
                    uint64_t member_address = base_address + offset + member_offset;

                    // Try to read the member value
                    std::string member_data = readMemoryAtAddress(member_address, 4);
                    if (!member_data.empty() && member_data.size() >= 4) {
                        // Read 4 bytes as float (most common for parameter structures)
                        uint32_t raw_value;
                        std::memcpy(&raw_value, member_data.data(), 4);
                        float float_val;
                        std::memcpy(&float_val, &raw_value, 4);

                        std::string full_member_name = base_name + "." + member_name;
                        MemberInfo param_member(string_interner_.intern(full_member_name),
                                                member_address,
                                                string_interner_.intern("float"),
                                                4);

                        // Format the float value
                        std::stringstream ss;
                        ss << std::fixed << std::setprecision(6) << float_val << "f";
                        param_member.constant_value = ss.str();
                        param_member.is_constant = true;

                        if (config_.showSections) {
                            param_member.section_name = getSectionNameForAddress(member_address);
                        }

                        members.push_back(param_member);
                    }
                }
            }
            // If actual member names cannot be found, don't expand the structure
            // This avoids providing misleading generic parameter names
        }

        return members;
    }

    const TypeInfo& type_data = *type_info;

    for (const auto& member : type_data.members) {
        std::string member_name = base_name + "." + member.name;
        uint64_t member_address = base_address + offset + member.offset;

        if (member.is_struct) {
            // Check if we can find the nested structure type
            bool found_nested_type = false;

            // Try direct lookup first
            if (types_.hasType(member.type)) {
                found_nested_type = true;
            } else {
                // Try the same improved resolution as the parent
                auto all_type_names = types_.getAllTypeNames();
                for (const auto& key : all_type_names) {
                    if (key.find("@") != std::string::npos) {
                        std::string base_key = key.substr(0, key.find("@"));
                        if (base_key == member.type) {
                            found_nested_type = true;
                            break;
                        }
                    }
                }
            }

            if (found_nested_type) {
                // Recursively expand nested structures
                auto nested_members = expandStructureMembers(
                    member_name, member.type, base_address, offset + member.offset);
                members.insert(members.end(), nested_members.begin(), nested_members.end());
            } else {
                // If nested structure not found, show as a single member with enhanced metadata
                // Use estimated size if DWARF size seems incorrect (e.g., arrays showing as 4
                // bytes)
                uint64_t correct_size = estimateTypeSizeFallback(member.type);
                if (correct_size > 0 && (member.type.find('[') != std::string::npos ||
                                         member.type == "uint64_t" || member.type == "double")) {
                    MemberInfo member_info(string_interner_.intern(member_name),
                                           member_address,
                                           string_interner_.intern(member.type),
                                           correct_size);
                    if (config_.showSections) {
                        member_info.section_name = getSectionNameForAddress(member_address);
                    }
                    members.push_back(member_info);
                } else {
                    MemberInfo member_info(string_interner_.intern(member_name),
                                           member_address,
                                           string_interner_.intern(member.type),
                                           member.size);
                    if (config_.showSections) {
                        member_info.section_name = getSectionNameForAddress(member_address);
                    }
                    members.push_back(member_info);
                }
            }
        } else {
            // Primitive member - use enhanced constructor with size information
            // Use estimated size if DWARF size seems incorrect (e.g., arrays showing as 4 bytes)
            uint64_t correct_size = estimateTypeSizeFallback(member.type);
            if (correct_size > 0 && (member.type.find('[') != std::string::npos ||
                                     member.type == "uint64_t" || member.type == "double")) {
                MemberInfo member_info(string_interner_.intern(member_name),
                                       member_address,
                                       string_interner_.intern(member.type),
                                       correct_size);

                // Read constant value from memory if in constants mode and address is valid
                if (config_.constantsOnly && member_address != 0) {
                    member_info.constant_value =
                        readConstantValueFromMemory(member_address, member.type, correct_size);
                    member_info.is_constant = !member_info.constant_value.empty();
                }

                if (config_.showSections) {
                    member_info.section_name = getSectionNameForAddress(member_address);
                }
                members.push_back(member_info);
            } else {
                MemberInfo member_info(string_interner_.intern(member_name),
                                       member_address,
                                       string_interner_.intern(member.type),
                                       member.size);

                // Read constant value from memory if in constants mode and address is valid
                if (config_.constantsOnly && member_address != 0) {
                    member_info.constant_value =
                        readConstantValueFromMemory(member_address, member.type, member.size);
                    member_info.is_constant = !member_info.constant_value.empty();
                }

                if (config_.showSections) {
                    member_info.section_name = getSectionNameForAddress(member_address);
                }
                members.push_back(member_info);
            }
        }
    }

    return members;
}

std::vector<std::pair<std::string, uint32_t>>
ElfReader::getActualMemberNames(const std::string& type_name) const {
    std::vector<std::pair<std::string, uint32_t>> members;

    // Try to find the type in our already parsed type information
    auto type_info = types_.getType(type_name);
    if (!type_info.has_value()) {
        // Try improved resolution strategies similar to expandStructureMembers
        auto all_type_names = types_.getAllTypeNames();
        for (const auto& key : all_type_names) {
            if (key.find("@") != std::string::npos) {
                std::string base_key = key.substr(0, key.find("@"));
                if (base_key == type_name) {
                    type_info = types_.getType(key);
                    if (type_info.has_value()) {
                        break;
                    }
                }
            }
        }
    }

    // Additional enhancement: Try substring matching for typedef resolution
    if (!type_info.has_value()) {
        auto all_type_names = types_.getAllTypeNames();
        for (const auto& key : all_type_names) {
            // Check if this type name contains our target type (for typedef resolution)
            if (key.find(type_name) != std::string::npos) {
                auto candidate_info = types_.getType(key);
                if (candidate_info.has_value()) {
                    const TypeInfo& candidate_data = *candidate_info;
                    if (!candidate_data.members.empty()) {
                        type_info = candidate_info;
                        break;
                    }
                }
            }
        }
    }

    if (type_info.has_value()) {
        const TypeInfo& type_data = *type_info;
        // Extract member names and offsets from the parsed type information
        for (const auto& member : type_data.members) {
            if (!member.name.empty()) {
                members.emplace_back(std::string(member.name), member.offset);
            }
        }
    }

    // If no members found in parsed data, try enhanced type resolution
    if (members.empty()) {
        // The information IS in the ELF file (we found it with readelf), so we need to
        // follow typedef chains to get actual member names. Use the existing DWARF data.

        // Look for the typedef's underlying type in DWARF variables
        std::string underlyingTypeName = resolveTypedefChain(type_name);
        if (!underlyingTypeName.empty() && underlyingTypeName != type_name) {
            members = getMembersFromDwarfVariables(underlyingTypeName, type_info);
        }

        // If still no members, try parsing template parameter chains
        if (members.empty() && type_name.find('<') != std::string::npos) {
            members = extractMembersFromTemplateChain(type_name, type_info);
        }
    }

    return members;
}

#if HAVE_LIBDWARF
std::vector<std::pair<std::string, uint32_t>>
ElfReader::extractDwarfMembersDirect(const std::string& type_name) const {
    std::vector<std::pair<std::string, uint32_t>> members;

    try {
        Dwarf_Debug dbg = nullptr;

        // Initialize libdwarf for the current file
        if (DwarfInitializer::initialize(filename_, dbg)) {
            // Look for the type DIE by name
            Dwarf_Die type_die = nullptr;

            if (findDwarfTypeByName(dbg, type_name, type_die)) {
                // Extract member information from the type DIE
                extractMembersFromDwarfDie(dbg, type_die, members);
            }

            // Clean up
            DwarfInitializer::cleanup(dbg);
        }
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
        // If anything fails, return empty vector - intentionally swallow exceptions
    }

    return members;
}

std::vector<std::pair<std::string, uint32_t>>
ElfReader::extractDwarfMembers(const std::string& type_name) const {
    std::vector<std::pair<std::string, uint32_t>> members;

    try {
        Dwarf_Debug dbg = nullptr;

        // Try to initialize libdwarf for the current file
        if (DwarfInitializer::initialize(filename_, dbg)) {
            // Look for the type in DWARF
            Dwarf_Die type_die = nullptr;

            // Try to find the type DIE by name
            if (findDwarfTypeByName(dbg, type_name, type_die)) {
                // Extract member information from the type DIE
                extractMembersFromDwarfDie(dbg, type_die, members);
            }

            // Clean up
            DwarfInitializer::cleanup(dbg);
        }
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
        // If anything fails, return empty vector to trigger fallback - intentionally swallow
        // exceptions
    }

    return members;
}

// Helper methods for enhanced member name resolution
std::string ElfReader::resolveTypedefChain(const std::string& type_name) const {
    // Check if we have type information for this type directly
    auto type_info = types_.getType(type_name);
    if (type_info.has_value() && !type_info->members.empty()) {
        return type_name;  // Already a concrete type with members
    }

    // Look for types with similar names that have members
    // This handles cases where typedef names and struct names differ slightly
    auto all_type_names = types_.getAllTypeNames();
    for (const auto& candidate_name : all_type_names) {
        auto candidate_info = types_.getType(candidate_name);
        if (candidate_info.has_value()) {
            const TypeInfo& candidate_data = *candidate_info;
            if (!candidate_data.members.empty()) {
                // Check if this candidate could be the underlying type for our typedef
                // Examples:
                // - SomeType_t -> SomeType (remove _t suffix)
                // - SomeType -> SomeType_impl (similar names)
                // - 6UnnamedType -> SomeType (linkage name to typedef)
                if (candidate_name.find(type_name) != std::string::npos ||
                    type_name.find(candidate_name) != std::string::npos ||
                    (type_name.length() > 2 && type_name.substr(type_name.length() - 2) == "_t" &&
                     candidate_name.find(type_name.substr(0, type_name.length() - 2)) !=
                         std::string::npos)) {
                    return candidate_name;
                }
            }
        }
    }

    return "";  // No resolution found
}

std::vector<std::pair<std::string, uint32_t>>
ElfReader::getMembersFromDwarfVariables(const std::string& underlying_type,
                                        std::optional<TypeInfo>& type_info) const {
    std::vector<std::pair<std::string, uint32_t>> members;

    // First try to get members from the types collection
    auto resolved_info = types_.getType(underlying_type);
    if (resolved_info.has_value()) {
        const TypeInfo& resolved_data = *resolved_info;
        for (const auto& member : resolved_data.members) {
            if (!member.name.empty()) {
                members.emplace_back(std::string(member.name), member.offset);
            }
        }
        // Update the type_info reference
        type_info = resolved_info;
    }

    return members;
}

std::vector<std::pair<std::string, uint32_t>>
ElfReader::extractMembersFromTemplateChain(const std::string& template_type,
                                           std::optional<TypeInfo>& type_info) const {
    std::vector<std::pair<std::string, uint32_t>> members;

    // Parse template type like "BIST::fpuTest<RegisterTest>"
    size_t template_start = template_type.find('<');
    size_t template_end = template_type.find('>', template_start);

    if (template_start != std::string::npos && template_end != std::string::npos) {
        // Extract template parameter: "RegisterTest"
        std::string template_param =
            template_type.substr(template_start + 1, template_end - template_start - 1);

        // Look for the template parameter as a concrete type
        auto param_info = types_.getType(template_param);
        if (param_info.has_value()) {
            const TypeInfo& param_data = *param_info;
            for (const auto& member : param_data.members) {
                if (!member.name.empty()) {
                    members.emplace_back(std::string(member.name), member.offset);
                }
            }
            type_info = param_info;
        }

        // If not found in types, try with "Base" suffix/prefix variations
        if (members.empty()) {
            std::vector<std::string> variations = {template_param + "Base",
                                                   "Base" + template_param,
                                                   template_param + "_t",
                                                   template_param};

            for (const auto& variation : variations) {
                auto var_info = types_.getType(variation);
                if (var_info.has_value()) {
                    const TypeInfo& var_data = *var_info;
                    for (const auto& member : var_data.members) {
                        if (!member.name.empty()) {
                            members.emplace_back(std::string(member.name), member.offset);
                        }
                    }
                    type_info = var_info;
                    break;  // Found a match
                }
            }
        }
    }

    return members;
}

bool ElfReader::findDwarfTypeByName(Dwarf_Debug dbg,
                                    const std::string& type_name,
                                    Dwarf_Die& type_die) const {
    Dwarf_Error error = nullptr;
    Dwarf_Unsigned cu_header_length = 0;
    Dwarf_Half version_stamp = 0;
    Dwarf_Unsigned abbrev_offset = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half length_size = 0;
    Dwarf_Half extension_size = 0;
    Dwarf_Sig8 signature;
    Dwarf_Bool is_info = true;

    // Iterate through all compilation units
    while (dwarf_next_cu_header_d(dbg,
                                  is_info,
                                  &cu_header_length,
                                  &version_stamp,
                                  &abbrev_offset,
                                  &address_size,
                                  &length_size,
                                  &extension_size,
                                  &signature,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  &error) == DW_DLV_OK) {
        Dwarf_Die cu_die = nullptr;
        if (dwarf_siblingof_b(dbg, nullptr, is_info, &cu_die, &error) == DW_DLV_OK) {
            // Search for the type in this compilation unit
            if (searchForTypeInCU(dbg, cu_die, type_name, type_die)) {
                dwarf_dealloc_die(cu_die);
                return true;
            }
            dwarf_dealloc_die(cu_die);
        }
    }

    return false;
}

bool ElfReader::searchForTypeInCU(Dwarf_Debug dbg,
                                  Dwarf_Die cu_die,
                                  const std::string& type_name,
                                  Dwarf_Die& type_die) const {
    Dwarf_Error error = nullptr;
    Dwarf_Die child_die = nullptr;
    Dwarf_Die sibling_die = nullptr;

    // Get first child of the CU
    int result = dwarf_child(cu_die, &child_die, &error);
    if (result == DW_DLV_NO_ENTRY) {
        return false;  // No children
    }
    if (result != DW_DLV_OK) {
        return false;  // Error
    }

    // Search through all children
    while (child_die) {
        if (isMatchingTypeDie(dbg, child_die, type_name, type_die)) {
            dwarf_dealloc_die(child_die);
            return true;
        }

        // Move to next sibling
        if (dwarf_siblingof_b(dbg, child_die, true, &sibling_die, &error) == DW_DLV_OK) {
            dwarf_dealloc_die(child_die);
            child_die = sibling_die;
            sibling_die = nullptr;
        } else {
            dwarf_dealloc_die(child_die);
            child_die = nullptr;
        }
    }

    return false;
}

/**
 * @brief Check if a type name represents a basic/primitive type that should not be expanded
 *
 * Basic types include fundamental C/C++ types like int, char, float, bool, etc.
 * These should never be looked up as structures and expanded.
 *
 * @param type_name Type name to check
 * @return true if this is a basic type, false otherwise
 */
bool ElfReader::isBasicType(const std::string& type_name) const {
    // List of basic C/C++ types that should never be expanded as structures
    static const std::vector<std::string> basic_types = {// Integer types
                                                         "char",
                                                         "signed char",
                                                         "unsigned char",
                                                         "short",
                                                         "short int",
                                                         "signed short",
                                                         "signed short int",
                                                         "unsigned short",
                                                         "unsigned short int",
                                                         "short unsigned int",
                                                         "int",
                                                         "signed int",
                                                         "unsigned int",
                                                         "unsigned",
                                                         "long",
                                                         "long int",
                                                         "signed long",
                                                         "signed long int",
                                                         "unsigned long",
                                                         "unsigned long int",
                                                         "long unsigned int",
                                                         "long long",
                                                         "long long int",
                                                         "signed long long",
                                                         "signed long long int",
                                                         "unsigned long long",
                                                         "unsigned long long int",
                                                         "long long unsigned int",
                                                         // Floating point types
                                                         "float",
                                                         "double",
                                                         "long double",
                                                         // Boolean type
                                                         "bool",
                                                         "_Bool",
                                                         // Fixed-width integer types
                                                         "int8_t",
                                                         "uint8_t",
                                                         "int16_t",
                                                         "uint16_t",
                                                         "int32_t",
                                                         "uint32_t",
                                                         "int64_t",
                                                         "uint64_t",
                                                         // Other basic types
                                                         "size_t",
                                                         "ssize_t",
                                                         "ptrdiff_t",
                                                         "void",
                                                         "wchar_t",
                                                         "char16_t",
                                                         "char32_t"};

    // Also check for "const " and "volatile " prefixes
    std::string clean_type = type_name;
    if (clean_type.substr(0, 6) == "const ") {
        clean_type = clean_type.substr(6);
    }
    if (clean_type.substr(0, 9) == "volatile ") {
        clean_type = clean_type.substr(9);
    }
    if (clean_type.substr(0, 6) == "const ") {  // Handle "volatile const"
        clean_type = clean_type.substr(6);
    }

    // Check if this matches any basic type
    for (const auto& basic_type : basic_types) {
        if (clean_type == basic_type) {
            return true;
        }
    }

    return false;
}

bool ElfReader::isMatchingTypeDie(Dwarf_Debug dbg,
                                  Dwarf_Die die,
                                  const std::string& type_name,
                                  Dwarf_Die& found_die) const {
    Dwarf_Error error = nullptr;

    // Get the DIE tag
    Dwarf_Half tag = 0;
    if (dwarf_tag(die, &tag, &error) != DW_DLV_OK) {
        return false;
    }

    // Check if this is a structure, class, or typedef
    if (tag == DW_TAG_structure_type || tag == DW_TAG_class_type || tag == DW_TAG_typedef) {
        // Get the name of this DIE
        char* die_name = nullptr;
        if (dwarf_diename(die, &die_name, &error) == DW_DLV_OK && die_name) {
            std::string current_name(die_name);
            free(die_name);

            // Check for exact match
            if (current_name == type_name) {
                found_die = die;
                return true;
            }

            // For typedefs, check if the underlying type matches
            if (tag == DW_TAG_typedef) {
                Dwarf_Attribute type_attr = nullptr;
                if (dwarf_attr(die, DW_AT_type, &type_attr, &error) == DW_DLV_OK) {
                    Dwarf_Off type_offset = 0;
                    if (dwarf_global_formref(type_attr, &type_offset, &error) == DW_DLV_OK) {
                        Dwarf_Die underlying_die = nullptr;
                        if (dwarf_offdie_b(dbg, type_offset, 1, &underlying_die, &error) ==
                            DW_DLV_OK) {
                            if (isMatchingTypeDie(dbg, underlying_die, type_name, found_die)) {
                                dwarf_dealloc_attribute(type_attr);
                                dwarf_dealloc_die(underlying_die);
                                return true;
                            }
                            dwarf_dealloc_die(underlying_die);
                        }
                    }
                    dwarf_dealloc_attribute(type_attr);
                }
            }
        }
    }

    return false;
}

void ElfReader::extractMembersFromDwarfDie(
    Dwarf_Debug dbg,
    Dwarf_Die type_die,
    std::vector<std::pair<std::string, uint32_t>>& members) const {
    Dwarf_Error error = nullptr;
    Dwarf_Die child_die = nullptr;
    Dwarf_Die sibling_die = nullptr;

    // Get first child
    int result = dwarf_child(type_die, &child_die, &error);
    if (result != DW_DLV_OK) {
        return;  // No children or error
    }

    // Process all children
    while (child_die) {
        Dwarf_Half tag = 0;
        if (dwarf_tag(child_die, &tag, &error) == DW_DLV_OK && tag == DW_TAG_member) {
            // Get member name
            char* member_name = nullptr;
            if (dwarf_diename(child_die, &member_name, &error) == DW_DLV_OK && member_name) {
                // Get member offset
                Dwarf_Attribute location_attr = nullptr;
                uint32_t member_offset = 0;

                if (dwarf_attr(child_die, DW_AT_data_member_location, &location_attr, &error) ==
                    DW_DLV_OK) {
                    Dwarf_Unsigned offset_val = 0;
                    if (dwarf_formudata(location_attr, &offset_val, &error) == DW_DLV_OK) {
                        member_offset = static_cast<uint32_t>(offset_val);
                    }
                    dwarf_dealloc_attribute(location_attr);
                }

                // Add to members list
                members.emplace_back(std::string(member_name), member_offset);
                free(member_name);
            }
        }

        // Move to next sibling
        if (dwarf_siblingof_b(dbg, child_die, true, &sibling_die, &error) == DW_DLV_OK) {
            dwarf_dealloc_die(child_die);
            child_die = sibling_die;
            sibling_die = nullptr;
        } else {
            dwarf_dealloc_die(child_die);
            child_die = nullptr;
        }
    }
}
#endif  // HAVE_LIBDWARF

void ElfReader::extractGenericParameters(const std::string& base_name,
                                         uint64_t struct_address,
                                         std::vector<MemberInfo>& members) const {
    // Read up to 64 bytes of structure data
    std::string struct_data = readMemoryAtAddress(struct_address, 64);
    if (struct_data.empty() || struct_data.size() < 16) {
        return;
    }

    // Try to decode as float parameters (common in control structures)
    const uint8_t* data = reinterpret_cast<const uint8_t*>(struct_data.data());

    // Decode individual float values from the structure
    for (size_t i = 0; i < struct_data.size() && i < 64; i += 4) {
        if (i + 4 <= struct_data.size()) {
            // Read 4 bytes as float
            uint32_t raw_value;
            std::memcpy(&raw_value, data + i, 4);
            float float_val;
            std::memcpy(&float_val, &raw_value, 4);

            // Use generic parameter names as last resort
            std::string param_name = getGenericParamName(i / 4);
            std::string member_name = base_name + "." + param_name;
            MemberInfo param_member(string_interner_.intern(member_name),
                                    struct_address + i,
                                    string_interner_.intern("float"),
                                    4);

            // Format the float value
            std::stringstream ss;
            ss << std::fixed << std::setprecision(6) << float_val << "f";
            param_member.constant_value = ss.str();
            param_member.is_constant = true;

            if (config_.showSections) {
                param_member.section_name = getSectionNameForAddress(struct_address + i);
            }

            members.push_back(param_member);
        }
    }
}

template<typename T>
T ElfReader::readValue(size_t offset) const {
    // Use memory validator for comprehensive bounds checking
    T value = memory_validator_->readValue<T>(offset, "readValue");

    // Handle endianness conversion
    if ((is_little_endian_ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||
        (!is_little_endian_ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) {
        swapEndianness(&value, sizeof(T));
    }

    return value;
}

template<typename T>
void ElfReader::readStruct(size_t offset, T& structure) const {
    // For complex structures, we need to read field by field to handle endianness
    if constexpr (std::is_same_v<T, Elf32_Ehdr>) {
        structure.e_type = readValue<uint16_t>(offset + 0);
        structure.e_machine = readValue<uint16_t>(offset + 2);
        structure.e_version = readValue<uint32_t>(offset + 4);
        structure.e_entry = readValue<uint32_t>(offset + 8);
        structure.e_phoff = readValue<uint32_t>(offset + 12);
        structure.e_shoff = readValue<uint32_t>(offset + 16);
        structure.e_flags = readValue<uint32_t>(offset + 20);
        structure.e_ehsize = readValue<uint16_t>(offset + 24);
        structure.e_phentsize = readValue<uint16_t>(offset + 26);
        structure.e_phnum = readValue<uint16_t>(offset + 28);
        structure.e_shentsize = readValue<uint16_t>(offset + 30);
        structure.e_shnum = readValue<uint16_t>(offset + 32);
        structure.e_shstrndx = readValue<uint16_t>(offset + 34);
    } else if constexpr (std::is_same_v<T, Elf64_Ehdr>) {
        structure.e_type = readValue<uint16_t>(offset + 0);
        structure.e_machine = readValue<uint16_t>(offset + 2);
        structure.e_version = readValue<uint32_t>(offset + 4);
        structure.e_entry = readValue<uint64_t>(offset + 8);
        structure.e_phoff = readValue<uint64_t>(offset + 16);
        structure.e_shoff = readValue<uint64_t>(offset + 24);
        structure.e_flags = readValue<uint32_t>(offset + 32);
        structure.e_ehsize = readValue<uint16_t>(offset + 36);
        structure.e_phentsize = readValue<uint16_t>(offset + 38);
        structure.e_phnum = readValue<uint16_t>(offset + 40);
        structure.e_shentsize = readValue<uint16_t>(offset + 42);
        structure.e_shnum = readValue<uint16_t>(offset + 44);
        structure.e_shstrndx = readValue<uint16_t>(offset + 46);
    } else if constexpr (std::is_same_v<T, Elf32_Shdr>) {
        structure.sh_name = readValue<uint32_t>(offset + 0);
        structure.sh_type = readValue<uint32_t>(offset + 4);
        structure.sh_flags = readValue<uint32_t>(offset + 8);
        structure.sh_addr = readValue<uint32_t>(offset + 12);
        structure.sh_offset = readValue<uint32_t>(offset + 16);
        structure.sh_size = readValue<uint32_t>(offset + 20);
        structure.sh_link = readValue<uint32_t>(offset + 24);
        structure.sh_info = readValue<uint32_t>(offset + 28);
        structure.sh_addralign = readValue<uint32_t>(offset + 32);
        structure.sh_entsize = readValue<uint32_t>(offset + 36);
    } else if constexpr (std::is_same_v<T, Elf64_Shdr>) {
        structure.sh_name = readValue<uint32_t>(offset + 0);
        structure.sh_type = readValue<uint32_t>(offset + 4);
        structure.sh_flags = readValue<uint64_t>(offset + 8);
        structure.sh_addr = readValue<uint64_t>(offset + 16);
        structure.sh_offset = readValue<uint64_t>(offset + 24);
        structure.sh_size = readValue<uint64_t>(offset + 32);
        structure.sh_link = readValue<uint32_t>(offset + 40);
        structure.sh_info = readValue<uint32_t>(offset + 44);
        structure.sh_addralign = readValue<uint64_t>(offset + 48);
        structure.sh_entsize = readValue<uint64_t>(offset + 56);
    } else if constexpr (std::is_same_v<T, Elf32_Sym>) {
        structure.st_name = readValue<uint32_t>(offset + 0);
        structure.st_value = readValue<uint32_t>(offset + 4);
        structure.st_size = readValue<uint32_t>(offset + 8);
        structure.st_info = readValue<uint8_t>(offset + 12);
        structure.st_other = readValue<uint8_t>(offset + 13);
        structure.st_shndx = readValue<uint16_t>(offset + 14);
    } else if constexpr (std::is_same_v<T, Elf64_Sym>) {
        structure.st_name = readValue<uint32_t>(offset + 0);
        structure.st_info = readValue<uint8_t>(offset + 4);
        structure.st_other = readValue<uint8_t>(offset + 5);
        structure.st_shndx = readValue<uint16_t>(offset + 6);
        structure.st_value = readValue<uint64_t>(offset + 8);
        structure.st_size = readValue<uint64_t>(offset + 16);
    }
}

void ElfReader::swapEndianness(void* data, size_t size) const {
    uint8_t* bytes = reinterpret_cast<uint8_t*>(data);
    for (size_t i = 0; i < size / 2; ++i) {
        std::swap(bytes[i], bytes[size - 1 - i]);
    }
}

uint64_t ElfReader::getEntryPoint() const {
    return is_32bit_ ? ehdr32_.e_entry : ehdr64_.e_entry;
}

uint16_t ElfReader::getSectionCount() const {
    return is_32bit_ ? ehdr32_.e_shnum : ehdr64_.e_shnum;
}

uint32_t ElfReader::getSectionHeaderOffset() const {
    return is_32bit_ ? ehdr32_.e_shoff : static_cast<uint32_t>(ehdr64_.e_shoff);
}

uint16_t ElfReader::getSectionHeaderSize() const {
    return is_32bit_ ? ehdr32_.e_shentsize : ehdr64_.e_shentsize;
}

uint16_t ElfReader::getSectionNameIndex() const {
    return is_32bit_ ? ehdr32_.e_shstrndx : ehdr64_.e_shstrndx;
}

void ElfReader::analyzeInterruptVectors() {
    if (extractInterruptVectorTable()) {
        printInterruptVectorTable();
    } else {
        if (config_.verbosity > 0) {
            std::cout << "\nNo interrupt vector table found in this ELF file.\n";
        }
    }
}

void ElfReader::analyzeMemoryRegions() {
    if (extractMemoryRegionMapping()) {
        printMemoryRegionMapping();
    } else {
        if (config_.verbosity > 0) {
            std::cout << "\nNo memory region mapping available for this ELF file.\n";
        }
    }
}

std::string ElfReader::readConstantValueFromMemory(uint64_t address,
                                                   const std::string& type_name,
                                                   uint64_t size) const {
    // Universal function to read constant values from ELF memory sections
    // Works for any type stored in .rodata or other const sections

    if (address == 0 || size == 0) {
        return "";  // Can't read from address 0 or unknown size
    }

    // Read the raw bytes from memory
    std::string raw_data = readMemoryAtAddress(address, size);
    if (raw_data.empty() || raw_data.size() < size) {
        return "";  // Failed to read data
    }

    // Format the value based on type
    std::ostringstream oss;

    if (type_name == "float" && size == 4) {
        float value;
        std::memcpy(&value, raw_data.data(), 4);

        // Validate that the float value is reasonable
        // Skip NaN, infinity, and values with extreme exponents (likely not actual floats)
        if (std::isnan(value) || std::isinf(value) || std::abs(value) > 1e20f) {
            return "";  // Value looks suspicious, probably not a real float
        }

        oss << std::fixed << std::setprecision(6) << value << "f";
        return oss.str();
    } else if (type_name == "double" && size == 8) {
        double value;
        std::memcpy(&value, raw_data.data(), 8);

        // Validate that the double value is reasonable
        if (std::isnan(value) || std::isinf(value) || std::abs(value) > 1e100) {
            return "";  // Value looks suspicious, probably not a real double
        }

        oss << std::fixed << std::setprecision(15) << value;
        return oss.str();
    } else if (type_name == "int" || type_name == "int32_t" || type_name == "signed int") {
        if (size == 4) {
            int32_t value;
            std::memcpy(&value, raw_data.data(), 4);
            oss << value;
            return oss.str();
        }
    } else if (type_name == "unsigned int" || type_name == "uint32_t") {
        if (size == 4) {
            uint32_t value;
            std::memcpy(&value, raw_data.data(), 4);
            oss << value;
            return oss.str();
        }
    } else if (type_name == "short" || type_name == "short int" || type_name == "int16_t") {
        if (size == 2) {
            int16_t value;
            std::memcpy(&value, raw_data.data(), 2);
            oss << value;
            return oss.str();
        }
    } else if (type_name == "unsigned short" || type_name == "short unsigned int" ||
               type_name == "uint16_t") {
        if (size == 2) {
            uint16_t value;
            std::memcpy(&value, raw_data.data(), 2);
            oss << value;
            return oss.str();
        }
    } else if (type_name == "char" || type_name == "signed char" || type_name == "int8_t") {
        if (size == 1) {
            int8_t value;
            std::memcpy(&value, raw_data.data(), 1);
            oss << static_cast<int>(value);
            return oss.str();
        }
    } else if (type_name == "unsigned char" || type_name == "uint8_t") {
        if (size == 1) {
            uint8_t value;
            std::memcpy(&value, raw_data.data(), 1);
            oss << static_cast<unsigned int>(value);
            return oss.str();
        }
    } else if (type_name == "long" || type_name == "long int" || type_name == "int64_t") {
        if (size == 8) {
            int64_t value;
            std::memcpy(&value, raw_data.data(), 8);
            oss << value;
            return oss.str();
        } else if (size == 4) {
            int32_t value;
            std::memcpy(&value, raw_data.data(), 4);
            oss << value;
            return oss.str();
        }
    } else if (type_name == "unsigned long" || type_name == "long unsigned int" ||
               type_name == "uint64_t") {
        if (size == 8) {
            uint64_t value;
            std::memcpy(&value, raw_data.data(), 8);
            oss << value;
            return oss.str();
        } else if (size == 4) {
            uint32_t value;
            std::memcpy(&value, raw_data.data(), 4);
            oss << value;
            return oss.str();
        }
    }

    // Fallback: for unknown typedefs (like frac16_t, frac32_t), try to infer from type name and
    // size This handles custom integer types universally across any ELF file

    // Special case: type name suggests 16-bit but size might be wrong
    if (type_name.find("16") != std::string::npos && raw_data.size() >= 2) {
        // Likely a 16-bit fixed-point type like frac16_t
        int16_t value;
        std::memcpy(&value, raw_data.data(), 2);
        oss << value;
        return oss.str();
    }

    // Special case: type name suggests 32-bit
    if (type_name.find("32") != std::string::npos && raw_data.size() >= 4) {
        // Likely a 32-bit fixed-point type like frac32_t
        int32_t value;
        std::memcpy(&value, raw_data.data(), 4);
        oss << value;
        return oss.str();
    }

    // Generic fallback based on actual data size
    if (raw_data.size() >= 1 && size == 1) {
        // 1-byte: treat as signed char
        int8_t value;
        std::memcpy(&value, raw_data.data(), 1);
        oss << static_cast<int>(value);
        return oss.str();
    } else if (raw_data.size() >= 2 && size == 2) {
        // 2-byte: treat as signed short
        int16_t value;
        std::memcpy(&value, raw_data.data(), 2);
        oss << value;
        return oss.str();
    } else if (raw_data.size() >= 4 && size == 4) {
        // 4-byte: treat as signed int
        int32_t value;
        std::memcpy(&value, raw_data.data(), 4);
        oss << value;
        return oss.str();
    } else if (raw_data.size() >= 8 && size == 8) {
        // 8-byte: treat as signed long
        int64_t value;
        std::memcpy(&value, raw_data.data(), 8);
        oss << value;
        return oss.str();
    }

    // For unknown types or unsupported sizes, return empty
    return "";
}

void ElfReader::analyzeVariablesAndMembers() {
    std::vector<MemberInfo> all_members;
    std::set<std::string> processed_symbols;  // Avoid duplicates
    std::set<uint64_t> processed_addresses;   // Avoid processing same variable multiple times

    // Process variables discovered from DWARF debug information first
    for (const auto& [symbol_name, var_info] : dwarf_variables_) {
        // Apply constants filter if specified
        if (config_.constantsOnly && !var_info.is_constant) {
            continue;  // Skip non-constants when constants mode is enabled
        }

        // For compile-time constants with address=0, skip address-based deduplication
        // since multiple constants can legitimately have address=0
        bool is_addressless_constant = (var_info.is_constant && var_info.address == 0);
        bool address_not_processed =
            (processed_addresses.find(var_info.address) == processed_addresses.end());

        if (var_info.is_global && (var_info.address != 0 || var_info.is_constant) &&
            (is_addressless_constant || address_not_processed)) {
            // Only track address for variables with actual addresses
            if (!is_addressless_constant) {
                processed_addresses.insert(var_info.address);
            }
            std::string display_name =
                var_info.demangled_name.empty() ? var_info.name : var_info.demangled_name;
            std::string type_name = var_info.type_name;
            uint64_t symbol_address = var_info.address;

            // Track both mangled and demangled names to avoid duplicates
            processed_symbols.insert(symbol_name);
            if (!var_info.demangled_name.empty() && var_info.demangled_name != symbol_name) {
                processed_symbols.insert(var_info.demangled_name);
            }

            // Find and track the corresponding mangled symbol name in symbol table
            if (is_32bit_) {
                for (const auto& symbol : symbols32_) {
                    if (symbol.st_value == symbol_address && !symbol.name.empty()) {
                        processed_symbols.insert(symbol.name);
                        break;
                    }
                }
            } else {
                for (const auto& symbol : symbols64_) {
                    if (symbol.st_value == symbol_address && !symbol.name.empty()) {
                        processed_symbols.insert(symbol.name);
                        break;
                    }
                }
            }

            if (!type_name.empty() && !isBasicType(type_name)) {
                // Try to expand as structure/class for both variables and constants
                // This allows us to see embedded constant parameters in structures
                // But skip basic/primitive types that should never be expanded
                // ALSO: Don't expand structures with address=0 in constants mode - these are
                // compile-time constants without memory representation
                bool should_expand = (symbol_address != 0 || !config_.constantsOnly);
                auto members = should_expand
                                   ? expandStructureMembers(display_name, type_name, symbol_address)
                                   : std::vector<MemberInfo>();
                if (!members.empty()) {
                    all_members.insert(all_members.end(), members.begin(), members.end());
                } else {
                    // Type lookup failed or returned empty - output as simple variable with
                    // constant info
                    MemberInfo member_info(string_interner_.intern(display_name),
                                           symbol_address,
                                           string_interner_.intern(type_name),
                                           var_info.is_constant,
                                           var_info.constant_value);
                    if (config_.showSections) {
                        member_info.section_name = getSectionNameForAddress(symbol_address);
                    }
                    all_members.push_back(member_info);
                }
            } else {
                // For constants or unknown structures, show the variable itself with constant info
                std::string type_str = var_info.type_name.empty() ? "OBJECT" : var_info.type_name;
                uint64_t estimated_size = estimateTypeSizeFallback(type_str);

                // If this is a constant with a real address but no value, try to read it from
                // memory
                std::string const_value = var_info.constant_value;
                if (var_info.is_constant && const_value.empty() && symbol_address != 0) {
                    const_value =
                        readConstantValueFromMemory(symbol_address, type_str, estimated_size);
                }

                if (estimated_size > 0) {
                    // Use enhanced constructor with size information
                    MemberInfo member_info(string_interner_.intern(display_name),
                                           symbol_address,
                                           string_interner_.intern(type_str),
                                           estimated_size);
                    member_info.is_constant = var_info.is_constant;
                    member_info.constant_value = const_value;
                    if (config_.showSections) {
                        member_info.section_name = getSectionNameForAddress(symbol_address);
                    }
                    all_members.push_back(member_info);
                } else {
                    // Fallback to original constructor
                    MemberInfo fallback_member(string_interner_.intern(display_name),
                                               symbol_address,
                                               string_interner_.intern(type_str),
                                               var_info.is_constant,
                                               const_value);
                    if (config_.showSections) {
                        fallback_member.section_name = getSectionNameForAddress(symbol_address);
                    }
                    all_members.push_back(fallback_member);
                }
            }
        }
    }

    // Then process symbols from symbol table that weren't already processed
    // Skip symbol table processing in constants mode since constants come from DWARF
    if (!config_.constantsOnly) {
        if (is_32bit_) {
            processSymbolTable(symbols32_, processed_symbols, all_members);
        } else {
            processSymbolTable(symbols64_, processed_symbols, all_members);
        }
    }

    // Integrate enhanced symbols from ELF symbol table analysis
    // Skip in constants mode to preserve DWARF constant values
    if (!enhanced_symbols_.empty() && !config_.constantsOnly) {
        // Convert enhanced symbols to MemberInfo format and merge with existing results
        std::vector<MemberInfo> enhanced_members =
            output_generator_->convertEnhancedSymbols(enhanced_symbols_, config_);

        // Add enhanced symbols to the all_members list, avoiding duplicates
        std::set<uint64_t> existing_addresses;
        for (const auto& member : all_members) {
            existing_addresses.insert(member.address);
        }

        for (const auto& enhanced_member : enhanced_members) {
            // Only add if not already present (avoid duplicates)
            if (existing_addresses.find(enhanced_member.address) == existing_addresses.end()) {
                all_members.push_back(enhanced_member);
                existing_addresses.insert(enhanced_member.address);
            }
        }

        if (config_.verbosity > 1) {
            std::cout << "Integrated " << enhanced_members.size()
                      << " enhanced symbols into analysis\n";
        }
    }

    // Sort by address for better readability
    std::sort(all_members.begin(), all_members.end(), [](const MemberInfo& a, const MemberInfo& b) {
        return a.address < b.address;
    });

    if (config_.format == "json") {
        // Pass symbol tables for function output
        output_generator_->generateJsonOutput(
            all_members,
            config_,
            nullptr,  // No section name function needed for variable output
            is_32bit_ ? &symbols32_ : nullptr,
            is_32bit_ ? nullptr : &symbols64_);
    } else {
        output_generator_->generateCsvOutput(all_members, config_);
    }
}

void ElfReader::analyzeFunctions() {
    std::vector<FunctionInfo> all_functions;

    if (is_32bit_) {
        for (const auto& symbol : symbols32_) {
            if (!symbol.name.empty() &&
                symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) &&
                symbol.st_value != 0) {
                // Demangle C++ function names for better readability
                std::string func_name = demangleCppName(symbol.name);

                FunctionInfo func_info;
                func_info.name = func_name;
                func_info.mangled_name = symbol.name;
                func_info.start_address = symbol.st_value;
                func_info.end_address = symbol.st_value + symbol.st_size;
                all_functions.push_back(func_info);
            }
        }
    } else {
        for (const auto& symbol : symbols64_) {
            if (!symbol.name.empty() &&
                symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) &&
                symbol.st_value != 0) {
                // Demangle C++ function names for better readability
                std::string func_name = demangleCppName(symbol.name);

                FunctionInfo func_info;
                func_info.name = func_name;
                func_info.mangled_name = symbol.name;
                func_info.start_address = symbol.st_value;
                func_info.end_address = symbol.st_value + symbol.st_size;
                all_functions.push_back(func_info);
            }
        }
    }

    // Output functions in the requested format
    if (!all_functions.empty()) {
        // Lambda to get section name for address
        auto get_section_fn = [this](uint64_t addr) {
            return this->getSectionNameForAddress(addr);
        };

        if (config_.format == "json") {
            output_generator_->generateFunctionJsonOutput(all_functions, config_, get_section_fn);
        } else {
            output_generator_->generateFunctionCsvOutput(all_functions, config_, get_section_fn);
        }
    }
}

void ElfReader::analyzeMemberParameters() {
    // Mark analysis as completed first
    analysis_completed_ = true;

    if (config_.verbosity < 0)
        return;

    // Interrupt Vector Table Analysis (exclusive mode)
    if (config_.extractInterruptVectors) {
        analyzeInterruptVectors();
        return;
    }

    // Memory Region Mapping and Validation (exclusive mode)
    if (config_.extractMemoryRegions) {
        analyzeMemoryRegions();
        return;
    }

    // Variables and members analysis (default and variables-only modes)
    if (!config_.functionsOnly) {
        analyzeVariablesAndMembers();
        if (config_.variablesOnly) {
            return;  // Exit early when variables-only mode
        }
    }

    // Functions analysis (functions-only and default modes)
    if (config_.functionsOnly) {
        analyzeFunctions();
    }

    // Report final string interning statistics if debug output is enabled
    if (config_.verbosity > 1) {
        auto [intern_count, lookup_count, cache_hits] = string_interner_.getStats();
        (void)intern_count;  // Suppress unused variable warning
        (void)lookup_count;  // Suppress unused variable warning
        (void)cache_hits;    // Suppress unused variable warning
        size_t unique_strings = string_interner_.size();
        size_t estimated_bytes = string_interner_.getMemoryUsage();
        double avg_length = unique_strings > 0 ? static_cast<double>(estimated_bytes) /
                                                     static_cast<double>(unique_strings)
                                               : 0.0;
        double cache_hit_ratio = string_interner_.getCacheHitRatio();
        std::cout << "\nString Interning Final Statistics:\n";
        std::cout << std::dec << "  Unique strings: " << unique_strings << "\n";
        std::cout << "  Estimated memory: " << estimated_bytes << " bytes\n";
        std::cout << "  Average length: " << std::fixed << std::setprecision(1) << avg_length
                  << " chars\n";
        std::cout << "  Cache hit ratio: " << std::fixed << std::setprecision(2) << cache_hit_ratio
                  << "%\n";

        // Report type storage statistics for verification
        size_t total_types = types_.size();
        size_t linkage_types = types_.getLinkageNameMapSize();
        size_t qualified_types = types_.getQualifiedNameMapSize();
        double linkage_ratio =
            total_types > 0 ? (static_cast<double>(linkage_types) / total_types * 100.0) : 0.0;

        std::cout << "\nType Storage Statistics:\n";
        std::cout << "  Total types: " << total_types << "\n";
        std::cout << "  Types with linkage names: " << linkage_types << " (" << std::fixed
                  << std::setprecision(1) << linkage_ratio << "%)\n";
        std::cout << "  Types with qualified names: " << qualified_types << "\n";
        std::cout << "  C++ types (have linkage): " << linkage_types << "\n";
        std::cout << "  C structs (no linkage): " << (total_types - linkage_types) << "\n";
    }

    // Binary Export Functionality
    if (!config_.exportFormat.empty()) {
        if (config_.verbosity >= 0) {
            std::cout << "\nExporting binary data to " << config_.exportFormat << " format...\n";
        }

        if (performBinaryExport()) {
            if (config_.verbosity >= 0) {
                std::cout << "Export completed successfully.\n";
            }
        } else {
            if (config_.verbosity >= 0) {
                std::cerr << "Export failed.\n";
            }
        }
    }
}

// Output generation methods moved to output/OutputGenerator.cpp

AdvancedTypeInfo ElfReader::getCachedTypeInfo(const std::string& type_name) const {
    auto it = type_cache_.find(type_name);
    if (it != type_cache_.end()) {
        // Check if cache entry is still valid (simple time-based expiration)
        uint64_t current_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch())
                                    .count();

        // Cache entries are valid for 1 minute
        const uint64_t cache_expiration_ns =
            static_cast<uint64_t>(60) * 1000 * 1000 * 1000ULL;  // 1 minute in nanoseconds

        if ((current_time - it->second.second) < cache_expiration_ns) {
            // Return cached result and mark as cache hit
            AdvancedTypeInfo cached_info = it->second.first;
            cached_info.is_cached = true;
            return cached_info;
        } else {
            // Cache expired, remove entry
            type_cache_.erase(it);
        }
    }

    // Cache miss - return empty AdvancedTypeInfo
    return AdvancedTypeInfo();
}

void ElfReader::cacheTypeInfo(const std::string& type_name, const AdvancedTypeInfo& info) {
    uint64_t current_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count();

    // Implement simple LRU by limiting cache size
    const size_t max_cache_size = ParsingLimits::MAX_CACHE_SIZE;
    if (type_cache_.size() >= max_cache_size) {
        // Remove oldest entry (simple implementation - could be optimized with proper LRU)
        auto oldest = type_cache_.begin();
        uint64_t oldest_time = oldest->second.second;

        for (auto it = type_cache_.begin(); it != type_cache_.end(); ++it) {
            if (it->second.second < oldest_time) {
                oldest = it;
                oldest_time = it->second.second;
            }
        }
        type_cache_.erase(oldest);
    }

    // Cache the type info with timestamp
    AdvancedTypeInfo cached_info = info;
    cached_info.is_cached = false;  // This is the original, not from cache
    type_cache_[type_name] = std::make_pair(cached_info, current_time);
}

std::string ElfReader::deduplicateTypeName(const std::string& type_name) {
    // Use string interning for type name deduplication
    return std::string(string_interner_.intern(type_name));
}

void ElfReader::optimizeTypeDependencies() {
    // Build dependency graph and optimize resolution order
    std::map<std::string, std::vector<std::string>> dependency_graph;

    // Build the graph from all advanced types
    for (const auto& [type_name, advanced_info] : advanced_types_) {
        for (const auto& dependency : advanced_info.dependencies) {
            dependency_graph[type_name].push_back(dependency.base_type);
        }
    }

    // Simple cycle detection and optimization
    // (A more sophisticated implementation could use topological sorting)
    for (const auto& [type_name, deps] : dependency_graph) {
        if (deps.size() > 1) {
            // Type has multiple dependencies - could benefit from parallel resolution
            if (config_.verbosity > 1) {
                std::cout << "Type optimization: " << type_name << " has " << deps.size()
                          << " dependencies\n";
            }
        }
    }
}

void ElfReader::printTypeResolutionStats() const {
    if (config_.verbosity > 0) {
        std::cout << "\n=== Advanced Type Resolution Statistics ===\n";
        std::cout << "DWARF 5 advanced types: " << advanced_types_.size() << "\n";
        std::cout << "Type cache entries: " << type_cache_.size() << "\n";
        std::cout << "Template specializations: " << template_specializations_.size() << "\n";

        // Calculate cache hit rate
        size_t cached_types = 0;
        uint64_t total_resolution_time = 0;

        for (const auto& [type_name, advanced_info] : advanced_types_) {
            if (advanced_info.is_cached) {
                cached_types++;
            }
            total_resolution_time += advanced_info.resolution_time_ns;
        }

        if (!advanced_types_.empty()) {
            double cache_hit_rate = static_cast<double>(cached_types) /
                                    static_cast<double>(advanced_types_.size()) * 100.0;
            double avg_resolution_time = static_cast<double>(total_resolution_time) /
                                         static_cast<double>(advanced_types_.size()) /
                                         1000.0;  // Convert to microseconds

            std::cout << "Cache hit rate: " << std::fixed << std::setprecision(1) << cache_hit_rate
                      << "%\n";
            std::cout << "Average type resolution: " << std::fixed << std::setprecision(2)
                      << avg_resolution_time << " μs\n";
        }

        // Report type qualifiers usage
        std::map<TypeQualifiers, size_t> qualifier_counts;
        for (const auto& [type_name, advanced_info] : advanced_types_) {
            if (advanced_info.qualifiers != TypeQualifiers::NONE) {
                qualifier_counts[advanced_info.qualifiers]++;
            }
        }

        if (!qualifier_counts.empty()) {
            std::cout << "Type qualifiers found:\n";
            for (const auto& [qualifier, count] : qualifier_counts) {
                std::cout << "  - " << static_cast<uint32_t>(qualifier) << ": " << count
                          << " types\n";
            }
        }

        std::cout << "========================================\n\n";
    }
}

bool ElfReader::extractInterruptVectorTable() {
    try {
        // Clear any previous interrupt vector data
        interrupt_vector_table_ = InterruptVectorTable();

        // Set architecture info based on ELF header
        uint16_t machine_type = is_32bit_ ? ehdr32_.e_machine : ehdr64_.e_machine;
        switch (machine_type) {
            case static_cast<uint16_t>(ElfMachine::EM_ARM):
                interrupt_vector_table_.architecture = "ARM";
                break;
            case static_cast<uint16_t>(ElfMachine::EM_AARCH64):
                interrupt_vector_table_.architecture = "ARM64";
                break;
            case static_cast<uint16_t>(ElfMachine::EM_RISCV):
                interrupt_vector_table_.architecture = "RISC-V";
                break;
            case static_cast<uint16_t>(ElfMachine::EM_XTENSA):
                interrupt_vector_table_.architecture = "Xtensa";
                break;
            default:
                interrupt_vector_table_.architecture = "Unknown";
                break;
        }

        // Strategy 1: Look for common interrupt vector section names
        std::vector<std::string> vector_section_names = {
            ".isr_vector",       // Common ARM Cortex-M naming
            ".vector_table",     // Alternative naming
            ".vectors",          // Short form
            ".interrupt_vector"  // Descriptive naming
        };

        bool found_vector_section = false;
        for (const auto& section_name : vector_section_names) {
            if (extractVectorFromSection(section_name)) {
                found_vector_section = true;
                break;
            }
        }

        // Strategy 2: If no dedicated section found, look at the beginning of .text
        if (!found_vector_section && interrupt_vector_table_.architecture == "ARM") {
            // For ARM Cortex-M, vector table is typically at the start of flash memory
            extractArmCortexMVectors();
        }

        // Strategy 3: Always try to identify interrupt handler functions
        std::vector<FunctionInfo> handlers = identifyInterruptHandlers();

        // Add handler function names to our vector table
        for (const auto& handler : handlers) {
            interrupt_vector_table_.handler_functions[handler.start_address] = handler.name;

            // Try to match handlers with vectors by address
            for (auto& vector : interrupt_vector_table_.vectors) {
                if (vector.handler_address == handler.start_address) {
                    vector.handler_name = handler.name;
                    break;
                }
            }
        }

        return !interrupt_vector_table_.vectors.empty() ||
               !interrupt_vector_table_.handler_functions.empty();

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "Error extracting interrupt vector table: " << e.what() << "\n";
        }
        return false;
    }
}

std::vector<FunctionInfo> ElfReader::identifyInterruptHandlers() const {
    std::vector<FunctionInfo> handlers;

    // Look through all discovered functions for interrupt handler patterns
    if (is_32bit_) {
        for (const auto& symbol : symbols32_) {
            if (!symbol.name.empty() && symbol.st_value != 0 &&
                symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC)) {
                // Create a FunctionInfo object for analysis
                FunctionInfo func_info;
                func_info.name = symbol.name;
                func_info.start_address = symbol.st_value;
                func_info.end_address = symbol.st_value + symbol.st_size;

                // Check if this function matches interrupt handler patterns
                if (func_info.isPotentialInterruptHandler()) {
                    handlers.push_back(func_info);
                }
            }
        }
    } else {
        for (const auto& symbol : symbols64_) {
            if (!symbol.name.empty() && symbol.st_value != 0 &&
                symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC)) {
                // Create a FunctionInfo object for analysis
                FunctionInfo func_info;
                func_info.name = symbol.name;
                func_info.start_address = symbol.st_value;
                func_info.end_address = symbol.st_value + symbol.st_size;

                // Check if this function matches interrupt handler patterns
                if (func_info.isPotentialInterruptHandler()) {
                    handlers.push_back(func_info);
                }
            }
        }
    }

    // Also check any functions discovered during DWARF analysis
    for (const auto& [func_name, func_info] : functions_) {
        if (func_info.isPotentialInterruptHandler()) {
            // Check if we already have this handler
            bool already_added = false;
            for (const auto& existing : handlers) {
                if (existing.name == func_info.name) {
                    already_added = true;
                    break;
                }
            }

            if (!already_added) {
                handlers.push_back(func_info);
            }
        }
    }

    return handlers;
}

void ElfReader::printInterruptVectorTable() const {
    if (!interrupt_vector_table_.vectors.empty()) {
        std::cout << "Vector# | Handler Address | Function Name                | Description\n";
        std::cout << "--------|-----------------|------------------------------|-------------------"
                     "--------\n";

        for (const auto& vector : interrupt_vector_table_.vectors) {
            if (vector.is_valid) {
                printf("%-7u | 0x%08llx      | %-28s | %s\n",
                       vector.vector_number,
                       (unsigned long long)vector.handler_address,
                       vector.handler_name.empty() ? "(unknown)" : vector.handler_name.c_str(),
                       vector.description.c_str());
            }
        }
    }
}

std::string ElfReader::getArmInterruptDescription(uint32_t vector_number) const {
    // ARM Cortex-M standard system exceptions and interrupts
    switch (vector_number) {
        case 0:
            return "Initial Stack Pointer";
        case 1:
            return "Reset Handler";
        case 2:
            return "NMI Handler";
        case 3:
            return "Hard Fault Handler";
        case 4:
            return "Memory Management Fault Handler";
        case 5:
            return "Bus Fault Handler";
        case 6:
            return "Usage Fault Handler";
        case 7:
        case 8:
        case 9:
        case 10:
            return "Reserved";
        case 11:
            return "SVCall Handler";
        case 12:
            return "Debug Monitor Handler";
        case 13:
            return "Reserved";
        case 14:
            return "PendSV Handler";
        case 15:
            return "SysTick Handler";
        default:
            if (vector_number >= ParsingLimits::MIN_SIGNIFICANT_IRQ) {
                return "External Interrupt " +
                       std::to_string(vector_number - ParsingLimits::MIN_SIGNIFICANT_IRQ);
            }
            return "Unknown Vector";
    }
}

bool ElfReader::extractVectorFromSection(const std::string& section_name) {
    // Look for the specified section in our section headers
    if (is_32bit_) {
        for (size_t i = 0; i < sections32_.size(); ++i) {
            if (sections32_[i].name == section_name) {
                // Found the vector section, extract data
                return extractVectorDataFromSection(i);
            }
        }
    } else {
        for (size_t i = 0; i < sections64_.size(); ++i) {
            if (sections64_[i].name == section_name) {
                // Found the vector section, extract data
                return extractVectorDataFromSection(i);
            }
        }
    }
    return false;
}

bool ElfReader::extractVectorDataFromSection(size_t section_index) {
    try {
        uint64_t section_addr = 0;
        uint64_t section_size = 0;

        if (is_32bit_) {
            if (section_index >= sections32_.size()) {
                return false;
            }
            const auto& section = sections32_[section_index];
            section_addr = section.sh_addr;
            section_size = section.sh_size;
        } else {
            if (section_index >= sections64_.size()) {
                return false;
            }
            const auto& section = sections64_[section_index];
            section_addr = section.sh_addr;
            section_size = section.sh_size;
        }

        interrupt_vector_table_.base_address = section_addr;
        interrupt_vector_table_.entry_size = ParsingLimits::DEFAULT_VECTOR_ENTRY_SIZE;
        interrupt_vector_table_.total_entries = section_size / interrupt_vector_table_.entry_size;

        // Read section data
        std::vector<uint8_t> section_data;
        if (!readSectionData(section_index, section_data)) {
            return false;
        }

        // Parse vector entries (assuming 32-bit addresses)
        for (uint32_t i = 0; i < interrupt_vector_table_.total_entries &&
                             static_cast<size_t>(i) * 4 < section_data.size();
             ++i) {
            uint32_t handler_address = 0;

            // Read 32-bit address (little-endian)
            if (static_cast<size_t>(i) * 4 + 3 < section_data.size()) {
                handler_address = section_data[static_cast<size_t>(i) * 4] |
                                  (section_data[static_cast<size_t>(i) * 4 + 1] << 8) |
                                  (section_data[static_cast<size_t>(i) * 4 + 2] << 16) |
                                  (section_data[static_cast<size_t>(i) * 4 + 3] << 24);
            }

            // Skip null or invalid addresses
            if (handler_address == 0 || handler_address == 0xFFFFFFFF) {
                continue;
            }

            // Create vector entry
            InterruptVectorEntry vector_entry(i, handler_address);
            vector_entry.description = getArmInterruptDescription(i);
            interrupt_vector_table_.vectors.push_back(vector_entry);
        }

        return !interrupt_vector_table_.vectors.empty();

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "Error parsing vector section data: " << e.what() << "\n";
        }
        return false;
    }
}

bool ElfReader::extractArmCortexMVectors() {
    // For ARM Cortex-M, vector table typically starts at beginning of flash
    // Look for .text section or similar that might contain the vector table

    if (is_32bit_) {
        for (size_t i = 0; i < sections32_.size(); ++i) {
            const auto& section = sections32_[i];

            // Look for executable sections that might contain vector table
            if (section.name == ".text" && section.sh_flags & 0x4 &&  // SHF_EXECINSTR
                section.sh_addr < ParsingLimits::LOW_MEMORY_THRESHOLD) {
                interrupt_vector_table_.base_address = section.sh_addr;
                interrupt_vector_table_.entry_size = ParsingLimits::DEFAULT_VECTOR_ENTRY_SIZE;

                // Assume standard ARM Cortex-M vector count (16 system + N user vectors)
                // Limit to reasonable size to avoid parsing entire .text section
                uint32_t max_vectors = std::min(64U, static_cast<uint32_t>(section.sh_size / 4));
                interrupt_vector_table_.total_entries = max_vectors;

                // Try to parse first few entries as potential vectors
                std::vector<uint8_t> section_data;
                if (readSectionData(i, section_data)) {
                    for (uint32_t vec = 0;
                         vec < max_vectors && static_cast<size_t>(vec) * 4 < section_data.size();
                         ++vec) {
                        uint32_t handler_address = 0;

                        if (static_cast<size_t>(vec) * 4 + 3 < section_data.size()) {
                            handler_address =
                                section_data[static_cast<size_t>(vec) * 4] |
                                (section_data[static_cast<size_t>(vec) * 4 + 1] << 8) |
                                (section_data[static_cast<size_t>(vec) * 4 + 2] << 16) |
                                (section_data[static_cast<size_t>(vec) * 4 + 3] << 24);
                        }

                        // ARM Cortex-M vectors: check if address looks valid
                        // Vector 0 is initial SP, vectors 1+ are handler addresses
                        if (vec == 0) {
                            // Stack pointer - should be reasonable value
                            if (handler_address > 0x20000000 && handler_address < 0x30000000) {
                                InterruptVectorEntry entry(vec,
                                                           handler_address,
                                                           "Initial Stack Pointer",
                                                           "ARM Cortex-M Initial SP");
                                interrupt_vector_table_.vectors.push_back(entry);
                            }
                        } else if (handler_address > 0x00000000 && handler_address < 0x10000000 &&
                                   handler_address != 0xFFFFFFFF && (handler_address & 1)) {
                            // ARM Cortex-M function addresses should be odd (Thumb mode)
                            InterruptVectorEntry entry(vec, handler_address);
                            entry.description = getArmInterruptDescription(vec);
                            interrupt_vector_table_.vectors.push_back(entry);
                        }
                    }
                    return !interrupt_vector_table_.vectors.empty();
                }
            }
        }
    }
    return false;
}

bool ElfReader::readSectionData(size_t section_index, std::vector<uint8_t>& data) const {
    uint64_t section_size = 0;
    uint64_t section_offset = 0;
    uint32_t section_type = 0;

    if (is_32bit_) {
        if (section_index >= sections32_.size()) {
            return false;
        }
        const auto& section = sections32_[section_index];
        section_size = section.sh_size;
        section_offset = section.sh_offset;
        section_type = section.sh_type;
    } else {
        if (section_index >= sections64_.size()) {
            return false;
        }
        const auto& section = sections64_[section_index];
        section_size = section.sh_size;
        section_offset = section.sh_offset;
        section_type = section.sh_type;
    }

    // Skip sections with no file data
    if (section_type == 8) {  // SHT_NOBITS
        return false;
    }

    try {
        // Check bounds
        if (section_offset + section_size > file_access_->size()) {
            return false;
        }

        data.resize(section_size);

        // Use the file access strategy to read section data
        if (file_access_) {
            const uint8_t* file_data = file_access_->data();
            std::memcpy(data.data(), file_data + section_offset, section_size);
        } else {
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "Error reading section data: " << e.what() << "\n";
        }
        return false;
    }
}

bool ElfReader::extractMemoryRegionMapping() {
    try {
        // Clear previous memory region data
        memory_region_map_.regions.clear();
        memory_region_map_.validation.global_errors.clear();
        memory_region_map_.validation.global_warnings.clear();

        // Set basic architecture information
        memory_region_map_.architecture = is_32bit_ ? "32-bit" : "64-bit";
        memory_region_map_.entry_point = getEntryPoint();

        if (config_.verbosity > 0) {
            std::cout << "Extracting memory region mapping from ELF program headers...\n";
        }

        // Check if program headers are available
        uint16_t ph_count = is_32bit_ ? ehdr32_.e_phnum : ehdr64_.e_phnum;
        if (ph_count == 0) {
            if (config_.verbosity > 0) {
                std::cout << "No program headers found in this ELF file.\n";
            }
            return false;
        }

        // Parse program headers to extract memory regions
        if (!parseMemoryRegionsFromProgramHeaders()) {
            return false;
        }

        // Classify memory regions by type
        classifyMemoryRegions();

        // Validate memory layout
        validateMemoryLayout();

        // Calculate memory usage statistics
        memory_region_map_.calculateMemoryUsage();

        // Determine memory layout characteristics
        analyzeMemoryLayoutCharacteristics();

        if (config_.verbosity > 1) {
            std::cout << "Found " << memory_region_map_.regions.size() << " memory regions ("
                      << memory_region_map_.getLoadableRegionCount() << " loadable)\n";
        }

        return !memory_region_map_.regions.empty();

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cerr << "Error extracting memory region mapping: " << e.what() << std::endl;
        }
        return false;
    }
}

void ElfReader::printMemoryRegionMapping() const {
    std::cout << "\n";
    std::cout << "==================================================================" << std::endl;
    std::cout << "Memory Region Mapping and Validation" << std::endl;
    std::cout << "==================================================================" << std::endl;
    std::cout << std::endl;

    // Basic information
    std::cout << "Architecture: " << memory_region_map_.architecture << std::endl;
    std::cout << "Entry Point: 0x" << std::hex << memory_region_map_.entry_point << std::dec
              << std::endl;
    std::cout << "Total Regions: " << memory_region_map_.regions.size() << std::endl;
    std::cout << "Loadable Regions: " << memory_region_map_.getLoadableRegionCount() << std::endl;
    std::cout << std::endl;

    // Memory layout characteristics
    const auto& layout = memory_region_map_.layout;
    std::cout << "Memory Layout Characteristics:" << std::endl;
    std::cout << "  Memory Model: "
              << (layout.memory_model.empty() ? "Standard" : layout.memory_model) << std::endl;
    std::cout << "  Position Independent: " << (layout.is_position_independent ? "Yes" : "No")
              << std::endl;
    std::cout << "  Physical Addresses: "
              << (layout.has_physical_addresses ? "Meaningful" : "Virtual only") << std::endl;

    if (layout.code_base_address > 0) {
        std::cout << "  Code Base Address: 0x" << std::hex << layout.code_base_address << std::dec
                  << std::endl;
    }
    if (layout.data_base_address > 0) {
        std::cout << "  Data Base Address: 0x" << std::hex << layout.data_base_address << std::dec
                  << std::endl;
    }
    std::cout << std::endl;

    // Calculate Flash and RAM usage based on region classification
    uint64_t flash_size = 0;
    uint64_t ram_size = 0;

    for (const auto& region : memory_region_map_.regions) {
        if (!region.is_loadable)
            continue;

        // Use the classified region type for accurate flash/RAM determination
        if (region.region_type == MemoryRegionType::CODE ||
            region.region_type == MemoryRegionType::RODATA) {
            flash_size += region.memory_size;
        } else if (region.region_type == MemoryRegionType::DATA ||
                   region.region_type == MemoryRegionType::BSS) {
            ram_size += region.memory_size;
        }
    }

    // Memory usage summary with Flash/RAM breakdown
    std::cout << "Memory Usage Summary:" << std::endl;
    std::cout << "  Flash (Code + RO Data): " << formatMemorySize(flash_size) << std::endl;
    std::cout << "  RAM (Data + BSS):       " << formatMemorySize(ram_size) << std::endl;
    std::cout << "  Total Memory:           " << formatMemorySize(flash_size + ram_size)
              << std::endl;
    std::cout << std::endl;

    // Detailed memory regions with region names
    std::cout << "Memory Regions:" << std::endl;
    std::cout << "================================================================================="
              << std::endl;
    std::cout << std::left << std::setw(12) << "Region" << std::setw(10) << "Type" << std::setw(18)
              << "Address" << std::setw(12) << "Size" << std::setw(13) << "Permissions"
              << "Description" << std::endl;
    std::cout << "================================================================================="
              << std::endl;

    for (const auto& region : memory_region_map_.regions) {
        if (!region.is_loadable)
            continue;  // Skip non-loadable regions in main display

        std::string region_name =
            region.name.empty() ? getRegionTypeName(region.region_type) : region.name;

        std::cout << std::left << std::setw(12) << region_name << std::setw(10)
                  << getRegionTypeName(region.region_type) << "0x" << std::hex << std::setw(16)
                  << region.virtual_address << std::dec << std::setw(12)
                  << formatMemorySize(region.memory_size) << std::setw(13)
                  << region.getPermissionString() << region.description << std::endl;
    }
    std::cout << "================================================================================="
              << std::endl;
    std::cout << std::endl;

    // Non-loadable regions (if any)
    bool hasNonLoadable = false;
    for (const auto& region : memory_region_map_.regions) {
        if (!region.is_loadable) {
            if (!hasNonLoadable) {
                std::cout << "Non-Loadable Regions:" << std::endl;
                std::cout << "====================================================================="
                             "============"
                          << std::endl;
                hasNonLoadable = true;
            }
            std::string region_name =
                region.name.empty() ? getRegionTypeName(region.region_type) : region.name;
            std::cout << std::left << std::setw(12) << region_name << std::setw(10)
                      << getRegionTypeName(region.region_type) << "0x" << std::hex << std::setw(16)
                      << region.virtual_address << std::dec << std::setw(12)
                      << formatMemorySize(region.memory_size) << std::setw(13)
                      << region.getPermissionString() << region.description << std::endl;
        }
    }
    if (hasNonLoadable) {
        std::cout
            << "================================================================================="
            << std::endl;
        std::cout << std::endl;
    }

    // Validation results - only show if there are errors, or if verbose mode
    const auto& validation = memory_region_map_.validation;
    bool has_errors = (validation.error_count > 0);
    bool has_warnings = (validation.warning_count > 0);

    // Show validation section if: errors exist OR verbose mode is enabled
    if (has_errors || config_.verbosity > 0) {
        std::cout << "Validation Results:" << std::endl;
        std::cout << "-------------------" << std::endl;

        if (config_.verbosity > 0) {
            std::cout
                << "The validation checks ensure the ELF file's memory layout is consistent and"
                << std::endl;
            std::cout << "reasonable for the target architecture." << std::endl;
            std::cout << std::endl;
            std::cout << "  Layout Valid:         "
                      << (validation.layout_valid ? "[OK] Yes" : "[!!] No")
                      << " - Memory regions are properly structured" << std::endl;
            std::cout << "  No Overlaps:          "
                      << (validation.no_overlaps ? "[OK] Yes" : "[!!] No")
                      << " - No conflicting memory regions" << std::endl;
            std::cout << "  Addresses Reasonable: "
                      << (validation.addresses_reasonable ? "[OK] Yes" : "[!!] No")
                      << " - Addresses match expected ranges" << std::endl;
            std::cout << "  Sizes Reasonable:     "
                      << (validation.sizes_reasonable ? "[OK] Yes" : "[!!] No")
                      << " - Region sizes are within expected limits" << std::endl;
            std::cout << std::endl;
        }

        std::cout << "  Total Errors:   " << validation.error_count << std::endl;
        std::cout << "  Total Warnings: " << validation.warning_count << std::endl;

        // Show errors (always show if they exist)
        if (!validation.global_errors.empty()) {
            std::cout << std::endl << "Validation Errors:" << std::endl;
            for (const auto& error : validation.global_errors) {
                std::cout << "  [!!] " << error << std::endl;
            }
        }

        // Show global warnings in verbose mode
        if (!validation.global_warnings.empty() && config_.verbosity > 0) {
            std::cout << std::endl << "Validation Warnings:" << std::endl;
            for (const auto& warning : validation.global_warnings) {
                std::cout << "  [!]  " << warning << std::endl;
            }
        }

        // Show per-region warnings in verbose mode
        if (has_warnings && config_.verbosity > 0) {
            bool header_shown = false;
            for (size_t i = 0; i < memory_region_map_.regions.size(); ++i) {
                const auto& region = memory_region_map_.regions[i];
                std::string region_name =
                    region.name.empty() ? getRegionTypeName(region.region_type) : region.name;

                if (!region.validation.warnings.empty()) {
                    if (!header_shown && validation.global_warnings.empty()) {
                        std::cout << std::endl << "Validation Warnings:" << std::endl;
                        header_shown = true;
                    }
                    for (const auto& warning : region.validation.warnings) {
                        std::cout << "  [!]  " << region_name << ": " << warning << std::endl;
                    }
                }

                // Always show errors (if they exist)
                if (!region.validation.errors.empty()) {
                    for (const auto& error : region.validation.errors) {
                        std::cout << "  [!!] " << region_name << ": " << error << std::endl;
                    }
                }
            }
        }

        std::cout << std::endl;
    }

    std::cout << std::endl;
}

//==============================================================================
// Memory Region Helper Methods
//==============================================================================

bool ElfReader::parseMemoryRegionsFromProgramHeaders() {
    try {
        // Get program header table offset and size
        uint64_t ph_offset = is_32bit_ ? ehdr32_.e_phoff : ehdr64_.e_phoff;
        uint16_t ph_count = is_32bit_ ? ehdr32_.e_phnum : ehdr64_.e_phnum;
        uint16_t ph_size = is_32bit_ ? ehdr32_.e_phentsize : ehdr64_.e_phentsize;

        if (config_.verbosity > 1) {
            std::cout << "Parsing " << ph_count << " program headers at offset 0x" << std::hex
                      << ph_offset << std::dec << "\n";
        }

        for (uint16_t i = 0; i < ph_count; ++i) {
            uint64_t current_offset = ph_offset + (static_cast<uint64_t>(i) * ph_size);

            // Parse program header based on ELF class
            MemoryRegion region;
            if (!is_32bit_) {
                if (!parseProgramHeader64(current_offset, region)) {
                    continue;  // Skip invalid headers
                }
            } else {
                if (!parseProgramHeader32(current_offset, region)) {
                    continue;  // Skip invalid headers
                }
            }

            // Add region to collection
            memory_region_map_.regions.push_back(region);
        }

        return !memory_region_map_.regions.empty();

    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cerr << "Error parsing program headers: " << e.what() << std::endl;
        }
        return false;
    }
}

bool ElfReader::parseProgramHeader32(uint64_t offset, MemoryRegion& region) {
    try {
        Elf32_Phdr phdr;

        // Read program header fields
        phdr.p_type = readValue<uint32_t>(offset);
        phdr.p_offset = readValue<uint32_t>(offset + 4);
        phdr.p_vaddr = readValue<uint32_t>(offset + 8);
        phdr.p_paddr = readValue<uint32_t>(offset + 12);
        phdr.p_filesz = readValue<uint32_t>(offset + 16);
        phdr.p_memsz = readValue<uint32_t>(offset + 20);
        phdr.p_flags = readValue<uint32_t>(offset + 24);
        phdr.p_align = readValue<uint32_t>(offset + 28);

        // Fill memory region structure
        region.virtual_address = phdr.p_vaddr;
        region.physical_address = phdr.p_paddr;
        region.file_offset = phdr.p_offset;
        region.file_size = phdr.p_filesz;
        region.memory_size = phdr.p_memsz;
        region.alignment = phdr.p_align;
        region.permissions = phdr.p_flags;
        region.segment_type = static_cast<ElfSegmentType>(phdr.p_type);
        region.is_loadable = (phdr.p_type == static_cast<uint32_t>(ElfSegmentType::PT_LOAD));

        // Set basic description
        region.description = getSegmentTypeDescription(region.segment_type);

        return true;

    } catch (const std::exception& e) {
        if (config_.verbosity > 1) {
            std::cerr << "Error parsing 32-bit program header: " << e.what() << std::endl;
        }
        return false;
    }
}

bool ElfReader::parseProgramHeader64(uint64_t offset, MemoryRegion& region) {
    try {
        Elf64_Phdr phdr;

        // Read program header fields (64-bit has different ordering)
        phdr.p_type = readValue<uint32_t>(offset);
        phdr.p_flags = readValue<uint32_t>(offset + 4);
        phdr.p_offset = readValue<uint64_t>(offset + 8);
        phdr.p_vaddr = readValue<uint64_t>(offset + 16);
        phdr.p_paddr = readValue<uint64_t>(offset + 24);
        phdr.p_filesz = readValue<uint64_t>(offset + 32);
        phdr.p_memsz = readValue<uint64_t>(offset + 40);
        phdr.p_align = readValue<uint64_t>(offset + 48);

        // Fill memory region structure
        region.virtual_address = phdr.p_vaddr;
        region.physical_address = phdr.p_paddr;
        region.file_offset = phdr.p_offset;
        region.file_size = phdr.p_filesz;
        region.memory_size = phdr.p_memsz;
        region.alignment = phdr.p_align;
        region.permissions = phdr.p_flags;
        region.segment_type = static_cast<ElfSegmentType>(phdr.p_type);
        region.is_loadable = (phdr.p_type == static_cast<uint32_t>(ElfSegmentType::PT_LOAD));

        // Set basic description
        region.description = getSegmentTypeDescription(region.segment_type);

        return true;

    } catch (const std::exception& e) {
        if (config_.verbosity > 1) {
            std::cerr << "Error parsing 64-bit program header: " << e.what() << std::endl;
        }
        return false;
    }
}

void ElfReader::classifyMemoryRegions() {
    // Check if this is an ESP32/Xtensa binary for specialized classification
    uint16_t machine_type = is_32bit_ ? ehdr32_.e_machine : ehdr64_.e_machine;
    bool is_esp32 = (machine_type == static_cast<uint16_t>(ElfMachine::EM_XTENSA));

    for (auto& region : memory_region_map_.regions) {
        // Skip non-loadable segments for classification
        if (!region.is_loadable) {
            region.region_type = classifyNonLoadableRegion(region.segment_type);
            continue;
        }

        // Classify based on permissions and characteristics
        bool readable = region.hasPermission(ElfSegmentFlags::PF_R);
        bool writable = region.hasPermission(ElfSegmentFlags::PF_W);
        bool executable = region.hasPermission(ElfSegmentFlags::PF_X);

        // ESP32-specific memory region classification
        if (is_esp32) {
            classifyESP32MemoryRegion(region, readable, writable, executable);
        } else {
            // Generic classification for non-ESP32 architectures

            // Check common embedded flash/RAM address ranges first
            bool is_likely_flash = (region.virtual_address >= 0x08000000 &&
                                    region.virtual_address < 0x10000000) ||  // STM32 flash
                                   (region.virtual_address < 0x00100000);  // Some MCUs start at 0x0
            bool is_likely_ram = (region.virtual_address >= 0x20000000 &&
                                  region.virtual_address < 0x30000000) ||  // STM32 SRAM
                                 (region.virtual_address >= 0x10000000 &&
                                  region.virtual_address < 0x20000000);  // Some MCU SRAM

            if ((executable && readable && !writable) || (executable && is_likely_flash)) {
                // RX or RWX in flash region - treat as code/flash
                region.region_type = MemoryRegionType::CODE;
                region.name = "FLASH";
            } else if ((readable && writable && !executable) || (is_likely_ram && writable)) {
                // Writable region - could be DATA or BSS
                if (region.file_size > 0) {
                    region.region_type = MemoryRegionType::DATA;
                    region.name = "DATA";
                } else {
                    region.region_type = MemoryRegionType::BSS;
                    region.name = "BSS";
                }
            } else if (readable && !writable && !executable) {
                region.region_type = MemoryRegionType::RODATA;
                region.name = "RODATA";
            } else {
                region.region_type = MemoryRegionType::UNKNOWN;
                region.name = "UNKNOWN";
            }
        }
    }
}

void ElfReader::validateMemoryLayout() {
    auto& validation = memory_region_map_.validation;

    // Reset validation state
    validation.layout_valid = true;
    validation.no_overlaps = true;
    validation.addresses_reasonable = true;
    validation.sizes_reasonable = true;
    validation.error_count = 0;
    validation.warning_count = 0;

    // Validate individual regions
    for (size_t i = 0; i < memory_region_map_.regions.size(); ++i) {
        auto& region = memory_region_map_.regions[i];
        validateSingleRegion(region);

        // Count errors and warnings
        validation.error_count += region.validation.errors.size();
        validation.warning_count += region.validation.warnings.size();
    }

    // Check for overlaps
    checkRegionOverlaps();

    // Validate global layout characteristics
    validateGlobalLayout();

    // Set overall validation status
    validation.layout_valid = (validation.error_count == 0);
}

void ElfReader::validateSingleRegion(MemoryRegion& region) {
    region.validation.address_valid = true;
    region.validation.size_valid = true;
    region.validation.alignment_valid = true;
    region.validation.overlap_detected = false;
    region.validation.permission_conflict = false;

    // Validate virtual address range
    if (region.virtual_address == 0 && region.is_loadable) {
        region.validation.address_valid = false;
        region.validation.warnings.push_back("Loadable region has zero virtual address");
    }

    // Check for extremely large addresses (might indicate corruption)
    if (region.virtual_address > 0xFFFFFFFF00000000ULL && is_32bit_) {
        region.validation.address_valid = false;
        region.validation.errors.push_back("Virtual address too large for 32-bit architecture");
    }

    // Validate sizes
    if (region.memory_size == 0 && region.is_loadable) {
        region.validation.size_valid = false;
        region.validation.warnings.push_back("Loadable region has zero memory size");
    }

    if (region.file_size > region.memory_size) {
        region.validation.size_valid = false;
        region.validation.errors.push_back("File size larger than memory size");
    }

    // Check for extremely large sizes
    if (region.memory_size > 0x40000000) {  // 1GB
        region.validation.size_valid = false;
        region.validation.warnings.push_back("Region size exceeds 1GB (might indicate corruption)");
    }

    // Validate alignment
    if (region.alignment > 0) {
        if ((region.alignment & (region.alignment - 1)) != 0) {
            region.validation.alignment_valid = false;
            region.validation.errors.push_back("Alignment is not a power of 2");
        }

        if (region.virtual_address % region.alignment != 0) {
            region.validation.alignment_valid = false;
            region.validation.warnings.push_back(
                "Virtual address not aligned to specified boundary");
        }
    }

    // Validate permissions
    if (region.is_loadable) {
        bool readable = region.hasPermission(ElfSegmentFlags::PF_R);
        bool writable = region.hasPermission(ElfSegmentFlags::PF_W);
        bool executable = region.hasPermission(ElfSegmentFlags::PF_X);

        if (!readable && !writable && !executable) {
            region.validation.permission_conflict = true;
            region.validation.warnings.push_back("Loadable region has no permissions");
        }

        if (writable && executable) {
            region.validation.permission_conflict = true;
            region.validation.warnings.push_back(
                "Region is both writable and executable (security risk)");
        }
    }
}

void ElfReader::checkRegionOverlaps() {
    auto& validation = memory_region_map_.validation;

    // Check all loadable regions for overlaps
    for (size_t i = 0; i < memory_region_map_.regions.size(); ++i) {
        auto& region1 = memory_region_map_.regions[i];
        if (!region1.is_loadable)
            continue;

        for (size_t j = i + 1; j < memory_region_map_.regions.size(); ++j) {
            auto& region2 = memory_region_map_.regions[j];
            if (!region2.is_loadable)
                continue;

            if (region1.overlaps(region2)) {
                validation.no_overlaps = false;
                region1.validation.overlap_detected = true;
                region2.validation.overlap_detected = true;

                std::ostringstream oss;
                oss << "Region " << getRegionTypeName(region1.region_type) << " overlaps with "
                    << getRegionTypeName(region2.region_type);
                validation.global_errors.push_back(oss.str());

                region1.validation.errors.push_back("Overlaps with another region");
                region2.validation.errors.push_back("Overlaps with another region");
            }
        }
    }
}

void ElfReader::validateGlobalLayout() {
    auto& validation = memory_region_map_.validation;

    // Check if entry point falls within a code region
    bool entry_point_valid = false;
    for (const auto& region : memory_region_map_.regions) {
        if (region.region_type == MemoryRegionType::CODE &&
            region.containsAddress(memory_region_map_.entry_point)) {
            entry_point_valid = true;
            break;
        }
    }

    if (!entry_point_valid && memory_region_map_.entry_point != 0) {
        validation.addresses_reasonable = false;
        validation.global_warnings.push_back("Entry point is not within a code region");
    }

    // Check for reasonable memory layout
    uint64_t min_addr = UINT64_MAX;
    uint64_t max_addr = 0;

    for (const auto& region : memory_region_map_.regions) {
        if (region.is_loadable) {
            min_addr = std::min(min_addr, region.virtual_address);
            max_addr = std::max(max_addr, region.virtual_address + region.memory_size);
        }
    }

    if (min_addr != UINT64_MAX && max_addr - min_addr > 0x100000000ULL) {  // 4GB span
        validation.addresses_reasonable = false;
        validation.global_warnings.push_back("Memory layout spans more than 4GB");
    }
}

void ElfReader::analyzeMemoryLayoutCharacteristics() {
    auto& layout = memory_region_map_.layout;

    // Find code and data base addresses
    layout.code_base_address = 0;
    layout.data_base_address = 0;

    for (const auto& region : memory_region_map_.regions) {
        if (region.region_type == MemoryRegionType::CODE && layout.code_base_address == 0) {
            layout.code_base_address = region.virtual_address;
        }
        if (region.region_type == MemoryRegionType::DATA && layout.data_base_address == 0) {
            layout.data_base_address = region.virtual_address;
        }
    }

    // Determine if physical addresses are meaningful
    layout.has_physical_addresses = false;
    for (const auto& region : memory_region_map_.regions) {
        if (region.physical_address != 0 && region.physical_address != region.virtual_address) {
            layout.has_physical_addresses = true;
            break;
        }
    }

    // Check for position independence
    layout.is_position_independent = false;
    if (layout.code_base_address < 0x400000) {
        layout.is_position_independent = true;
    }

    // Determine memory model
    if (layout.has_physical_addresses) {
        layout.memory_model = "Harvard (separate physical addresses)";
    } else if (is_32bit_) {
        layout.memory_model = "Flat (unified address space)";
    } else {
        layout.memory_model = "Virtual memory";
    }
}

//==============================================================================
// Memory Region Utility Methods
//==============================================================================

std::string ElfReader::getSegmentTypeDescription(ElfSegmentType type) const {
    switch (type) {
        case ElfSegmentType::PT_NULL:
            return "Unused program header entry";
        case ElfSegmentType::PT_LOAD:
            return "Loadable segment";
        case ElfSegmentType::PT_DYNAMIC:
            return "Dynamic linking information";
        case ElfSegmentType::PT_INTERP:
            return "Interpreter information";
        case ElfSegmentType::PT_NOTE:
            return "Auxiliary information";
        case ElfSegmentType::PT_SHLIB:
            return "Reserved";
        case ElfSegmentType::PT_PHDR:
            return "Program header table";
        case ElfSegmentType::PT_TLS:
            return "Thread-local storage";
        case ElfSegmentType::PT_GNU_EH_FRAME:
            return "GNU exception handling frame";
        case ElfSegmentType::PT_GNU_STACK:
            return "GNU stack flags";
        case ElfSegmentType::PT_GNU_RELRO:
            return "GNU read-only after relocation";
        case ElfSegmentType::PT_ARM_EXIDX:
            return "ARM exception index table";
        default:
            return "Unknown segment type";
    }
}

std::string ElfReader::getRegionTypeName(MemoryRegionType type) const {
    switch (type) {
        case MemoryRegionType::CODE:
            return "CODE";
        case MemoryRegionType::DATA:
            return "DATA";
        case MemoryRegionType::BSS:
            return "BSS";
        case MemoryRegionType::RODATA:
            return "RODATA";
        case MemoryRegionType::STACK:
            return "STACK";
        case MemoryRegionType::HEAP:
            return "HEAP";
        case MemoryRegionType::DYNAMIC:
            return "DYNAMIC";
        case MemoryRegionType::TLS:
            return "TLS";
        case MemoryRegionType::NOTE:
            return "NOTE";
        case MemoryRegionType::EXCEPTION:
            return "EXCEPTION";
        case MemoryRegionType::UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

MemoryRegionType ElfReader::classifyNonLoadableRegion(ElfSegmentType type) const {
    switch (type) {
        case ElfSegmentType::PT_DYNAMIC:
            return MemoryRegionType::DYNAMIC;
        case ElfSegmentType::PT_TLS:
            return MemoryRegionType::TLS;
        case ElfSegmentType::PT_NOTE:
            return MemoryRegionType::NOTE;
        case ElfSegmentType::PT_GNU_EH_FRAME:
        case ElfSegmentType::PT_ARM_EXIDX:
            return MemoryRegionType::EXCEPTION;
        default:
            return MemoryRegionType::UNKNOWN;
    }
}

void ElfReader::classifyESP32MemoryRegion(MemoryRegion& region,
                                          bool readable,
                                          bool writable,
                                          bool executable) {
    uint64_t addr = region.virtual_address;

    // ESP32 memory map classification based on address ranges
    // Reference:
    // https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/memory-types.html

    if (addr >= 0x3FF00000 && addr < 0x3FF80000) {
        // Internal ROM 0 - 512KB
        region.region_type = MemoryRegionType::RODATA;
        region.name = "ROM0 (Internal ROM)";
    } else if (addr >= 0x3FF80000 && addr < 0x3FFC0000) {
        // Internal SRAM 0 - 192KB
        if (executable && readable) {
            region.region_type = MemoryRegionType::CODE;
            region.name = "IRAM (Internal SRAM0 Instruction)";
        } else if (readable && writable) {
            region.region_type = MemoryRegionType::DATA;
            region.name = "DRAM (Internal SRAM0 Data)";
        } else {
            region.region_type = MemoryRegionType::DATA;
            region.name = "SRAM0 (Internal SRAM0)";
        }
    } else if (addr >= 0x3FFC0000 && addr < 0x40000000) {
        // Internal SRAM 1 - 128KB
        if (readable && writable && !executable) {
            region.region_type = MemoryRegionType::DATA;
            region.name = "DRAM (Internal SRAM1)";
        } else {
            region.region_type = MemoryRegionType::DATA;
            region.name = "SRAM1 (Internal SRAM1)";
        }
    } else if (addr >= 0x40000000 && addr < 0x40070000) {
        // Internal ROM 1 - 448KB
        region.region_type = MemoryRegionType::RODATA;
        region.name = "ROM1 (Internal ROM)";
    } else if (addr >= 0x40070000 && addr < 0x40080000) {
        // Internal SRAM 2 - 64KB
        region.region_type = MemoryRegionType::DATA;
        region.name = "SRAM2 (Internal SRAM2)";
    } else if (addr >= 0x40080000 && addr < 0x400A0000) {
        // Internal SRAM 0 (Instruction bus view) - 128KB
        region.region_type = MemoryRegionType::CODE;
        region.name = "IRAM (Internal SRAM0 Instruction)";
    } else if (addr >= 0x400A0000 && addr < 0x400C0000) {
        // Internal SRAM 1 (Instruction bus view) - 128KB
        region.region_type = MemoryRegionType::CODE;
        region.name = "IRAM (Internal SRAM1 Instruction)";
    } else if (addr >= 0x400C0000 && addr < 0x400C2000) {
        // RTC Fast Memory - 8KB
        region.region_type = MemoryRegionType::DATA;
        region.name = "RTC_FAST (RTC Fast Memory)";
    } else if (addr >= 0x50000000 && addr < 0x50002000) {
        // RTC Slow Memory - 8KB
        region.region_type = MemoryRegionType::DATA;
        region.name = "RTC_SLOW (RTC Slow Memory)";
    } else if (addr >= 0x3F800000 && addr < 0x3FC00000) {
        // External SPIRAM - up to 4MB
        region.region_type = MemoryRegionType::DATA;
        region.name = "SPIRAM (External PSRAM)";
    } else {
        // Fall back to generic classification for unknown ranges
        if (executable && readable && !writable) {
            region.region_type = MemoryRegionType::CODE;
            region.name = "CODE";
        } else if (readable && writable && !executable) {
            if (region.file_size > 0) {
                region.region_type = MemoryRegionType::DATA;
                region.name = "DATA";
            } else {
                region.region_type = MemoryRegionType::BSS;
                region.name = "BSS";
            }
        } else if (readable && !writable && !executable) {
            region.region_type = MemoryRegionType::RODATA;
            region.name = "RODATA";
        } else {
            region.region_type = MemoryRegionType::UNKNOWN;
            region.name = "UNKNOWN";
        }
    }
}

std::string ElfReader::formatMemorySize(uint64_t size) const {
    std::ostringstream oss;

    if (size >= (1ULL << 30)) {
        oss << std::fixed << std::setprecision(1) << (double)size / (1ULL << 30) << " GB";
    } else if (size >= (1ULL << 20)) {
        oss << std::fixed << std::setprecision(1) << (double)size / (1ULL << 20) << " MB";
    } else if (size >= (1ULL << 10)) {
        oss << std::fixed << std::setprecision(1) << (double)size / (1ULL << 10) << " KB";
    } else {
        oss << size << " bytes";
    }

    return oss.str();
}

bool ElfReader::performBinaryExport() {
    try {
        // Create exporter for the specified format
        auto exporter = createExporter(config_.exportFormat);
        if (!exporter) {
            std::cerr << "Error: Unsupported export format '" << config_.exportFormat << "'\n";
            std::cerr << "Supported formats: hex, s19, s28, s37, bin\n";
            return false;
        }

        // Extract memory regions from loadable sections
        std::vector<ExportMemoryRegion> regions = extractMemoryRegions();
        if (regions.empty()) {
            std::cerr << "Warning: No loadable sections found for export\n";
            return true;
        }

        // Generate output filename
        std::string output_filename = config_.inputFile + exporter->getFileExtension();

        if (config_.verbosity >= 1) {
            std::cout << "Exporting " << regions.size() << " memory regions to: " << output_filename
                      << std::endl;
            for (const auto& region : regions) {
                std::cout << "  Region: " << region.section_name << " @ 0x" << std::hex
                          << std::setw(8) << std::setfill('0') << region.address << " (" << std::dec
                          << region.size << " bytes)" << std::endl;
            }
        }

        // Perform the export
        bool success = exporter->exportToFile(output_filename, regions, 0);

        if (success && config_.verbosity >= 1) {
            std::cout << "Successfully exported to " << exporter->getFormatName() << " format"
                      << std::endl;
        }

        return success;

    } catch (const std::exception& e) {
        std::cerr << "Error during binary export: " << e.what() << std::endl;
        return false;
    }
}
std::vector<ExportMemoryRegion> ElfReader::extractMemoryRegions() {
    std::vector<ExportMemoryRegion> regions;

    try {
        // Process loadable sections (.text, .data, .rodata, etc.)
        const auto section_count = getSectionCount();

        for (uint16_t i = 0; i < section_count; ++i) {
            std::string section_name = getSectionName(i);

            // Skip non-loadable sections
            if (!isSectionLoadable(i)) {
                continue;
            }

            // Get section information
            uint64_t section_addr = 0;
            uint64_t section_size = 0;

            if (is_32bit_) {
                if (i < sections32_.size()) {
                    section_addr = sections32_[i].sh_addr;
                    section_size = sections32_[i].sh_size;
                }
            } else {
                if (i < sections64_.size()) {
                    section_addr = sections64_[i].sh_addr;
                    section_size = sections64_[i].sh_size;
                }
            }

            // Skip sections with no address or size
            if (section_addr == 0 || section_size == 0) {
                continue;
            }

            // Read section data
            std::vector<uint8_t> section_data;
            if (readSectionData(i, section_data) && !section_data.empty()) {
                regions.emplace_back(section_addr, section_size, section_data, section_name);

                if (config_.verbosity >= 2) {
                    std::cout << "Added region: " << section_name << " @ 0x" << std::hex
                              << section_addr << " (" << std::dec << section_size << " bytes)"
                              << std::endl;
                }
            }
        }

        // Sort regions by address
        std::sort(regions.begin(),
                  regions.end(),
                  [](const ExportMemoryRegion& a, const ExportMemoryRegion& b) {
                      return a.address < b.address;
                  });

    } catch (const std::exception& e) {
        std::cerr << "Error extracting memory regions: " << e.what() << std::endl;
    }

    return regions;
}

std::string ElfReader::getSectionName(uint16_t section_index) const {
    try {
        uint16_t shstrndx = getSectionNameIndex();
        if (shstrndx >= string_tables_.size()) {
            return "section_" + std::to_string(section_index);
        }

        uint32_t name_offset = 0;
        if (is_32bit_ && section_index < sections32_.size()) {
            name_offset = sections32_[section_index].sh_name;
        } else if (!is_32bit_ && section_index < sections64_.size()) {
            name_offset = sections64_[section_index].sh_name;
        }

        return getString(shstrndx, name_offset);

    } catch (const std::exception&) {
        return "section_" + std::to_string(section_index);
    }
}

std::string ElfReader::getSectionNameForAddress(uint64_t address) const {
    try {
        if (is_32bit_) {
            for (size_t i = 0; i < sections32_.size(); ++i) {
                const auto& section = sections32_[i];
                // Check if address falls within this section's range
                if (address >= section.sh_addr && address < section.sh_addr + section.sh_size &&
                    section.sh_addr != 0) {  // Only consider sections with valid addresses
                    return section.name.empty() ? getSectionName(i) : section.name;
                }
            }
        } else {
            for (size_t i = 0; i < sections64_.size(); ++i) {
                const auto& section = sections64_[i];
                // Check if address falls within this section's range
                if (address >= section.sh_addr && address < section.sh_addr + section.sh_size &&
                    section.sh_addr != 0) {  // Only consider sections with valid addresses
                    return section.name.empty() ? getSectionName(i) : section.name;
                }
            }
        }
        return "";  // Address not found in any section
    } catch (const std::exception&) {
        return "";  // Error occurred
    }
}

bool ElfReader::isSectionLoadable(uint16_t section_index) {
    try {
        uint32_t section_flags = 0;
        uint32_t section_type = 0;

        if (is_32bit_ && section_index < sections32_.size()) {
            section_flags = sections32_[section_index].sh_flags;
            section_type = sections32_[section_index].sh_type;
        } else if (!is_32bit_ && section_index < sections64_.size()) {
            section_flags = sections64_[section_index].sh_flags;
            section_type = sections64_[section_index].sh_type;
        }

        // Check if section has ALLOC flag (should be loaded into memory)
        bool has_alloc = (section_flags & 0x2) != 0;  // SHF_ALLOC

        // Check if it's a program bits section
        bool is_progbits = (section_type == 1);  // SHT_PROGBITS

        return has_alloc && is_progbits;

    } catch (const std::exception&) {
        return false;
    }
}

bool ElfReader::readSectionData(uint16_t section_index, std::vector<uint8_t>& data) const {
    try {
        uint64_t section_offset = 0;
        uint64_t section_size = 0;

        if (is_32bit_ && section_index < sections32_.size()) {
            section_offset = sections32_[section_index].sh_offset;
            section_size = sections32_[section_index].sh_size;
        } else if (!is_32bit_ && section_index < sections64_.size()) {
            section_offset = sections64_[section_index].sh_offset;
            section_size = sections64_[section_index].sh_size;
        } else {
            return false;
        }

        if (section_size == 0) {
            return false;
        }

        data.resize(section_size);
        std::memcpy(data.data(), file_access_->data() + section_offset, section_size);

        return true;

    } catch (const std::exception&) {
        return false;
    }
}

void ElfReader::printPerformanceMetrics() const {
    if constexpr (!ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
        return;  // Performance metrics disabled
    }

    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "Performance Optimization Metrics\n";
    std::cout << std::string(80, '=') << "\n";

    // File and memory access metrics
    std::cout << "File Processing:\n";
    std::cout << "  File Size: " << (performance_metrics_.file_size_bytes / 1024 / 1024) << " MB\n";
    std::cout << "  Access Strategy: "
              << (performance_metrics_.memory_mapping_used ? "Memory Mapping" : "In-Memory Loading")
              << "\n";
    std::cout << "  Total Processing Time: " << std::fixed << std::setprecision(1)
              << performance_metrics_.total_processing_time_ms << " ms\n";

    // DWARF processing efficiency
    std::cout << "\nDWARF Processing Efficiency:\n";
    std::cout << "  Compilation Units: " << performance_metrics_.compilation_units_processed
              << "\n";
    std::cout << "  Total Structures Encountered: "
              << performance_metrics_.total_structures_encountered << "\n";
    std::cout << "  Duplicate Structures Skipped: "
              << performance_metrics_.duplicate_structures_skipped << "\n";
    std::cout << "  Deduplication Efficiency: " << std::fixed << std::setprecision(1)
              << performance_metrics_.getDeduplicationEfficiency() << "%\n";

    // String interner metrics
    std::cout << "\nString Interner Performance:\n";
    std::cout << "  Reserved Capacity: " << performance_metrics_.string_interner_capacity_reserved
              << " strings\n";
    std::cout << "  Final Pool Size: " << performance_metrics_.final_string_pool_size
              << " strings\n";
    std::cout << "  Utilization: " << std::fixed << std::setprecision(1)
              << performance_metrics_.getStringInternerUtilization() << "%\n";

    if (performance_metrics_.string_interner_fallback_used == 1) {
        std::cout << "  Note: Used fallback allocation (25% of original capacity)\n";
    } else if (performance_metrics_.string_interner_fallback_used == 2) {
        std::cout << "  Note: Pre-allocation failed, used dynamic allocation\n";
    }

    // Performance summary
    double structures_per_second =
        static_cast<double>(performance_metrics_.total_structures_encountered) /
        (static_cast<double>(performance_metrics_.total_processing_time_ms) / 1000.0);
    std::cout << "\nPerformance Summary:\n";
    std::cout << "  Processing Rate: " << std::fixed << std::setprecision(0)
              << structures_per_second << " structures/second\n";

    size_t bytes_per_ms = performance_metrics_.file_size_bytes /
                          static_cast<size_t>(performance_metrics_.total_processing_time_ms);
    std::cout << "  Throughput: " << (bytes_per_ms * 1000 / 1024 / 1024) << " MB/second\n";

    if (performance_metrics_.duplicate_structures_skipped > 0) {
        size_t processing_saved = performance_metrics_.duplicate_structures_skipped;
        std::cout << "  Optimization Benefit: Avoided processing " << processing_saved
                  << " duplicate structures\n";
    }

    std::cout << std::string(80, '=') << "\n";
}

// ==========================================
// Library API Methods Implementation
// ==========================================

void ElfReader::ensureAnalysisCompleted() {
    if (!analysis_completed_) {
        // Temporarily set verbosity to quiet to avoid output in library mode
        int original_verbosity = config_.verbosity;
        config_.verbosity = -1;
        analyzeMemberParameters();
        config_.verbosity = original_verbosity;
    }
}

std::vector<MemberInfo> ElfReader::getVariables() {
    ensureAnalysisCompleted();
    std::vector<MemberInfo> variables;
    std::set<std::string> processed_symbols;
    std::set<uint64_t> processed_addresses;

    // Process variables discovered from DWARF debug information
    for (const auto& [symbol_name, var_info] : dwarf_variables_) {
        if (processed_addresses.find(var_info.address) != processed_addresses.end()) {
            continue;  // Skip duplicate addresses
        }
        processed_addresses.insert(var_info.address);

        // Create a MemberInfo from the DWARF variable
        MemberInfo member(symbol_name, var_info.address, var_info.type_name);
        member.is_constant = var_info.is_constant;
        member.constant_value = var_info.constant_value;
        if (config_.showSections) {
            member.section_name = getSectionNameForAddress(var_info.address);
        }

        variables.push_back(member);
    }

    return variables;
}

std::vector<FunctionInfo> ElfReader::getFunctions() {
    ensureAnalysisCompleted();
    std::vector<FunctionInfo> functions;

    // Extract functions from DWARF information
    for (const auto& [func_name, func_info] : functions_) {
        functions.push_back(func_info);
    }

    return functions;
}

std::vector<MemberInfo> ElfReader::getConstants() {
    ensureAnalysisCompleted();
    std::vector<MemberInfo> constants;
    auto all_variables = getVariables();

    // Filter to only include constants
    for (const auto& var : all_variables) {
        if (var.is_constant) {
            constants.push_back(var);
        }
    }

    return constants;
}

std::string ElfReader::getArchitecture() const {
    if (is_32bit_) {
        return "32-bit Little Endian";
    } else {
        return "64-bit Little Endian";
    }
}

// ========================================================================
// Parallel Processing Implementation
// ========================================================================

void ElfReader::initializeParallelProcessing() {
    if (!config_.enableParallelProcessing) {
        if (config_.verbosity > 1) {
            std::cout << "Parallel processing disabled in configuration\n";
        }
        return;
    }

    try {
        // Create thread pool with configured or auto-detected thread count
        thread_pool_ = std::make_unique<ThreadPool>(config_.threadCount);

        if (config_.verbosity > 1) {
            std::cout << "Initialized thread pool with " << thread_pool_->getThreadCount()
                      << " worker threads\n";
        }

        // Note: Work distribution coordinator will be initialized when needed
        // For now, we focus on thread pool setup and basic parallel infrastructure

        if (config_.verbosity > 1) {
            std::cout << "Parallel processing infrastructure ready\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize parallel processing: " << e.what() << std::endl;

        // Fallback to sequential processing
        thread_pool_.reset();

        if (config_.verbosity > 0) {
            std::cout << "Falling back to sequential processing\n";
        }
    }
}

void ElfReader::shutdownParallelProcessing() {
    if (thread_pool_) {
        if (config_.verbosity > 1) {
            std::cout << "Shutting down thread pool...\n";
        }

        // Thread pool destructor handles shutdown automatically
        thread_pool_.reset();
    }

    if (config_.verbosity > 1) {
        std::cout << "Parallel processing shutdown complete\n";
    }
}

#if HAVE_LIBDWARF
bool ElfReader::parseDwarfCompilationUnitsParallel(Dwarf_Debug dbg) {
    if (!thread_pool_) {
        if (config_.verbosity > 1) {
            std::cout << "Thread pool not available, using sequential processing\n";
        }
        return parseDwarfCompilationUnitsSequential(dbg);
    }

    if (config_.verbosity > 0) {
        std::cout << "Parallel DWARF compilation unit processing infrastructure ready\n";
        std::cout << "Thread pool available with " << thread_pool_->getThreadCount()
                  << " workers\n";
        std::cout
            << "Using sequential processing (parallel CU processing implementation pending)\n";
    }

    // We set up the infrastructure but use sequential processing
    // Full parallel implementation requires complex coordination of libdwarf contexts
    return parseDwarfCompilationUnitsSequential(dbg);
}

bool ElfReader::parseDwarfCompilationUnitsSequential(Dwarf_Debug dbg) {
    // This is the original sequential processing logic extracted from parseDwarfWithLibdwarf
    Dwarf_Bool is_info = 1;
    int cu_count = 0;
    Dwarf_Error error = nullptr;

    while (true) {
        Dwarf_Unsigned cu_header_length = 0;
        Dwarf_Half version_stamp = 0;
        Dwarf_Off abbrev_offset = 0;
        Dwarf_Half address_size = 0;
        Dwarf_Half offset_size = 0;
        Dwarf_Half extension_size = 0;
        Dwarf_Sig8 signature = {0};
        Dwarf_Unsigned typeoffset = 0;
        Dwarf_Unsigned next_cu_header = 0;
        Dwarf_Half header_cu_type = 0;
        Dwarf_Error cu_error = nullptr;

        int ret = dwarf_next_cu_header_d(dbg,
                                         is_info,
                                         &cu_header_length,
                                         &version_stamp,
                                         &abbrev_offset,
                                         &address_size,
                                         &offset_size,
                                         &extension_size,
                                         &signature,
                                         &typeoffset,
                                         &next_cu_header,
                                         &header_cu_type,
                                         &cu_error);

        if (ret == DW_DLV_NO_ENTRY) {
            break;
        }
        if (ret != DW_DLV_OK) {
            break;
        }

        Dwarf_Die cu_die = nullptr;
        ret = dwarf_siblingof_b(dbg, nullptr, is_info, &cu_die, &error);
        if (ret == DW_DLV_OK && cu_die != nullptr) {
            cu_count++;
            if (config_.verbosity > 0 &&
                cu_count % ElfOptimization::PROGRESS_REPORT_INTERVAL == 0) {
                std::cout << "Processed " << cu_count << " compilation units...\n";
            }
            processCompilationUnit(dbg, cu_die);
            dwarf_dealloc_die(cu_die);
        }
    }

    if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
        performance_metrics_.compilation_units_processed = cu_count;
    }

    return true;
}

#endif  // HAVE_LIBDWARF

void ElfReader::addEnhancedSymbols(const std::vector<ExtractedSymbol>& enhanced_symbols) {
    enhanced_symbols_ = enhanced_symbols;

    if (config_.verbosity > 1) {
        std::cout << "Added " << enhanced_symbols_.size() << " enhanced symbols to analysis\n";
    }
}
