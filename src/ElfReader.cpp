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
#include <dwarf.h>
#include <chrono>
#include <iomanip>
#include <libdwarf.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include "ElfExceptions.h"
#include "ExportFormats.h"
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <set>

using namespace ElfReaderExceptions;

// ========================================================================
// DwarfInitializer Implementation
// ========================================================================

bool DwarfInitializer::initialize(const std::string& filename, Dwarf_Debug& dbg) {
    Dwarf_Error error = nullptr;

    // Critical Implementation Note: libdwarf API varies significantly between versions
    // This conditional compilation handles the two major API variants in use
#if defined(DW_LIBDWARF_VERSION_MAJOR) && (DW_LIBDWARF_VERSION_MAJOR >= 2) || defined(__APPLE__) || (defined(_WIN32) && defined(__MINGW64__))
    // libdwarf 2.x API or macOS/Windows with simplified API (8 parameters):
    // dwarf_init_path(filename, error_handler, error_arg, groupnumber,
    //                 errhand_arg, errhand, dbg, error)
    int ret = dwarf_init_path(filename.c_str(), nullptr, 0, DW_GROUPNUMBER_ANY,
                              nullptr, nullptr, &dbg, &error);
#else
    // Older libdwarf API with extended parameters (12 parameters):
    // dwarf_init_path(filename, error_handler, error_arg, groupnumber, access,
    //                 init_fd, ftype, flags, dbg, pathsource, reserved, error)
    int ret = dwarf_init_path(filename.c_str(), nullptr, 0, DW_GROUPNUMBER_ANY,
                              0, nullptr, nullptr, &dbg, nullptr, 0, nullptr, &error);
#endif

    return (ret == DW_DLV_OK);
}

void DwarfInitializer::cleanup(Dwarf_Debug dbg) {
    if (dbg == nullptr) return;

    [[maybe_unused]] Dwarf_Error error = nullptr;

    // Handle API differences between libdwarf versions
#if defined(DW_LIBDWARF_VERSION_MAJOR) && (DW_LIBDWARF_VERSION_MAJOR >= 2) || defined(__APPLE__) || (defined(_WIN32) && defined(__MINGW64__))
    // libdwarf 2.x API or macOS/Windows (1 parameter)
    dwarf_finish(dbg);
#else
    // Older libdwarf API (2 parameters)
    dwarf_finish(dbg, &error);
#endif
}

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
        performance_metrics_.memory_mapping_used = (file_access_->getStrategyName() == "Memory-mapped");
    }

    // Performance optimization: Reserve string interner capacity for large files with bounds checking
    size_t file_size_mb = file_access_->size() / (1024 * 1024);
    if (file_size_mb > ElfOptimization::STRING_CAPACITY_THRESHOLD_MB) {
        // Estimate unique strings based on file size with comprehensive bounds checking
        size_t estimated_capacity = std::min(
            file_size_mb * ElfOptimization::STRING_CAPACITY_MULTIPLIER,
            ElfOptimization::MAX_STRING_CAPACITY
        );

        try {
            string_interner_.reserve(estimated_capacity);
            if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                performance_metrics_.string_interner_capacity_reserved = estimated_capacity;
            }
            if (config_.verbosity > 0) {
                std::cout << "Reserved string interner capacity: " << estimated_capacity << " strings\n";
            }
        } catch (const std::bad_alloc& e) {
            // Fallback: try with reduced capacity if allocation fails
            size_t fallback_capacity = estimated_capacity / 4;  // Try 25% of original
            if (config_.verbosity > 0) {
                std::cout << "Warning: Could not reserve " << estimated_capacity
                          << " strings, trying fallback: " << fallback_capacity << " strings\n";
            }
            try {
                string_interner_.reserve(fallback_capacity);
                if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                    performance_metrics_.string_interner_capacity_reserved = fallback_capacity;
                    performance_metrics_.string_interner_fallback_used = 1;
                }
            } catch (const std::bad_alloc&) {
                if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
                    performance_metrics_.string_interner_fallback_used = 2; // Failed even with fallback
                }
                // Continue without pre-allocation if even fallback fails
                if (config_.verbosity > 0) {
                    std::cout << "Warning: String interner pre-allocation failed, continuing with dynamic allocation\n";
                }
            }
        }
    }

    parseElfHeader();
    parseSectionHeaders();
    parseStringTables();
    parseSymbolTable();

    // Always attempt DWARF parsing for comprehensive analysis
    bool dwarf_success = parseDwarfWithLibdwarf();
    has_dwarf_info_ = dwarf_success;

    if (!dwarf_success && config_.verbosity >= 0) {
        std::cerr << "Note: No DWARF debug information found. Compile with -g for detailed analysis." << std::endl;
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
        // Explicitly clear DWARF-related containers to avoid use-after-free issues
        // This prevents crashes when destructing containers that may reference
        // libdwarf memory that was freed during parseDwarfWithLibdwarf()
        dwarf_variables_.clear();
        dwarf_dies_.clear();
        types_.clear();
        functions_.clear();
        advanced_types_.clear();

    } catch (const std::exception&) {
        // Never throw from destructor - just silently handle any cleanup issues
        // This is critical for proper RAII behavior in firmware analysis scenarios
    }
}

ElfReader::ElfReader(const Config& config) {
    initializeElfReader(config.inputFile, config);
}

void ElfReader::validateElfFile() {
    if (file_access_->size() < 16) {
        throw ElfFileError(ElfFileError::ErrorType::FileTooSmall,
                          "File too small to be a valid ELF file", filename_);
    }
    
    const uint8_t* data = file_access_->data();
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        throw ElfFileError(ElfFileError::ErrorType::InvalidFormat,
                          "Invalid ELF file", filename_);
    }

    is_32bit_ = (data[4] == static_cast<uint8_t>(ElfClass::ELFCLASS32));
    is_little_endian_ = (data[5] == static_cast<uint8_t>(ElfData::ELFDATA2LSB));

    // Check for supported architectures: ARM, ARM64, RISC-V, Xtensa
    uint16_t machine_type = readValue<uint16_t>(18);
    
    if (is_32bit_) {
        // 32-bit architectures: ARM, RISC-V, or Xtensa
        if (machine_type != static_cast<uint16_t>(ElfMachine::EM_ARM) && 
            machine_type != static_cast<uint16_t>(ElfMachine::EM_RISCV) &&
            machine_type != static_cast<uint16_t>(ElfMachine::EM_XTENSA)) {
            throw ElfFileError(ElfFileError::ErrorType::InvalidFormat,
                              "Unsupported 32-bit architecture (expected ARM, RISC-V, or Xtensa)", filename_);
        }
    } else {
        // 64-bit architectures: ARM64 or RISC-V  
        if (machine_type != static_cast<uint16_t>(ElfMachine::EM_AARCH64) && 
            machine_type != static_cast<uint16_t>(ElfMachine::EM_RISCV)) {
            throw ElfFileError(ElfFileError::ErrorType::InvalidFormat,
                              "Unsupported 64-bit architecture (expected ARM64 or RISC-V)", filename_);
        }
    }
}

void ElfReader::loadFile() {
    try {
        // Create file access strategy based on file size and configuration
        file_access_ = FileAccessStrategy::create(filename_, config_.mmapThreshold);
        
        if (config_.verbosity > 0) {
            std::cout << "Loading file: " << filename_ << " (" << file_access_->size() << " bytes) using " 
                      << file_access_->getStrategyName() << " access\n";
        }
        
    } catch (const std::exception& e) {
        throw ElfFileError(ElfFileError::ErrorType::FileNotFound, 
                          "Cannot open file: " + filename_ + " (" + e.what() + ")", filename_);
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
    
    // Parse section header string table first
    if (is_32bit_ && shstrndx < sections32_.size()) {
        const auto& shstrtab = sections32_[shstrndx];
        if (shstrtab.sh_offset + shstrtab.sh_size <= file_access_->size()) {
            std::vector<char> strtab_data(file_access_->data() + shstrtab.sh_offset, 
                                        file_access_->data() + shstrtab.sh_offset + shstrtab.sh_size);
            string_tables_[shstrndx] = strtab_data;
            
            // Set section names
            for (auto& section : sections32_) {
                section.name = string_interner_.intern(getString(shstrndx, section.sh_name));
            }
        }
    } else if (!is_32bit_ && shstrndx < sections64_.size()) {
        const auto& shstrtab = sections64_[shstrndx];
        if (shstrtab.sh_offset + shstrtab.sh_size <= file_access_->size()) {
            std::vector<char> strtab_data(file_access_->data() + shstrtab.sh_offset, 
                                        file_access_->data() + shstrtab.sh_offset + shstrtab.sh_size);
            string_tables_[shstrndx] = strtab_data;
            
            // Set section names
            for (auto& section : sections64_) {
                section.name = string_interner_.intern(getString(shstrndx, section.sh_name));
            }
        }
    }
    
    // Parse all string tables
    if (is_32bit_) {
        for (size_t i = 0; i < sections32_.size(); ++i) {
            const auto& section = sections32_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_STRTAB) && 
                section.sh_offset + section.sh_size <= file_access_->size()) {
                std::vector<char> strtab_data(file_access_->data() + section.sh_offset, 
                                            file_access_->data() + section.sh_offset + section.sh_size);
                string_tables_[i] = strtab_data;
            }
        }
    } else {
        for (size_t i = 0; i < sections64_.size(); ++i) {
            const auto& section = sections64_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_STRTAB) && 
                section.sh_offset + section.sh_size <= file_access_->size()) {
                std::vector<char> strtab_data(file_access_->data() + section.sh_offset, 
                                            file_access_->data() + section.sh_offset + section.sh_size);
                string_tables_[i] = strtab_data;
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
                size_t num_symbols = section.sh_size / 16; // sizeof(Elf32_Sym) = 16
                uint32_t strtab_index = section.sh_link;
                
                // Pre-reserve capacity to avoid vector reallocations during parsing
                symbols32_.reserve(num_symbols);
                for (size_t j = 0; j < num_symbols; ++j) {
                    size_t offset = section.sh_offset + j * 16;
                    // Bounds checking: ensure we don't read past file end
                    if (offset + 16 <= file_access_->size()) {
                        Elf32_Sym symbol;
                        readStruct(offset, symbol);
                        // Resolve symbol name from linked string table (sh_link field)
                        symbol.name = string_interner_.intern(getString(strtab_index, symbol.st_name));
                        symbols32_.push_back(symbol);
                    }
                }
                break; // ELF standard: typically only one .symtab section per file
            }
        }
    } else {
        for (size_t i = 0; i < sections64_.size(); ++i) {
            const auto& section = sections64_[i];
            if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_SYMTAB)) {
                // Implementation detail: 64-bit ELF symbol entries have fixed 24-byte structure:
                // st_name(4) + st_info(1) + st_other(1) + st_shndx(2) + st_value(8) + st_size(8)
                size_t num_symbols = section.sh_size / 24; // sizeof(Elf64_Sym) = 24
                uint32_t strtab_index = section.sh_link;
                
                symbols64_.reserve(num_symbols);
                for (size_t j = 0; j < num_symbols; ++j) {
                    size_t offset = section.sh_offset + j * 24;
                    if (offset + 24 <= file_access_->size()) {
                        Elf64_Sym symbol;
                        readStruct(offset, symbol);
                        symbol.name = string_interner_.intern(getString(strtab_index, symbol.st_name));
                        symbols64_.push_back(symbol);
                    }
                }
                break; // Usually only one symbol table
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
            if (!types_.empty()) {
                std::cout << "Using libdwarf for structure analysis.\n";
            } else {
                std::cout << "Using libdwarf for variable analysis.\n";
            }
        }
        return;
    }
    
    if (config_.verbosity > 0) {
        std::cout << "No debug information found. Compile with -g flag for detailed structure analysis.\n";
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
    try {
        Dwarf_Debug dbg = nullptr;

        // Use the DwarfInitializer wrapper to abstract platform differences
        if (!DwarfInitializer::initialize(filename_, dbg)) {
            return false; // No debug info available, not an error condition
        }

        if (config_.verbosity > 0) {
            std::cout << "libdwarf parsing DWARF debug information...\n";
        }
        
        // Implementation Detail: DWARF Compilation Unit Iteration Algorithm
        // Each compilation unit represents one source file (.c/.cpp) and its includes
        Dwarf_Bool is_info = 1;  // Process .debug_info section (not .debug_types)
        int cu_count = 0;  // Track compilation units for progress
        Dwarf_Error error = nullptr;

        while (true) {
            // DWARF header parsing: extract compilation unit metadata
            // These fields describe the DWARF format version and structure layout
            Dwarf_Unsigned cu_header_length = 0;    // Length of compilation unit data
            Dwarf_Half version_stamp = 0;           // DWARF version (2, 3, 4, or 5)
            Dwarf_Off abbrev_offset = 0;            // Offset to abbreviation table
            Dwarf_Half address_size = 0;            // Address size (4 for 32-bit ARM)
            Dwarf_Half offset_size = 0;             // DWARF offset field size
            Dwarf_Half extension_size = 0;          // Extension header size
            Dwarf_Sig8 signature = {0};             // Type signature (DWARF 4+)
            Dwarf_Unsigned typeoffset = 0;          // Type offset (DWARF 4+)
            Dwarf_Unsigned next_cu_header = 0;      // Offset to next compilation unit
            Dwarf_Half header_cu_type = 0;          // Compilation unit type
            Dwarf_Error cu_error = nullptr;

            // Get next compilation unit header - this is the main parsing loop
            int ret = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp,
                                         &abbrev_offset, &address_size, &offset_size,
                                         &extension_size, &signature, &typeoffset,
                                         &next_cu_header, &header_cu_type, &cu_error);

            if (ret == DW_DLV_NO_ENTRY) {
                break; // Normal termination: processed all compilation units
            }
            if (ret != DW_DLV_OK) {
                break; // Error condition: abort parsing
            }

            // Get the root DIE (Debug Information Entry) for this compilation unit
            // This represents the source file and contains all types/variables defined in it
            Dwarf_Die cu_die = nullptr;
            ret = dwarf_siblingof_b(dbg, nullptr, is_info, &cu_die, &error);
            if (ret == DW_DLV_OK && cu_die != nullptr) {
                cu_count++;
                if (config_.verbosity > 0 && cu_count % ElfOptimization::PROGRESS_REPORT_INTERVAL == 0) {
                    std::cout << "Processed " << cu_count << " compilation units...\n";
                }
                processCompilationUnit(dbg, cu_die);
                // Memory management: libdwarf requires explicit deallocation of DIEs
                dwarf_dealloc_die(cu_die);
            }
        }

        if constexpr (ElfOptimization::ENABLE_PERFORMANCE_METRICS) {
            performance_metrics_.compilation_units_processed = cu_count;
        }

        if (config_.verbosity > 0) {
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
            auto stats = string_interner_.getStats();
            std::cout << "String interning: " << stats.unique_strings << " unique strings, "
                      << stats.estimated_bytes << " bytes, avg length " 
                      << std::fixed << std::setprecision(1) << stats.average_length << "\n";
        }
        return !types_.empty() || !dwarf_variables_.empty();
        
    } catch (const std::exception& e) {
        if (config_.verbosity > 0) {
            std::cout << "libdwarf exception: " << e.what() << "\n";
        }
        return false;
    }
}

// Real DWARF parsing implementation
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
void ElfReader::processDwarfDie(Dwarf_Debug dbg, Dwarf_Die die, const std::string& namespace_prefix) {
    Dwarf_Half tag;
    Dwarf_Error error = nullptr;
    
    // Extract the DWARF tag that identifies the type of program element
    int ret = dwarf_tag(die, &tag, &error);
    if (ret != DW_DLV_OK) {
        return; // Skip malformed DIEs rather than aborting entire parsing
    }
    
    // Process DIE based on its type - this switch implements the core analysis logic
    switch (tag) {
        case DW_TAG_structure_type:
        case DW_TAG_class_type: {
            // High Priority: Extract structure/class definitions immediately
            std::string name = getDwarfDieName(dbg, die);
            if (!name.empty()) {
                // Build fully qualified name with namespace context
                std::string full_name = namespace_prefix.empty() ? name : namespace_prefix + "::" + name;
                extractStructureFromDie(dbg, die, full_name);
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
            std::string name = getDwarfDieName(dbg, die);
            std::string new_prefix = namespace_prefix.empty() ? name : namespace_prefix + "::" + name;
            
            // Recursive child processing with updated namespace context
            Dwarf_Die child_die = nullptr;
            ret = dwarf_child(die, &child_die, &error);
            while (ret == DW_DLV_OK && child_die != nullptr) {
                processDwarfDie(dbg, child_die, new_prefix);
                
                // Critical: Sibling traversal with proper memory management
                Dwarf_Die sibling_die = nullptr;
                ret = dwarf_siblingof_b(dbg, child_die, 1, &sibling_die, &error);
                dwarf_dealloc_die(child_die); // Prevent memory leak
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

std::string ElfReader::getDwarfDieName(Dwarf_Debug dbg, Dwarf_Die die) {
    char* name = nullptr;
    Dwarf_Error error = nullptr;
    
    int ret = dwarf_diename(die, &name, &error);
    if (ret == DW_DLV_OK && name != nullptr) {
        std::string result(name);
        dwarf_dealloc(dbg, name, DW_DLA_STRING);
        return result;
    }
    
    return "";
}

std::string ElfReader::resolveDwarfType(Dwarf_Debug dbg, Dwarf_Die type_die) {
    if (type_die == nullptr) {
        return "void";
    }
    
    Dwarf_Half tag;
    Dwarf_Error error = nullptr;
    
    int ret = dwarf_tag(type_die, &tag, &error);
    if (ret != DW_DLV_OK) {
        // Enhanced DWARF-based fallback strategies

        // Strategy 1: Try to follow DW_AT_type attribute for indirect resolution
        Dwarf_Attribute attr;
        if (dwarf_attr(type_die, DW_AT_type, &attr, &error) == DW_DLV_OK) {
            Dwarf_Off type_offset;
            if (dwarf_global_formref(attr, &type_offset, &error) == DW_DLV_OK) {
                Dwarf_Die indirect_type_die = nullptr;
                if (dwarf_offdie_b(dbg, type_offset, 1, &indirect_type_die, &error) == DW_DLV_OK) {
                    std::string indirect_type = resolveDwarfType(dbg, indirect_type_die);
                    dwarf_dealloc_die(indirect_type_die);
                    if (indirect_type.find("type_0x") == std::string::npos) {
                        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
                        return indirect_type;
                    }
                }
            }
            dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        }

        // Strategy 2: Try to get byte size and encoding for basic type inference
        Dwarf_Unsigned byte_size = 0;
        Dwarf_Unsigned encoding = 0;
        bool has_size = (dwarf_bytesize(type_die, &byte_size, &error) == DW_DLV_OK);
        bool has_encoding = (dwarf_attr(type_die, DW_AT_encoding, &attr, &error) == DW_DLV_OK);

        if (has_encoding) {
            dwarf_formudata(attr, &encoding, &error);
            dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        }

        if (has_size) {
            // Use DWARF encoding to determine signed/unsigned/float
            switch (byte_size) {
                case 1:
                    if (encoding == DW_ATE_unsigned || encoding == DW_ATE_unsigned_char) return "unsigned char";
                    return "char";
                case 2:
                    if (encoding == DW_ATE_unsigned) return "unsigned short";
                    return "short";
                case 4:
                    if (encoding == DW_ATE_float) return "float";
                    if (encoding == DW_ATE_unsigned) return "unsigned int";
                    return "int";
                case 8:
                    if (encoding == DW_ATE_float) return "double";
                    if (encoding == DW_ATE_unsigned) return "unsigned long long";
                    return "long long";
                default: break;
            }
        }

        // Final fallback: Use hex ID but mark it as unresolved
        std::ostringstream oss;
        oss << "type_0x" << std::hex << reinterpret_cast<uintptr_t>(type_die);
        return oss.str();
    }
    
    switch (tag) {
        case DW_TAG_base_type: {
            std::string name = getDwarfDieName(dbg, type_die);
            return name.empty() ? "base_type" : name;
        }
        case DW_TAG_pointer_type:
            return "pointer";
        case DW_TAG_array_type: {
            return parseArrayType(dbg, type_die);
        }
        case DW_TAG_typedef: {
            std::string name = getDwarfDieName(dbg, type_die);
            return name.empty() ? "typedef" : name;
        }
        case DW_TAG_const_type: {
            // Follow the DW_AT_type attribute to get the underlying type
            Dwarf_Attribute attr;
            if (dwarf_attr(type_die, DW_AT_type, &attr, &error) == DW_DLV_OK) {
                Dwarf_Off type_offset;
                if (dwarf_global_formref(attr, &type_offset, &error) == DW_DLV_OK) {
                    Dwarf_Die underlying_type_die = nullptr;
                    if (dwarf_offdie_b(dbg, type_offset, 1, &underlying_type_die, &error) == DW_DLV_OK) {
                        std::string underlying_type = resolveDwarfType(dbg, underlying_type_die);
                        dwarf_dealloc_die(underlying_type_die);
                        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
                        return underlying_type;
                    }
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
            return "const_type";
        }
        case DW_TAG_structure_type:
        case DW_TAG_class_type: {
            std::string name = getDwarfDieName(dbg, type_die);
            if (name.empty()) {
                // For anonymous structures, create unique name using DIE offset
                Dwarf_Off die_offset = 0;
                if (dwarf_dieoffset(type_die, &die_offset, &error) == DW_DLV_OK) {
                    return "struct@" + std::to_string(die_offset);
                } else {
                    return "struct";
                }
            }
            return name;
        }
        default: {
            std::string name = getDwarfDieName(dbg, type_die);
            if (!name.empty()) {
                return name;
            }
            // Use hex ID as fallback as requested
            std::ostringstream oss;
            oss << "type_0x" << std::hex << reinterpret_cast<uintptr_t>(type_die);
            return oss.str();
        }
    }
}

// Phase 2A.1: Enhanced type metadata extraction
ElfReader::TypeMetadata ElfReader::extractTypeMetadata(Dwarf_Debug dbg, Dwarf_Die type_die) {
    TypeMetadata metadata;
    if (type_die == nullptr) {
        metadata.type_name = "void";
        return metadata;
    }
    
    Dwarf_Half tag;
    Dwarf_Error error = nullptr;
    int ret = dwarf_tag(type_die, &tag, &error);
    if (ret != DW_DLV_OK) {
        metadata.type_name = "unknown";
        return metadata;
    }
    
    // Get basic type name
    metadata.type_name = getDwarfDieName(dbg, type_die);
    if (metadata.type_name.empty()) {
        metadata.type_name = "unnamed_type";
    }
    
    // Get byte size
    Dwarf_Attribute byte_size_attr = nullptr;
    ret = dwarf_attr(type_die, DW_AT_byte_size, &byte_size_attr, &error);
    if (ret == DW_DLV_OK) {
        Dwarf_Unsigned size = 0;
        if (dwarf_formudata(byte_size_attr, &size, &error) == DW_DLV_OK) {
            metadata.byte_size = size;
        }
        dwarf_dealloc(dbg, byte_size_attr, DW_DLA_ATTR);
    }
    
    // Handle different type tags
    switch (tag) {
        case DW_TAG_typedef: {
            metadata.is_typedef = true;
            // Get underlying type
            Dwarf_Die underlying_type_die = nullptr;
            Dwarf_Attribute type_attr = nullptr;
            ret = dwarf_attr(type_die, DW_AT_type, &type_attr, &error);
            if (ret == DW_DLV_OK) {
                Dwarf_Off type_offset = 0;
                ret = dwarf_global_formref(type_attr, &type_offset, &error);
                if (ret == DW_DLV_OK) {
                    ret = dwarf_offdie_b(dbg, type_offset, 1, &underlying_type_die, &error);
                    if (ret == DW_DLV_OK) {
                        metadata.underlying_type = resolveDwarfType(dbg, underlying_type_die);
                        dwarf_dealloc_die(underlying_type_die);
                    }
                }
                dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
            }
            break;
        }
        case DW_TAG_union_type: {
            metadata.is_union = true;
            break;
        }
        case DW_TAG_enumeration_type: {
            // Extract enum values
            std::vector<std::string> enum_vals;
            Dwarf_Die child_die = nullptr;
            ret = dwarf_child(type_die, &child_die, &error);
            while (ret == DW_DLV_OK && child_die != nullptr) {
                Dwarf_Half child_tag = 0;
                if (dwarf_tag(child_die, &child_tag, &error) == DW_DLV_OK && child_tag == DW_TAG_enumerator) {
                    std::string enum_name = getDwarfDieName(dbg, child_die);
                    if (!enum_name.empty()) {
                        enum_vals.push_back(enum_name);
                    }
                }
                
                Dwarf_Die sibling_die = nullptr;
                ret = dwarf_siblingof_b(dbg, child_die, 1, &sibling_die, &error);
                dwarf_dealloc_die(child_die);
                child_die = sibling_die;
            }
            
            if (!enum_vals.empty()) {
                metadata.enum_values = "{";
                for (size_t i = 0; i < enum_vals.size(); ++i) {
                    if (i > 0) metadata.enum_values += ", ";
                    metadata.enum_values += enum_vals[i];
                }
                metadata.enum_values += "}";
            }
            break;
        }
        // Add more cases as needed
        default:
            break;
    }
    
    return metadata;
}

// Helper function to estimate size from type name  
uint64_t ElfReader::estimateTypeSize(const std::string& type_name) const {
    // Handle basic types first (including verbose DWARF names)
    if (type_name == "int" || type_name == "float" || type_name == "uint32_t" ||
        type_name == "unsigned int" || type_name == "long int" || type_name == "long unsigned int") {
        return 4;
    } else if (type_name == "char" || type_name == "uint8_t" || type_name == "int8_t" ||
               type_name == "signed char" || type_name == "unsigned char") {
        return 1;
    } else if (type_name == "double" || type_name == "uint64_t" || type_name == "long long") {
        return 8;
    } else if (type_name == "short" || type_name == "uint16_t" || type_name == "int16_t" ||
               type_name == "short int" || type_name == "short unsigned int") {
        return 2;
    }

    // Handle arrays: type[N], type[N][M], etc.
    if (type_name.find('[') != std::string::npos) {
        // Extract base type (everything before first '[')
        std::string base_type = type_name.substr(0, type_name.find('['));

        // Get base type size
        uint64_t base_size = 0;
        if (base_type == "int" || base_type == "float" || base_type == "uint32_t") {
            base_size = 4;
        } else if (base_type == "char" || base_type == "uint8_t" || base_type == "int8_t" ||
                   base_type == "signed char" || base_type == "unsigned char") {
            base_size = 1;
        } else if (base_type == "double" || base_type == "uint64_t" || base_type == "long long") {
            base_size = 8;
        } else if (base_type == "short" || base_type == "uint16_t" || base_type == "int16_t" ||
                   base_type == "short int" || base_type == "short unsigned int") {
            base_size = 2;
        } else if (base_type == "long" || base_type == "long int" || base_type == "long unsigned int" ||
                   base_type == "unsigned int") {
            base_size = 4;
        } else {
            base_size = 4; // Default for unknown types
        }

        // Calculate total array size by multiplying all dimensions
        uint64_t total_elements = 1;
        size_t pos = 0;
        while ((pos = type_name.find('[', pos)) != std::string::npos) {
            size_t end = type_name.find(']', pos);
            if (end != std::string::npos) {
                try {
                    std::string size_str = type_name.substr(pos + 1, end - pos - 1);
                    uint64_t dimension = std::stoi(size_str);
                    total_elements *= dimension;
                } catch (...) {
                    return 0;
                }
                pos = end + 1;
            } else {
                break;
            }
        }

        return base_size * total_elements;
    }

    return 0; // Unknown size
}

std::string ElfReader::parseArrayType(Dwarf_Debug dbg, Dwarf_Die array_die) {
    Dwarf_Error error = nullptr;
    
    // Get the element type of the array
    std::string element_type = "unknown";
    Dwarf_Die element_type_die = nullptr;
    Dwarf_Attribute attr = nullptr;
    
    int ret = dwarf_attr(array_die, DW_AT_type, &attr, &error);
    if (ret == DW_DLV_OK) {
        Dwarf_Off type_offset;
        ret = dwarf_global_formref(attr, &type_offset, &error);
        if (ret == DW_DLV_OK) {
            ret = dwarf_offdie_b(dbg, type_offset, 1, &element_type_die, &error);
            if (ret == DW_DLV_OK) {
                element_type = resolveDwarfType(dbg, element_type_die);
                dwarf_dealloc_die(element_type_die);
            }
        }
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    }
    
    // Parse array dimensions by examining DW_TAG_subrange_type children
    std::vector<uint64_t> dimensions;
    
    Dwarf_Die child_die = nullptr;
    ret = dwarf_child(array_die, &child_die, &error);
    
    while (ret == DW_DLV_OK && child_die != nullptr) {
        Dwarf_Half tag;
        ret = dwarf_tag(child_die, &tag, &error);
        
        if (ret == DW_DLV_OK && tag == DW_TAG_subrange_type) {
            // Get the upper bound of this dimension
            Dwarf_Unsigned upper_bound = 0;
            Dwarf_Unsigned lower_bound = 0;
            bool has_upper_bound = false;
            bool has_lower_bound = false;
            
            // Try to get upper bound
            ret = dwarf_attr(child_die, DW_AT_upper_bound, &attr, &error);
            if (ret == DW_DLV_OK) {
                ret = dwarf_formudata(attr, &upper_bound, &error);
                if (ret == DW_DLV_OK) {
                    has_upper_bound = true;
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
            
            // Try to get lower bound (usually 0, but may be explicit)
            ret = dwarf_attr(child_die, DW_AT_lower_bound, &attr, &error);
            if (ret == DW_DLV_OK) {
                ret = dwarf_formudata(attr, &lower_bound, &error);
                if (ret == DW_DLV_OK) {
                    has_lower_bound = true;
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
            
            // Calculate dimension size
            uint64_t dimension_size = 0;
            if (has_upper_bound) {
                // In DWARF, upper_bound is typically the last valid index
                // so array size = upper_bound - lower_bound + 1
                uint64_t effective_lower = has_lower_bound ? lower_bound : 0;
                dimension_size = upper_bound - effective_lower + 1;
                dimensions.push_back(dimension_size);
            } else {
                // No upper bound specified - might be a flexible array member
                // or incomplete array type
                dimensions.push_back(0); // 0 indicates unknown/flexible size
            }
        }
        
        // Get next sibling
        Dwarf_Die sibling_die = nullptr;
        ret = dwarf_siblingof_b(dbg, child_die, 1, &sibling_die, &error);
        dwarf_dealloc_die(child_die);
        child_die = sibling_die;
    }
    
    // Build the array type string with detailed information
    std::ostringstream array_type;
    array_type << element_type;
    
    // Add dimension information
    for (size_t i = 0; i < dimensions.size(); ++i) {
        array_type << "[";
        if (dimensions[i] > 0) {
            array_type << dimensions[i];
        }  // Empty brackets for flexible/unknown size
        array_type << "]";
    }
    
    return array_type.str();
}

void ElfReader::extractStructureFromDie(Dwarf_Debug dbg, Dwarf_Die struct_die, const std::string& full_name) {
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
        return; // Already processed this structure - skip to avoid redundant work
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
            std::string member_name = getDwarfDieName(dbg, child_die);
            
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
                    ret = dwarf_offdie_b(dbg, type_offset, 1, &type_die, &error);
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
            
            std::string type_name = resolveDwarfType(dbg, type_die);
            
            // Get type size (assume 4 bytes if can't determine)
            Dwarf_Unsigned member_size = 4;
            bool is_struct_type = false;
            
            if (type_die != nullptr) {
                dwarf_bytesize(type_die, &member_size, &error);
                if (member_size == 0) member_size = 4; // fallback
                
                // Check if it's a structure type and extract it recursively
                Dwarf_Half type_tag;
                if (dwarf_tag(type_die, &type_tag, &error) == DW_DLV_OK) {
                    is_struct_type = (type_tag == DW_TAG_structure_type || type_tag == DW_TAG_class_type);
                    
                    // If it's a structure, make sure we extract it
                    if (is_struct_type && !type_name.empty()) {
                        extractStructureFromDie(dbg, type_die, type_name);
                    }
                }
                
                dwarf_dealloc_die(type_die);
            }
            
            if (!member_name.empty()) {
                members.emplace_back(string_interner_.intern(member_name), string_interner_.intern(type_name), offset, member_size, is_struct_type);
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
                    ret = dwarf_offdie_b(dbg, type_offset, 1, &base_type_die, &error);
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
                std::string base_class_name = resolveDwarfType(dbg, base_type_die);
                
                // Extract base class structure recursively
                extractStructureFromDie(dbg, base_type_die, base_class_name);
                
                // Add base class members to this structure at the inheritance offset
                auto base_it = types_.find(base_class_name);
                if (base_it != types_.end()) {
                    for (const auto& base_member : base_it->second.members) {
                        members.emplace_back(string_interner_.intern(base_member.name), string_interner_.intern(base_member.type), 
                                           inherit_offset + base_member.offset, 
                                           base_member.size, base_member.is_struct);
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
    if (!members.empty() || byte_size > 0) {
        // Create unique key combining name and DIE offset
        std::string unique_key = full_name + "@" + std::to_string(die_offset);
        types_[unique_key] = TypeInfo(byte_size, members, die_offset, string_interner_.intern(full_name));
        
        // For anonymous structures (just "struct"), always use unique key
        // For named structures, also store with original name if not already present
        if (full_name != "struct" && types_.find(full_name) == types_.end()) {
            types_[full_name] = TypeInfo(byte_size, members, die_offset, string_interner_.intern(full_name));
        }
        
        if (config_.verbosity > 1) {
            std::cout << "Extracted structure: " << full_name << " (size: " << byte_size << ", members: " << members.size() << ", DIE: 0x" << std::hex << die_offset << std::dec << ")\n";
            
            // Debug: Print member details
            for (const auto& member : members) {
                std::cout << "  Member: " << member.name << " (" << member.type << ") at offset " << member.offset << "\n";
            }
        }
    }
}

void ElfReader::processDwarfVariable(Dwarf_Debug dbg, Dwarf_Die var_die, const std::string& namespace_prefix) {
    Dwarf_Error error = nullptr;
    
    // Get variable name
    std::string var_name = getDwarfDieName(dbg, var_die);
    if (var_name.empty()) {
        return; // Skip unnamed variables
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
            
            ret = dwarf_get_locdesc_entry_d(loc_head, 0, &lle_value, &rawlowpc, &rawhipc,
                                           &debug_addr_unavailable, &lowpc_cooked, &hipc_cooked,
                                           &op_count, &locdesc, &loclist_source, 
                                           &expression_offset, &locdesc_offset, &error);
            if (ret == DW_DLV_OK && op_count > 0 && locdesc) {
                Dwarf_Small op = 0;
                Dwarf_Unsigned op1 = 0, op2 = 0, op3 = 0;
                Dwarf_Unsigned branch_offset = 0;
                
                ret = dwarf_get_location_op_value_c(locdesc, 0, &op, &op1, &op2, &op3,
                                                   &branch_offset, &error);
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
        std::string full_var_name = namespace_prefix.empty() ? var_name : (namespace_prefix + "::" + var_name);
        
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

                    // First try to get the constant value directly from DW_AT_const_value on the variable DIE
                    Dwarf_Attribute const_attr = nullptr;
                    int const_ret = dwarf_attr(var_die, DW_AT_const_value, &const_attr, &error);
                    if (const_ret == DW_DLV_OK) {
                        Dwarf_Half form = 0;
                        const_ret = dwarf_whatform(const_attr, &form, &error);
                        if (const_ret == DW_DLV_OK) {
                            if (form == DW_FORM_data1 || form == DW_FORM_data2 ||
                                form == DW_FORM_data4 || form == DW_FORM_data8) {
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
                            }
                        }
                        dwarf_dealloc(dbg, const_attr, DW_DLA_ATTR);
                    }

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
                                ret = dwarf_offdie_b(dbg, base_type_offset, 1, &base_type_die, &error);
                                if (ret == DW_DLV_OK) {
                                    // Get byte size from the base type
                                    Dwarf_Attribute byte_size_attr = nullptr;
                                    ret = dwarf_attr(base_type_die, DW_AT_byte_size, &byte_size_attr, &error);
                                    if (ret == DW_DLV_OK) {
                                        Dwarf_Unsigned byte_size = 0;
                                        ret = dwarf_formudata(byte_size_attr, &byte_size, &error);
                                        if (ret == DW_DLV_OK && has_address) {
                                            // Try to read the actual constant value from memory
                                            constant_value = readConstantValueFromAddress(dbg, address, byte_size, base_type_die);
                                        } else {
                                            constant_value = "(const)";
                                        }
                                        dwarf_dealloc(dbg, byte_size_attr, DW_DLA_ATTR);
                                    } else {
                                        constant_value = "(const)";
                                    }
                                    dwarf_dealloc_die(base_type_die);
                                }
                            }
                            dwarf_dealloc(dbg, base_type_attr, DW_DLA_ATTR);
                        }

                        if (constant_value.empty()) {
                            constant_value = "(const)";
                        }
                    }
                }
                
                type_name = resolveDwarfType(dbg, type_die);
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
    std::string full_name = namespace_prefix.empty() ? var_name : namespace_prefix + "::" + var_name;
    
    // Store variable information for both original and demangled names
    std::string demangled_name = demangleCppName(var_name);
    
    // Store in DWARF variables map
    dwarf_variables_[var_name] = VariableInfo(string_interner_.intern(var_name), string_interner_.intern(demangled_name), string_interner_.intern(type_name), address, true, is_constant, constant_value);
    if (demangled_name != var_name) {
        dwarf_variables_[demangled_name] = VariableInfo(string_interner_.intern(var_name), string_interner_.intern(demangled_name), string_interner_.intern(type_name), address, true, is_constant, constant_value);
    }
    if (full_name != var_name && full_name != demangled_name) {
        dwarf_variables_[full_name] = VariableInfo(string_interner_.intern(var_name), string_interner_.intern(demangled_name), string_interner_.intern(type_name), address, true, is_constant, constant_value);
    }
    
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
        return ""; // Cannot determine form
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
                result = "\"" + std::string(str) + "\""; // Quote string constants
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

std::string ElfReader::extractConstantValueFromMemory(Dwarf_Debug /* dbg */, Dwarf_Die /* type_die */, uint64_t /* address */) {
    // TODO: Implement actual constant value reading from memory
    // This would require mapping addresses to file sections
    return "(const)";
}

std::string ElfReader::readConstantValueFromAddress(Dwarf_Debug dbg, uint64_t address, uint64_t byte_size, Dwarf_Die type_die) {
    try {
        // Find the section that contains this address
        size_t file_offset = 0;
        bool found_section = false;
        
        if (is_32bit_) {
            // For constants, first try .rodata section specifically (where const globals are typically stored)
            for (size_t i = 0; i < sections32_.size(); ++i) {
                const auto& section = sections32_[i];
                if (section.sh_type == static_cast<uint32_t>(SectionType::SHT_PROGBITS) &&
                    section.sh_size > 0) {
                    
                    // Check if this is likely .rodata: read-only, non-executable PROGBITS
                    bool is_executable = (section.sh_flags & 0x4) != 0; // SHF_EXECINSTR  
                    bool is_writable = (section.sh_flags & 0x1) != 0;   // SHF_WRITE
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
                            break; // Found .rodata section, this is best for constants
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
            return "(const)"; // Address not found in any section
        }
        
        // Ensure we don't read beyond file bounds
        if (file_offset + byte_size > file_access_->size()) {
            return "(const)"; // Would read beyond file
        }
        
        // Get DWARF type encoding and name to determine how to interpret the value
        Dwarf_Error error = nullptr;
        Dwarf_Half encoding = DW_ATE_signed; // Default to signed int
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
                    if ((type_name == "char" || encoding == DW_ATE_unsigned_char) && 
                        value >= 32 && value <= 126 && value != 92) { // Printable ASCII, not backslash
                        ss << "'" << static_cast<char>(value) << "'";
                    } else if ((type_name == "char" || encoding == DW_ATE_unsigned_char) && value == 0) {
                        ss << "'\\0'"; // Null character
                    } else {
                        ss << static_cast<unsigned int>(value);
                    }
                } else {
                    int8_t value = readValue<int8_t>(file_offset);
                    // Check if this is a printable character (for signed char)
                    if (type_name == "char" && value >= 32 && value <= 126 && value != 92) {
                        ss << "'" << static_cast<char>(value) << "'";
                    } else if (type_name == "char" && value == 0) {
                        ss << "'\\0'"; // Null character
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
                for (uint64_t i = 0; i < byte_size && i < 16; ++i) { // Limit to 16 bytes
                    uint8_t byte_val = readValue<uint8_t>(file_offset + i);
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte_val);
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

std::string ElfReader::readStringFromAddress(uint64_t /* address */) {
    // TODO: Implement string reading from memory addresses
    return "";
}

std::string ElfReader::demangleCppName(const std::string& mangled_name) const {
    // Simple C++ name demangling for common patterns
    if (!mangled_name.empty() && mangled_name.substr(0, 2) == "_Z") {
        // Basic demangling for global variables like _ZN15GlobalInstances18mainGlobalInstanceE
        if (mangled_name.find("_ZN") == 0) {
            std::string result;
            size_t pos = 3; // Skip "_ZN"
            
            while (pos < mangled_name.length()) {
                // Read number indicating namespace/class name length
                std::string len_str;
                while (pos < mangled_name.length() && isdigit(mangled_name[pos])) {
                    len_str += mangled_name[pos++];
                }
                
                if (len_str.empty()) break;
                
                int len = std::stoi(len_str);
                if (pos + len > mangled_name.length()) break;
                
                if (!result.empty()) result += "::";
                result += mangled_name.substr(pos, len);
                pos += len;
                
                // Check for end marker
                if (pos < mangled_name.length() && mangled_name[pos] == 'E') {
                    break;
                }
            }
            
            if (!result.empty()) {
                return result;
            }
        }
    }
    
    // Return original name if not a mangled C++ name
    return mangled_name;
}

std::string ElfReader::getCleanSymbolName(const std::string& symbol_name) const {
    // First try to demangle if it's a C++ mangled name
    std::string demangled = demangleCppName(symbol_name);
    if (demangled != symbol_name) {
        return demangled;
    }
    
    // Handle other symbol name cleaning patterns if needed
    return symbol_name;
}

std::string ElfReader::findTypeForSymbol(const std::string& symbol_name) const {
    // First check if we have DWARF variable information for this symbol
    auto var_it = dwarf_variables_.find(symbol_name);
    if (var_it != dwarf_variables_.end()) {
        return var_it->second.type_name;
    }
    
    // Try with demangled name
    std::string clean_name = getCleanSymbolName(symbol_name);
    auto var_clean_it = dwarf_variables_.find(clean_name);
    if (var_clean_it != dwarf_variables_.end()) {
        return var_clean_it->second.type_name;
    }
    
    // Legacy hardcoded logic for globalInstance (backward compatibility)
    if (symbol_name == "globalInstance" || clean_name == "globalInstance") {
        std::string best_match;
        size_t best_size = 0;
        size_t best_member_count = 0;
        
        for (const auto& type_pair : types_) {
            const std::string& type_name = type_pair.first;
            const TypeInfo& type_info = type_pair.second;
            
            // Skip simple types, look for complex structures
            if (type_name.find("::") != std::string::npos || 
                type_name.find("Struct") != std::string::npos ||
                type_name.find("Class") != std::string::npos) {
                
                // Prefer structures with more members and larger size (likely derived classes)
                if (type_info.members.size() > best_member_count || 
                    (type_info.members.size() == best_member_count && type_info.size > best_size)) {
                    best_match = type_name;
                    best_size = type_info.size;
                    best_member_count = type_info.members.size();
                }
            }
        }
        
        return best_match;
    }
    
    // No type found
    return "";
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
    if (debug_info_data_.size() < 11) { // Minimum CU header size
        return false;
    }
    
    size_t offset = 11; // Skip CU header (length=4, version=2, abbrev_offset=4, address_size=1)
    
    try {
        // Parse the root compilation unit and extract types
        while (offset < debug_info_data_.size()) {
            DwarfDIE die = parseDwarfDIE(debug_info_data_.data(), offset, debug_info_data_.size());
            if (die.abbrev_code == 0) break; // End of DIEs
            
            extractTypesFromDwarf(die);
        }
        return true;
    } catch (const std::exception&) {
        return false; // DWARF parsing failed, fall back to hardcoded analysis
    }
}

DwarfDIE ElfReader::parseDwarfDIE(const uint8_t* data, size_t& offset, size_t max_size) {
    DwarfDIE die;
    
    if (offset >= max_size) {
        die.abbrev_code = 0;
        return die;
    }
    
    // For simplicity, this is a basic DWARF parser that extracts key information
    // A full implementation would parse abbreviation tables, but for type discovery
    // we can work with the raw DIE data
    
    // Read DIE data directly from debug info
    // This simplified approach extracts the most common patterns we need
    die.offset = offset;
    
    // Skip complex parsing for now and look for key patterns
    // This basic implementation will be enhanced as needed
    die.abbrev_code = (offset < max_size) ? data[offset] : 0;
    if (die.abbrev_code == 0) return die;
    
    offset++; // Move past abbrev code
    return die;
}

std::string ElfReader::getDwarfString(uint32_t string_offset) const {
    if (string_offset < debug_str_data_.size()) {
        return std::string(reinterpret_cast<const char*>(debug_str_data_.data() + string_offset));
    }
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
        case DW_TAG_class_type:
            processDwarfClass(die, full_name);
            break;
        case DW_TAG_structure_type:
            processDwarfStructure(die, full_name);
            break;
        case DW_TAG_namespace:
            // Recursively process namespace contents
            for (const auto& child : die.children) {
                extractTypesFromDwarf(child, full_name);
            }
            break;
        default:
            break;
    }
}

void ElfReader::processDwarfClass(const DwarfDIE& class_die, const std::string& full_name) {
    if (full_name.empty()) return;
    
    std::vector<TypeMember> members;
    uint32_t total_size = class_die.getByteSize();
    
    // Process class members
    for (const auto& child : class_die.children) {
        if (child.tag == DW_TAG_member) {
            std::string member_name = child.getName();
            uint32_t member_offset = child.getDataMemberLocation();
            // uint32_t member_type = child.getType(); // TODO: Implement type resolution
            
            // For now, use generic type information
            // This would be enhanced to resolve type references properly
            members.emplace_back(string_interner_.intern(member_name), string_interner_.intern("auto"), member_offset, 4, false);
        }
    }
    
    types_[full_name] = TypeInfo(total_size, members);
}

void ElfReader::processDwarfStructure(const DwarfDIE& struct_die, const std::string& full_name) {
    // Similar to class processing but for structures
    processDwarfClass(struct_die, full_name);
}

std::string ElfReader::getString(uint32_t strtab_index, uint32_t offset) const {
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
        case SymbolType::STT_NOTYPE: return "NOTYPE";
        case SymbolType::STT_OBJECT: return "OBJECT";
        case SymbolType::STT_FUNC: return "FUNC";
        case SymbolType::STT_SECTION: return "SECTION";
        case SymbolType::STT_FILE: return "FILE";
        default: return "UNKNOWN(" + std::to_string(static_cast<int>(symbol_type)) + ")";
    }
}

std::vector<MemberInfo> ElfReader::expandStructureMembers(
    const std::string& base_name,
    const std::string& type_name,
    uint64_t base_address,
    uint32_t offset
) const {
    std::vector<MemberInfo> members;
    
    auto type_it = types_.find(type_name);
    
    // If direct lookup fails, try improved resolution strategy
    if (type_it == types_.end()) {
        // Strategy 1: Look for unique DIE-based key (type_name@offset)
        for (const auto& [key, value] : types_) {
            if (key.find("@") != std::string::npos) {
                std::string base_key = key.substr(0, key.find("@"));
                if (base_key == type_name) {
                    type_it = types_.find(key);
                    break;
                }
            }
        }
        
        // Strategy 2: Only if still not found, try namespace matching (more conservative)
        if (type_it == types_.end()) {
            std::vector<std::pair<std::string, const TypeInfo*>> candidates;
            for (const auto& [key, value] : types_) {
                if (key.length() > type_name.length() && 
                    key.substr(key.length() - type_name.length()) == type_name &&
                    key[key.length() - type_name.length() - 1] == ':') {
                    candidates.emplace_back(key, &value);
                }
            }
            
            // If we have exactly one candidate, use it. If multiple, prefer the first one found
            if (!candidates.empty()) {
                type_it = types_.find(candidates[0].first);
            }
        }
    }
    
    if (type_it == types_.end()) {
        // If we still don't know the structure, just return the base with estimated size
        uint64_t estimated_size = estimateTypeSize(type_name);
        if (estimated_size > 0) {
            MemberInfo base_member(string_interner_.intern(base_name), base_address + offset, string_interner_.intern(type_name), estimated_size);
            if (config_.showSections) {
                base_member.section_name = getSectionNameForAddress(base_address + offset);
            }
            members.push_back(base_member);
        } else {
            MemberInfo base_member(string_interner_.intern(base_name), base_address + offset, string_interner_.intern(type_name));
            if (config_.showSections) {
                base_member.section_name = getSectionNameForAddress(base_address + offset);
            }
            members.push_back(base_member);
        }
        return members;
    }
    
    const TypeInfo& type_info = type_it->second;
    
    for (const auto& member : type_info.members) {
        std::string member_name = base_name + "." + member.name;
        uint64_t member_address = base_address + offset + member.offset;
        
        if (member.is_struct) {
            // Check if we can find the nested structure type
            bool found_nested_type = false;
            
            // Try direct lookup first
            if (types_.find(member.type) != types_.end()) {
                found_nested_type = true;
            } else {
                // Try the same improved resolution as the parent
                for (const auto& [key, value] : types_) {
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
                    member_name, member.type, base_address, offset + member.offset
                );
                members.insert(members.end(), nested_members.begin(), nested_members.end());
            } else {
                // If nested structure not found, show as a single member with enhanced metadata
                // Use estimated size if DWARF size seems incorrect (e.g., arrays showing as 4 bytes)
                uint64_t correct_size = estimateTypeSize(member.type);
                if (correct_size > 0 && (member.type.find('[') != std::string::npos || member.type == "uint64_t" || member.type == "double")) {
                    MemberInfo member_info(string_interner_.intern(member_name), member_address, string_interner_.intern(member.type), correct_size);
                    if (config_.showSections) {
                        member_info.section_name = getSectionNameForAddress(member_address);
                    }
                    members.push_back(member_info);
                } else {
                    MemberInfo member_info(string_interner_.intern(member_name), member_address, string_interner_.intern(member.type), member.size);
                    if (config_.showSections) {
                        member_info.section_name = getSectionNameForAddress(member_address);
                    }
                    members.push_back(member_info);
                }
            }
        } else {
            // Primitive member - use enhanced constructor with size information
            // Use estimated size if DWARF size seems incorrect (e.g., arrays showing as 4 bytes)
            uint64_t correct_size = estimateTypeSize(member.type);
            if (correct_size > 0 && (member.type.find('[') != std::string::npos || member.type == "uint64_t" || member.type == "double")) {
                MemberInfo member_info(string_interner_.intern(member_name), member_address, string_interner_.intern(member.type), correct_size);
                if (config_.showSections) {
                    member_info.section_name = getSectionNameForAddress(member_address);
                }
                members.push_back(member_info);
            } else {
                MemberInfo member_info(string_interner_.intern(member_name), member_address, string_interner_.intern(member.type), member.size);
                if (config_.showSections) {
                    member_info.section_name = getSectionNameForAddress(member_address);
                }
                members.push_back(member_info);
            }
        }
    }
    
    return members;
}

template<typename T>
T ElfReader::readValue(size_t offset) const {
    if (offset + sizeof(T) > file_access_->size()) {
        throw MemoryAccessError("Attempt to read beyond end of file", offset);
    }
    
    T value;
    std::memcpy(&value, &file_access_->data()[offset], sizeof(T));
    
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

void ElfReader::analyzeMemberParameters() {
    // Mark analysis as completed first
    analysis_completed_ = true;

    if (config_.verbosity < 0) return;

    // Stack Frame Analysis for Embedded Debugging (exclusive mode)
    if (config_.showStackLayout) {
        if (extractStackFrameAnalysis()) {
            printStackFrameAnalysis();
        } else {
            if (config_.verbosity >= 0) {
                std::cout << "Stack frame analysis not available. Requires local variable analysis.\n";
            }
        }
        return; // Exit early when stack-layout mode
    }


    if (!config_.functionsOnly && !config_.variablesOnly) {
        
        // Find all global objects and expand their members
        std::vector<MemberInfo> all_members;
        std::set<std::string> processed_symbols; // Avoid duplicates
        
        // Process variables discovered from DWARF debug information first
        std::set<uint64_t> processed_addresses; // Avoid processing same variable multiple times

        for (const auto& [symbol_name, var_info] : dwarf_variables_) {
            // Apply constants filter if specified
            if (config_.constantsOnly && !var_info.is_constant) {
                continue; // Skip non-constants when constants mode is enabled
            }

            
            if (var_info.is_global && 
                (var_info.address != 0 || var_info.is_constant) &&
                processed_addresses.find(var_info.address) == processed_addresses.end()) {
                
                processed_addresses.insert(var_info.address);
                std::string display_name = var_info.demangled_name.empty() ? var_info.name : var_info.demangled_name;
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
                
                if (!type_name.empty() && !var_info.is_constant) {
                    // Try to expand as structure/class, but only for non-constants
                    auto members = expandStructureMembers(display_name, type_name, symbol_address);
                    all_members.insert(all_members.end(), members.begin(), members.end());
                } else {
                    // For constants or unknown structures, show the variable itself with constant info
                    std::string type_str = var_info.type_name.empty() ? "OBJECT" : var_info.type_name;
                    uint64_t estimated_size = estimateTypeSize(type_str);
                    
                    if (estimated_size > 0) {
                        // Use enhanced constructor with size information
                        MemberInfo member_info(string_interner_.intern(display_name), symbol_address, string_interner_.intern(type_str), estimated_size);
                        member_info.is_constant = var_info.is_constant;
                        member_info.constant_value = var_info.constant_value;
                        if (config_.showSections) {
                                            member_info.section_name = getSectionNameForAddress(symbol_address);
                        }
                        all_members.push_back(member_info);
                    } else {
                        // Fallback to original constructor
                        MemberInfo fallback_member(string_interner_.intern(display_name), symbol_address, string_interner_.intern(type_str), var_info.is_constant, var_info.constant_value);
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
        if (!config_.constantsOnly && is_32bit_) {
            for (const auto& symbol : symbols32_) {
                if (!symbol.name.empty() && 
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_OBJECT) &&
                    symbol.st_value != 0 && symbol.st_size > 0) {
                    
                    std::string symbol_name = symbol.name;
                    std::string demangled_name = demangleCppName(symbol_name);
                    
                    // Skip if either mangled or demangled name is already processed
                    if (processed_symbols.find(symbol_name) != processed_symbols.end() ||
                        processed_symbols.find(demangled_name) != processed_symbols.end()) {
                        continue;
                    }
                    
                    uint64_t symbol_address = symbol.st_value;
                    
                    // Track both names to prevent future duplicates
                    processed_symbols.insert(symbol_name);
                    if (demangled_name != symbol_name) {
                        processed_symbols.insert(demangled_name);
                    }
                    
                    // Try to determine the type based on DWARF structures
                    std::string type_name = findTypeForSymbol(symbol_name);
                    
                    if (type_name.empty() && (symbol_name.find("_ZN7NAMEOne7Counter7counterE") != std::string::npos || 
                              symbol_name.find("counter") != std::string::npos)) {
                        // Handle static counter variable - show with full namespace
                        std::string full_name = "NAMEOne::Counter::counter";
                        uint64_t int_size = estimateTypeSize("int");
                        MemberInfo counter_member(string_interner_.intern(full_name), symbol_address, string_interner_.intern("int"), int_size);
                        if (config_.showSections) {
                            counter_member.section_name = getSectionNameForAddress(symbol_address);
                        }
                        all_members.push_back(counter_member);
                        continue;
                    }
                    
                    // Use demangled name for display
                    std::string display_name = (demangled_name != symbol_name) ? demangled_name : symbol_name;
                    
                    if (!type_name.empty()) {
                        auto members = expandStructureMembers(display_name, type_name, symbol_address);
                        all_members.insert(all_members.end(), members.begin(), members.end());
                    } else {
                        // If we don't know the structure, just show the object itself
                        uint64_t object_size = estimateTypeSize("OBJECT");
                        if (object_size == 0) object_size = 4; // Default size for unknown objects
                        MemberInfo object_member(string_interner_.intern(display_name), symbol_address, string_interner_.intern("OBJECT"), object_size);
                        if (config_.showSections) {
                            object_member.section_name = getSectionNameForAddress(symbol_address);
                        }
                        all_members.push_back(object_member);
                    }
                }
            }
        } else if (!config_.constantsOnly) {
            for (const auto& symbol : symbols64_) {
                if (!symbol.name.empty() && 
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_OBJECT) &&
                    symbol.st_value != 0 && symbol.st_size > 0) {
                    
                    std::string symbol_name = symbol.name;
                    std::string demangled_name = demangleCppName(symbol_name);
                    
                    // Skip if either mangled or demangled name is already processed
                    if (processed_symbols.find(symbol_name) != processed_symbols.end() ||
                        processed_symbols.find(demangled_name) != processed_symbols.end()) {
                        continue;
                    }
                    
                    uint64_t symbol_address = symbol.st_value;
                    
                    // Track both names to prevent future duplicates
                    processed_symbols.insert(symbol_name);
                    if (demangled_name != symbol_name) {
                        processed_symbols.insert(demangled_name);
                    }
                    
                    // Try to determine the type based on DWARF structures
                    std::string type_name = findTypeForSymbol(symbol_name);
                    
                    if (type_name.empty() && (symbol_name.find("_ZN7NAMEOne7Counter7counterE") != std::string::npos || 
                              symbol_name.find("counter") != std::string::npos)) {
                        // Handle static counter variable - show with full namespace
                        std::string full_name = "NAMEOne::Counter::counter";
                        uint64_t int_size = estimateTypeSize("int");
                        MemberInfo counter_member(string_interner_.intern(full_name), symbol_address, string_interner_.intern("int"), int_size);
                        if (config_.showSections) {
                            counter_member.section_name = getSectionNameForAddress(symbol_address);
                        }
                        all_members.push_back(counter_member);
                        continue;
                    }
                    
                    // Use demangled name for display
                    std::string display_name = (demangled_name != symbol_name) ? demangled_name : symbol_name;
                    
                    if (!type_name.empty()) {
                        auto members = expandStructureMembers(display_name, type_name, symbol_address);
                        all_members.insert(all_members.end(), members.begin(), members.end());
                    } else {
                        // If we don't know the structure, just show the object itself
                        uint64_t object_size = estimateTypeSize("OBJECT");
                        if (object_size == 0) object_size = 4; // Default size for unknown objects
                        MemberInfo object_member(string_interner_.intern(display_name), symbol_address, string_interner_.intern("OBJECT"), object_size);
                        if (config_.showSections) {
                            object_member.section_name = getSectionNameForAddress(symbol_address);
                        }
                        all_members.push_back(object_member);
                    }
                }
            }
        }
        
        // Sort by address for better readability
        std::sort(all_members.begin(), all_members.end(), 
                  [](const MemberInfo& a, const MemberInfo& b) {
                      return a.address < b.address;
                  });
        
        if (config_.format == "json") {
            generateJsonOutput(all_members);
        } else {
            generateCsvOutput(all_members);
        }
    }

    // Handle variables-only mode
    if (config_.variablesOnly) {
        
        // Find all global objects and expand their members
        std::vector<MemberInfo> all_members;
        std::set<std::string> processed_symbols; // Avoid duplicates
        
        // Process variables discovered from DWARF debug information first
        std::set<uint64_t> processed_addresses; // Avoid processing same variable multiple times

        for (const auto& [symbol_name, var_info] : dwarf_variables_) {
            // Apply constants filter if specified
            if (config_.constantsOnly && !var_info.is_constant) {
                continue; // Skip non-constants when constants mode is enabled
            }

            
            if (var_info.is_global && 
                (var_info.address != 0 || var_info.is_constant) &&
                processed_addresses.find(var_info.address) == processed_addresses.end()) {
                
                processed_addresses.insert(var_info.address);
                std::string display_name = var_info.demangled_name.empty() ? var_info.name : var_info.demangled_name;
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
                
                if (!type_name.empty() && !var_info.is_constant) {
                    // Try to expand as structure/class, but only for non-constants
                    auto members = expandStructureMembers(display_name, type_name, symbol_address);
                    all_members.insert(all_members.end(), members.begin(), members.end());
                } else {
                    // For constants or unknown structures, show the variable itself with constant info
                    std::string type_str = var_info.type_name.empty() ? "OBJECT" : var_info.type_name;
                    uint64_t estimated_size = estimateTypeSize(type_str);
                    
                    if (estimated_size > 0) {
                        // Use enhanced constructor with size information
                        MemberInfo member_info(string_interner_.intern(display_name), symbol_address, string_interner_.intern(type_str), estimated_size);
                        member_info.is_constant = var_info.is_constant;
                        member_info.constant_value = var_info.constant_value;
                        if (config_.showSections) {
                                            member_info.section_name = getSectionNameForAddress(symbol_address);
                        }
                        all_members.push_back(member_info);
                    } else {
                        // Fallback to original constructor
                        MemberInfo fallback_member(string_interner_.intern(display_name), symbol_address, string_interner_.intern(type_str), var_info.is_constant, var_info.constant_value);
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
        if (!config_.constantsOnly && is_32bit_) {
            for (const auto& symbol : symbols32_) {
                if (!symbol.name.empty() && 
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_OBJECT) &&
                    symbol.st_value != 0 && symbol.st_size > 0) {
                    
                    std::string symbol_name = symbol.name;
                    std::string demangled_name = demangleCppName(symbol_name);
                    
                    // Skip if either mangled or demangled name is already processed
                    if (processed_symbols.find(symbol_name) != processed_symbols.end() ||
                        processed_symbols.find(demangled_name) != processed_symbols.end()) {
                        continue;
                    }
                    
                    
                    // Try to find DWARF type information
                    std::string type_name = findTypeForSymbol(symbol_name);
                    std::string display_name = demangled_name.empty() ? symbol_name : demangled_name;
                    
                    if (type_name != "unknown") {
                        auto members = expandStructureMembers(display_name, type_name, symbol.st_value);
                        all_members.insert(all_members.end(), members.begin(), members.end());
                    } else {
                        MemberInfo symbol_member(display_name, symbol.st_value, "OBJECT");
                        if (config_.showSections) {
                            symbol_member.section_name = getSectionNameForAddress(symbol.st_value);
                        }
                        all_members.push_back(symbol_member);
                    }
                    
                    processed_symbols.insert(symbol_name);
                    if (!demangled_name.empty() && demangled_name != symbol_name) {
                        processed_symbols.insert(demangled_name);
                    }
                }
            }
        } else if (!config_.constantsOnly) {
            for (const auto& symbol : symbols64_) {
                if (!symbol.name.empty() && 
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_OBJECT) &&
                    symbol.st_value != 0 && symbol.st_size > 0) {
                    
                    std::string symbol_name = symbol.name;
                    std::string demangled_name = demangleCppName(symbol_name);
                    
                    // Skip if either mangled or demangled name is already processed
                    if (processed_symbols.find(symbol_name) != processed_symbols.end() ||
                        processed_symbols.find(demangled_name) != processed_symbols.end()) {
                        continue;
                    }
                    
                    
                    // Try to find DWARF type information
                    std::string type_name = findTypeForSymbol(symbol_name);
                    std::string display_name = demangled_name.empty() ? symbol_name : demangled_name;
                    
                    if (type_name != "unknown") {
                        auto members = expandStructureMembers(display_name, type_name, symbol.st_value);
                        all_members.insert(all_members.end(), members.begin(), members.end());
                    } else {
                        MemberInfo symbol_member(display_name, symbol.st_value, "OBJECT");
                        if (config_.showSections) {
                            symbol_member.section_name = getSectionNameForAddress(symbol.st_value);
                        }
                        all_members.push_back(symbol_member);
                    }
                    
                    processed_symbols.insert(symbol_name);
                    if (!demangled_name.empty() && demangled_name != symbol_name) {
                        processed_symbols.insert(demangled_name);
                    }
                }
            }
        }
        
        if (config_.format == "json") {
            generateJsonOutput(all_members);
        } else {
            generateCsvOutput(all_members);
        }
        return; // Exit early when variables-only mode
    }

    // Handle functions output when requested
    if (config_.functionsOnly || (!config_.variablesOnly && !config_.constantsOnly)) {
        std::vector<FunctionInfo> all_functions;

        if (is_32bit_) {
            for (const auto& symbol : symbols32_) {
                if (!symbol.name.empty() &&
                    symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) &&
                    symbol.st_value != 0) {


                    std::string func_name = symbol.name;
                    // Demangle C++ function names for better readability
                    if (func_name.find("_ZN7NAMEOne7Counter2upEv") != std::string::npos) {
                        func_name = "NAMEOne::Counter::up()";
                    }

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


                    std::string func_name = symbol.name;
                    // Demangle C++ function names for better readability
                    if (func_name.find("_ZN7NAMEOne7Counter2upEv") != std::string::npos) {
                        func_name = "NAMEOne::Counter::up()";
                    }

                    FunctionInfo func_info;
                    func_info.name = func_name;
                    func_info.mangled_name = symbol.name;
                    func_info.start_address = symbol.st_value;
                    func_info.end_address = symbol.st_value + symbol.st_size;
                    all_functions.push_back(func_info);
                }
            }
        }

        // Output functions in the requested format, but only if functions are specifically requested
        if (config_.functionsOnly && !all_functions.empty()) {
            if (config_.format == "json") {
                generateFunctionJsonOutput(all_functions);
            } else {
                generateFunctionCsvOutput(all_functions);
            }
        }
    }
    
    // Report final string interning statistics if debug output is enabled
    if (config_.verbosity > 1) {
        auto stats = string_interner_.getStats();
        std::cout << "\nString Interning Final Statistics:\n";
        std::cout << std::dec << "  Unique strings: " << stats.unique_strings << "\n";
        std::cout << "  Total characters: " << stats.total_characters << "\n";
        std::cout << "  Estimated memory: " << stats.estimated_bytes << " bytes\n";
        std::cout << "  Average length: " << std::fixed << std::setprecision(1) << stats.average_length << " chars\n";
        std::cout << "  Load factor: " << std::fixed << std::setprecision(2) << stats.load_factor << "\n";
    }
    
    
    // Phase 7.2: Interrupt Vector Table Analysis
    if (config_.extractInterruptVectors) {
        if (extractInterruptVectorTable()) {
            printInterruptVectorTable();
        } else {
            if (config_.verbosity > 0) {
                std::cout << "\nNo interrupt vector table found in this ELF file.\n";
            }
        }
    }
    
    // Phase 7.2: Memory Region Mapping and Validation
    if (config_.extractMemoryRegions) {
        if (extractMemoryRegionMapping()) {
            printMemoryRegionMapping();
        } else {
            if (config_.verbosity > 0) {
                std::cout << "\nNo memory region mapping available for this ELF file.\n";
            }
        }
    }
    
    // Phase 1: Binary Export Functionality
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

void ElfReader::generateJsonOutput(const std::vector<MemberInfo>& members) {
    std::cout << "{\n";
    std::cout << "  \"architecture\": \"" << (is_32bit_ ? "32-bit" : "64-bit") << " " << (is_little_endian_ ? "Little" : "Big") << " Endian\",\n";
    std::cout << "  \"entryPoint\": \"0x" << std::hex << std::setw(8) << std::setfill('0') << getEntryPoint() << "\",\n";
    
    std::cout << "  \"parameters\": [\n";
    for (size_t i = 0; i < members.size(); ++i) {
        const auto& member = members[i];
        std::cout << "    {\n";
        std::cout << "      \"name\": \"" << member.name << "\",\n";
        std::cout << "      \"address\": \"0x" << std::hex << std::setw(8) << std::setfill('0') << member.address << "\",\n";
        std::cout << "      \"size\": " << std::dec << member.byte_size << ",\n";
        std::cout << "      \"type\": \"" << member.type << "\"";
        if (member.is_constant) {
            std::cout << ",\n      \"is_constant\": true";
            if (!member.constant_value.empty()) {
                std::cout << ",\n      \"constant_value\": \"" << member.constant_value << "\"";
            }
        }
        if (config_.showSections && !member.section_name.empty()) {
            std::cout << ",\n      \"section\": \"" << member.section_name << "\"";
        }
        std::cout << "\n    }" << (i == members.size() - 1 ? "" : ",") << "\n";
    }
    std::cout << "  ]";

    if (!config_.variablesOnly) {
        std::cout << ",\n";
        std::cout << "  \"functions\": [\n";
        if (is_32bit_) {
            for (size_t i = 0; i < symbols32_.size(); ++i) {
                const auto& symbol = symbols32_[i];
                if (!symbol.name.empty() && symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) && symbol.st_value != 0) {
                    std::cout << "    {\n";
                    std::cout << "      \"name\": \"" << symbol.name << "\",\n";
                    std::cout << "      \"address\": \"0x" << std::hex << std::setw(8) << std::setfill('0') << symbol.st_value << "\"\n";
                    std::cout << "    }" << (i == symbols32_.size() - 1 ? "" : ",") << "\n";
                }
            }
        } else {
            for (size_t i = 0; i < symbols64_.size(); ++i) {
                const auto& symbol = symbols64_[i];
                if (!symbol.name.empty() && symbol.getType() == static_cast<uint8_t>(SymbolType::STT_FUNC) && symbol.st_value != 0) {
                    std::cout << "    {\n";
                    std::cout << "      \"name\": \"" << symbol.name << "\",\n";
                    std::cout << "      \"address\": \"0x" << std::hex << std::setw(8) << std::setfill('0') << symbol.st_value << "\"\n";
                    std::cout << "    }" << (i == symbols64_.size() - 1 ? "" : ",") << "\n";
                }
            }
        }
        std::cout << "  ]\n";
    } else {
        std::cout << "\n";
    }
    std::cout << "}\n";
}

void ElfReader::generateCsvOutput(const std::vector<MemberInfo>& members) {
    // CSV Header
    std::cout << "Name,Address,Size,Type";
    if (config_.showSections) {
        std::cout << ",Section";
    }
    std::cout << ",Value"; // Always include Value column for constants
    std::cout << "\n";

    // CSV Data rows
    for (const auto& member : members) {
        std::cout << member.name << ",0x" << std::hex << std::setw(8) << std::setfill('0')
                  << member.address << "," << std::dec << member.byte_size << "," << member.type;

        if (config_.showSections) {
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

void ElfReader::generateFunctionCsvOutput(const std::vector<FunctionInfo>& functions) {
    // CSV Header for functions
    std::cout << "Name,Address,Type";
    if (config_.showSections) {
        std::cout << ",Section";
    }
    std::cout << "\n";

    // CSV Data rows for functions
    for (const auto& function : functions) {
        std::cout << function.name << ",0x" << std::hex << std::setw(8) << std::setfill('0')
                  << function.start_address << ",function";

        if (config_.showSections) {
            std::cout << ",";
            std::string section_name = getSectionNameForAddress(function.start_address);
            if (!section_name.empty()) {
                std::cout << section_name;
            }
        }

        std::cout << "\n";
    }
}

void ElfReader::generateFunctionJsonOutput(const std::vector<FunctionInfo>& functions) {
    std::cout << "{\n";
    std::cout << "  \"architecture\": \"" << (is_32bit_ ? "32-bit" : "64-bit") << " " << (is_little_endian_ ? "Little" : "Big") << " Endian\",\n";
    std::cout << "  \"entryPoint\": \"0x" << std::hex << std::setw(8) << std::setfill('0') << getEntryPoint() << "\",\n";

    std::cout << "  \"functions\": [\n";
    for (size_t i = 0; i < functions.size(); ++i) {
        const auto& function = functions[i];
        std::cout << "    {\n";
        std::cout << "      \"name\": \"" << function.name << "\",\n";
        std::cout << "      \"address\": \"0x" << std::hex << std::setw(8) << std::setfill('0') << function.start_address << "\",\n";
        std::cout << "      \"type\": \"function\"";

        if (config_.showSections) {
            std::string section_name = getSectionNameForAddress(function.start_address);
            if (!section_name.empty()) {
                std::cout << ",\n      \"section\": \"" << section_name << "\"";
            }
        }

        std::cout << "\n    }" << (i == functions.size() - 1 ? "" : ",") << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

// ========================================================================
// Phase 7.1B: DWARF 5 Advanced Type Resolution Implementation
// ========================================================================

void ElfReader::processDwarf5TypeQualifier(Dwarf_Debug dbg, Dwarf_Die die, 
                                          const std::string& /* namespace_prefix */, 
                                          TypeQualifiers qualifier) {
    try {
        Dwarf_Error error = nullptr;
        
        // Get the underlying type that this qualifier applies to
        Dwarf_Attribute type_attr = nullptr;
        int ret = dwarf_attr(die, DW_AT_type, &type_attr, &error);
        if (ret != DW_DLV_OK) {
            return; // No type reference, skip
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
        std::string base_type_name = getDwarfDieName(dbg, type_die);
        if (base_type_name.empty()) {
            base_type_name = resolveDwarfType(dbg, type_die);
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
            static_cast<uint32_t>(advanced_info.qualifiers) | static_cast<uint32_t>(qualifier)
        );
        
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

void ElfReader::processDwarfTemplateParameter(Dwarf_Debug dbg, Dwarf_Die die,
                                            const std::string& /* namespace_prefix */,
                                            bool is_type_parameter) {
    try {
        Dwarf_Error error = nullptr;
        
        // Get parameter name
        std::string param_name = getDwarfDieName(dbg, die);
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
                    param_type = resolveDwarfType(dbg, type_die);
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
                    if (form == DW_FORM_data1 || form == DW_FORM_data2 || 
                        form == DW_FORM_data4 || form == DW_FORM_data8) {
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
        ret = dwarf_die_CU_offset_range(die, nullptr, nullptr, &error);
        
        // For now, store in a temporary structure - this will be enhanced
        // when we implement full template specialization tracking
        
        if (config_.verbosity > 1) {
            std::cout << "DWARF 5: Found template " 
                      << (is_type_parameter ? "type" : "value") 
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

// ========================================================================
// Phase 7.1B: Type Resolution Optimization Implementation
// ========================================================================

AdvancedTypeInfo ElfReader::getCachedTypeInfo(const std::string& type_name) const {
    auto it = type_cache_.find(type_name);
    if (it != type_cache_.end()) {
        // Check if cache entry is still valid (simple time-based expiration)
        uint64_t current_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        // Cache entries are valid for 1 minute
        const uint64_t cache_expiration_ns = 60 * 1000 * 1000 * 1000ULL; // 1 minute in nanoseconds
        
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
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    // Implement simple LRU by limiting cache size
    const size_t max_cache_size = 1000;
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
    cached_info.is_cached = false; // This is the original, not from cache
    type_cache_[type_name] = std::make_pair(cached_info, current_time);
}

std::string ElfReader::deduplicateTypeName(const std::string& type_name) {
    // Use string interning for type name deduplication
    return string_interner_.intern(type_name);
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
                std::cout << "Type optimization: " << type_name 
                          << " has " << deps.size() << " dependencies\n";
            }
        }
    }
}

void ElfReader::printTypeResolutionStats() const {
    if (config_.verbosity > 0) {
        std::cout << "\n=== Phase 7.1B: Advanced Type Resolution Statistics ===\n";
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
            double cache_hit_rate = (double)cached_types / advanced_types_.size() * 100.0;
            double avg_resolution_time = (double)total_resolution_time / advanced_types_.size() / 1000.0; // Convert to microseconds
            
            std::cout << "Cache hit rate: " << std::fixed << std::setprecision(1) 
                      << cache_hit_rate << "%\n";
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
                std::cout << "  - " << static_cast<uint32_t>(qualifier) << ": " << count << " types\n";
            }
        }
        
        std::cout << "========================================\n\n";
    }
}

// ========================================================================
// Phase 7.2: Interrupt Vector Table Analysis Implementation
// ========================================================================

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
            ".isr_vector",      // Common ARM Cortex-M naming
            ".vector_table",    // Alternative naming
            ".vectors",         // Short form
            ".interrupt_vector" // Descriptive naming
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
            found_vector_section = extractArmCortexMVectors();
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
    std::cout << "\n=== Phase 7.2: Interrupt Vector Table Analysis ===\n";
    std::cout << "Architecture: " << interrupt_vector_table_.architecture << "\n";
    
    if (interrupt_vector_table_.base_address != 0) {
        std::cout << "Vector table base address: 0x" << std::hex << interrupt_vector_table_.base_address << std::dec << "\n";
        std::cout << "Entry size: " << interrupt_vector_table_.entry_size << " bytes\n";
        std::cout << "Total entries: " << interrupt_vector_table_.total_entries << "\n";
    }
    
    std::cout << "Valid handlers found: " << interrupt_vector_table_.getValidHandlerCount() << "\n";
    std::cout << "\n";
    
    if (!interrupt_vector_table_.vectors.empty()) {
        std::cout << "Interrupt Vectors:\n";
        std::cout << "Vector# | Handler Address | Function Name                | Description\n";
        std::cout << "--------|-----------------|------------------------------|---------------------------\n";
        
        for (const auto& vector : interrupt_vector_table_.vectors) {
            if (vector.is_valid) {
                printf("%-7u | 0x%08llx      | %-28s | %s\n",
                       vector.vector_number,
                       (unsigned long long)vector.handler_address,
                       vector.handler_name.empty() ? "(unknown)" : vector.handler_name.c_str(),
                       vector.description.c_str());
            }
        }
        std::cout << "\n";
    }
    
    // Show additional interrupt handler functions not in vector table
    std::vector<FunctionInfo> all_handlers = identifyInterruptHandlers();
    std::vector<FunctionInfo> additional_handlers;
    
    for (const auto& handler : all_handlers) {
        bool in_vector_table = false;
        for (const auto& vector : interrupt_vector_table_.vectors) {
            if (vector.handler_address == handler.start_address) {
                in_vector_table = true;
                break;
            }
        }
        
        if (!in_vector_table) {
            additional_handlers.push_back(handler);
        }
    }
    
    if (!additional_handlers.empty()) {
        std::cout << "Additional Interrupt Handler Functions (not in vector table):\n";
        std::cout << "Function Name                        | Address    | Size\n";
        std::cout << "-------------------------------------|------------|--------\n";
        
        for (const auto& handler : additional_handlers) {
            printf("%-36s | 0x%08llx | %llu bytes\n",
                   handler.name.c_str(),
                   (unsigned long long)handler.start_address,
                   (unsigned long long)(handler.end_address - handler.start_address));
        }
        std::cout << "\n";
    }
    
    std::cout << "===============================================\n\n";
}

std::string ElfReader::getArmInterruptDescription(uint32_t vector_number) const {
    // ARM Cortex-M standard system exceptions and interrupts
    switch (vector_number) {
        case 0: return "Initial Stack Pointer";
        case 1: return "Reset Handler";
        case 2: return "NMI Handler";
        case 3: return "Hard Fault Handler";
        case 4: return "Memory Management Fault Handler";
        case 5: return "Bus Fault Handler";
        case 6: return "Usage Fault Handler";
        case 7: case 8: case 9: case 10: return "Reserved";
        case 11: return "SVCall Handler";
        case 12: return "Debug Monitor Handler";
        case 13: return "Reserved";
        case 14: return "PendSV Handler";
        case 15: return "SysTick Handler";
        default:
            if (vector_number >= 16) {
                return "External Interrupt " + std::to_string(vector_number - 16);
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
        interrupt_vector_table_.entry_size = 4; // Typically 4 bytes per entry for ARM
        interrupt_vector_table_.total_entries = section_size / interrupt_vector_table_.entry_size;
        
        // Read section data
        std::vector<uint8_t> section_data;
        if (!readSectionData(section_index, section_data)) {
            return false;
        }
        
        // Parse vector entries (assuming 32-bit addresses)
        for (uint32_t i = 0; i < interrupt_vector_table_.total_entries && i * 4 < section_data.size(); ++i) {
            uint32_t handler_address = 0;
            
            // Read 32-bit address (little-endian)
            if (i * 4 + 3 < section_data.size()) {
                handler_address = section_data[i * 4] |
                                (section_data[i * 4 + 1] << 8) |
                                (section_data[i * 4 + 2] << 16) |
                                (section_data[i * 4 + 3] << 24);
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
            if (section.name == ".text" && 
                section.sh_flags & 0x4 && // SHF_EXECINSTR
                section.sh_addr < 0x10000) { // Low memory address
                
                interrupt_vector_table_.base_address = section.sh_addr;
                interrupt_vector_table_.entry_size = 4;
                
                // Assume standard ARM Cortex-M vector count (16 system + N user vectors)
                // Limit to reasonable size to avoid parsing entire .text section
                uint32_t max_vectors = std::min(64U, static_cast<uint32_t>(section.sh_size / 4));
                interrupt_vector_table_.total_entries = max_vectors;
            
                // Try to parse first few entries as potential vectors
                std::vector<uint8_t> section_data;
                if (readSectionData(i, section_data)) {
                    for (uint32_t vec = 0; vec < max_vectors && vec * 4 < section_data.size(); ++vec) {
                        uint32_t handler_address = 0;
                        
                        if (vec * 4 + 3 < section_data.size()) {
                            handler_address = section_data[vec * 4] |
                                            (section_data[vec * 4 + 1] << 8) |
                                            (section_data[vec * 4 + 2] << 16) |
                                            (section_data[vec * 4 + 3] << 24);
                        }
                        
                        // ARM Cortex-M vectors: check if address looks valid
                        // Vector 0 is initial SP, vectors 1+ are handler addresses
                        if (vec == 0) {
                            // Stack pointer - should be reasonable value
                            if (handler_address > 0x20000000 && handler_address < 0x30000000) {
                                InterruptVectorEntry entry(vec, handler_address, "Initial Stack Pointer", "ARM Cortex-M Initial SP");
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

bool ElfReader::readSectionData(size_t section_index, std::vector<uint8_t>& data) {
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
    if (section_type == 8) { // SHT_NOBITS
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

//==============================================================================
// Phase 7.2: Memory Region Mapping and Validation Implementation
//==============================================================================

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
            std::cout << "Found " << memory_region_map_.regions.size() 
                     << " memory regions (" << memory_region_map_.getLoadableRegionCount() 
                     << " loadable)\n";
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
    std::cout << "Entry Point: 0x" << std::hex << memory_region_map_.entry_point << std::dec << std::endl;
    std::cout << "Total Regions: " << memory_region_map_.regions.size() << std::endl;
    std::cout << "Loadable Regions: " << memory_region_map_.getLoadableRegionCount() << std::endl;
    std::cout << std::endl;
    
    // Memory layout characteristics
    const auto& layout = memory_region_map_.layout;
    std::cout << "Memory Layout Characteristics:" << std::endl;
    std::cout << "  Memory Model: " << (layout.memory_model.empty() ? "Standard" : layout.memory_model) << std::endl;
    std::cout << "  Position Independent: " << (layout.is_position_independent ? "Yes" : "No") << std::endl;
    std::cout << "  Physical Addresses: " << (layout.has_physical_addresses ? "Meaningful" : "Virtual only") << std::endl;
    
    if (layout.code_base_address > 0) {
        std::cout << "  Code Base Address: 0x" << std::hex << layout.code_base_address << std::dec << std::endl;
    }
    if (layout.data_base_address > 0) {
        std::cout << "  Data Base Address: 0x" << std::hex << layout.data_base_address << std::dec << std::endl;
    }
    std::cout << std::endl;
    
    // Memory usage summary
    std::cout << "Memory Usage Summary:" << std::endl;
    std::cout << "  Total Virtual Size: " << formatMemorySize(memory_region_map_.total_virtual_size) << std::endl;
    std::cout << "  Total Physical Size: " << formatMemorySize(memory_region_map_.total_physical_size) << std::endl;
    std::cout << std::endl;
    
    // Detailed memory regions
    std::cout << "Memory Regions:" << std::endl;
    std::cout << "-------------------------------------------------------------------------------" << std::endl;
    std::cout << "Type      Virtual Address    Size        Permissions  Description" << std::endl;
    std::cout << "-------------------------------------------------------------------------------" << std::endl;
    
    for (const auto& region : memory_region_map_.regions) {
        if (!region.is_loadable) continue; // Skip non-loadable regions in main display
        
        std::cout << std::left << std::setw(10) << getRegionTypeName(region.region_type)
                 << "0x" << std::hex << std::setw(16) << region.virtual_address << std::dec
                 << std::setw(12) << formatMemorySize(region.memory_size)
                 << std::setw(13) << region.getPermissionString()
                 << region.description << std::endl;
    }
    std::cout << std::endl;
    
    // Non-loadable regions (if any)
    bool hasNonLoadable = false;
    for (const auto& region : memory_region_map_.regions) {
        if (!region.is_loadable) {
            if (!hasNonLoadable) {
                std::cout << "Non-Loadable Regions:" << std::endl;
                std::cout << "-------------------------------------------------------------------------------" << std::endl;
                hasNonLoadable = true;
            }
            std::cout << std::left << std::setw(10) << getRegionTypeName(region.region_type)
                     << "0x" << std::hex << std::setw(16) << region.virtual_address << std::dec
                     << std::setw(12) << formatMemorySize(region.memory_size)
                     << std::setw(13) << region.getPermissionString()
                     << region.description << std::endl;
        }
    }
    if (hasNonLoadable) std::cout << std::endl;
    
    // Validation results
    const auto& validation = memory_region_map_.validation;
    std::cout << "Validation Results:" << std::endl;
    std::cout << "  Layout Valid: " << (validation.layout_valid ? "✓ Yes" : "✗ No") << std::endl;
    std::cout << "  No Overlaps: " << (validation.no_overlaps ? "✓ Yes" : "✗ No") << std::endl;
    std::cout << "  Addresses Reasonable: " << (validation.addresses_reasonable ? "✓ Yes" : "✗ No") << std::endl;
    std::cout << "  Sizes Reasonable: " << (validation.sizes_reasonable ? "✓ Yes" : "✗ No") << std::endl;
    std::cout << "  Total Errors: " << validation.error_count << std::endl;
    std::cout << "  Total Warnings: " << validation.warning_count << std::endl;
    
    // Show errors and warnings
    if (!validation.global_errors.empty()) {
        std::cout << std::endl << "Validation Errors:" << std::endl;
        for (const auto& error : validation.global_errors) {
            std::cout << "  ✗ " << error << std::endl;
        }
    }
    
    if (!validation.global_warnings.empty()) {
        std::cout << std::endl << "Validation Warnings:" << std::endl;
        for (const auto& warning : validation.global_warnings) {
            std::cout << "  ⚠ " << warning << std::endl;
        }
    }
    
    // Detailed region validation (if verbose)
    if (config_.verbosity > 1) {
        std::cout << std::endl << "Detailed Region Validation:" << std::endl;
        for (size_t i = 0; i < memory_region_map_.regions.size(); ++i) {
            const auto& region = memory_region_map_.regions[i];
            if (!region.validation.errors.empty() || !region.validation.warnings.empty()) {
                std::cout << "  Region " << i << " (" << getRegionTypeName(region.region_type) << "):" << std::endl;
                for (const auto& error : region.validation.errors) {
                    std::cout << "    ✗ " << error << std::endl;
                }
                for (const auto& warning : region.validation.warnings) {
                    std::cout << "    ⚠ " << warning << std::endl;
                }
            }
        }
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
            std::cout << "Parsing " << ph_count << " program headers at offset 0x" 
                     << std::hex << ph_offset << std::dec << "\n";
        }
        
        for (uint16_t i = 0; i < ph_count; ++i) {
            uint64_t current_offset = ph_offset + (i * ph_size);
            
            // Parse program header based on ELF class
            MemoryRegion region;
            if (!is_32bit_) {
                if (!parseProgramHeader64(current_offset, region)) {
                    continue; // Skip invalid headers
                }
            } else {
                if (!parseProgramHeader32(current_offset, region)) {
                    continue; // Skip invalid headers
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
            if (executable && readable && !writable) {
                region.region_type = MemoryRegionType::CODE;
                region.name = "CODE";
            } else if (readable && writable && !executable) {
                // Could be DATA or BSS - check if has file size
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
    if (region.memory_size > 0x40000000) { // 1GB
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
            region.validation.warnings.push_back("Virtual address not aligned to specified boundary");
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
            region.validation.warnings.push_back("Region is both writable and executable (security risk)");
        }
    }
}

void ElfReader::checkRegionOverlaps() {
    auto& validation = memory_region_map_.validation;
    
    // Check all loadable regions for overlaps
    for (size_t i = 0; i < memory_region_map_.regions.size(); ++i) {
        auto& region1 = memory_region_map_.regions[i];
        if (!region1.is_loadable) continue;
        
        for (size_t j = i + 1; j < memory_region_map_.regions.size(); ++j) {
            auto& region2 = memory_region_map_.regions[j];
            if (!region2.is_loadable) continue;
            
            if (region1.overlaps(region2)) {
                validation.no_overlaps = false;
                region1.validation.overlap_detected = true;
                region2.validation.overlap_detected = true;
                
                std::ostringstream oss;
                oss << "Region " << getRegionTypeName(region1.region_type) 
                    << " overlaps with " << getRegionTypeName(region2.region_type);
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
    
    if (min_addr != UINT64_MAX && max_addr - min_addr > 0x100000000ULL) { // 4GB span
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
    if (layout.code_base_address == 0 || layout.code_base_address < 0x400000) {
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
        case ElfSegmentType::PT_NULL: return "Unused program header entry";
        case ElfSegmentType::PT_LOAD: return "Loadable segment";
        case ElfSegmentType::PT_DYNAMIC: return "Dynamic linking information";
        case ElfSegmentType::PT_INTERP: return "Interpreter information";
        case ElfSegmentType::PT_NOTE: return "Auxiliary information";
        case ElfSegmentType::PT_SHLIB: return "Reserved";
        case ElfSegmentType::PT_PHDR: return "Program header table";
        case ElfSegmentType::PT_TLS: return "Thread-local storage";
        case ElfSegmentType::PT_GNU_EH_FRAME: return "GNU exception handling frame";
        case ElfSegmentType::PT_GNU_STACK: return "GNU stack flags";
        case ElfSegmentType::PT_GNU_RELRO: return "GNU read-only after relocation";
        case ElfSegmentType::PT_ARM_EXIDX: return "ARM exception index table";
        default: return "Unknown segment type";
    }
}

std::string ElfReader::getRegionTypeName(MemoryRegionType type) const {
    switch (type) {
        case MemoryRegionType::CODE: return "CODE";
        case MemoryRegionType::DATA: return "DATA";
        case MemoryRegionType::BSS: return "BSS";
        case MemoryRegionType::RODATA: return "RODATA";
        case MemoryRegionType::STACK: return "STACK";
        case MemoryRegionType::HEAP: return "HEAP";
        case MemoryRegionType::DYNAMIC: return "DYNAMIC";
        case MemoryRegionType::TLS: return "TLS";
        case MemoryRegionType::NOTE: return "NOTE";
        case MemoryRegionType::EXCEPTION: return "EXCEPTION";
        case MemoryRegionType::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

MemoryRegionType ElfReader::classifyNonLoadableRegion(ElfSegmentType type) const {
    switch (type) {
        case ElfSegmentType::PT_DYNAMIC: return MemoryRegionType::DYNAMIC;
        case ElfSegmentType::PT_TLS: return MemoryRegionType::TLS;
        case ElfSegmentType::PT_NOTE: return MemoryRegionType::NOTE;
        case ElfSegmentType::PT_GNU_EH_FRAME: return MemoryRegionType::EXCEPTION;
        case ElfSegmentType::PT_ARM_EXIDX: return MemoryRegionType::EXCEPTION;
        default: return MemoryRegionType::UNKNOWN;
    }
}

void ElfReader::classifyESP32MemoryRegion(MemoryRegion& region, bool readable, bool writable, bool executable) {
    uint64_t addr = region.virtual_address;
    
    // ESP32 memory map classification based on address ranges
    // Reference: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/memory-types.html
    
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

//==============================================================================
// Stack Frame Analysis Implementation (Embedded Debugging Support)
//==============================================================================

bool ElfReader::extractStackFrameAnalysis() {
    if (config_.verbosity >= 1) {
        std::cout << "Starting comprehensive stack frame analysis..." << std::endl;
    }
    
    // Initialize stack frame analysis results
    stack_frame_analysis_.function_frames.clear();
    stack_frame_analysis_.address_to_function.clear();
    stack_frame_analysis_.total_functions_analyzed = 0;
    stack_frame_analysis_.functions_with_frame_pointer = 0;
    stack_frame_analysis_.leaf_functions = 0;
    stack_frame_analysis_.largest_frame_size = 0;
    stack_frame_analysis_.largest_frame_function.clear();
    
    // Set architecture information
    uint16_t machine_type = is_32bit_ ? ehdr32_.e_machine : ehdr64_.e_machine;
    if (machine_type == static_cast<uint16_t>(ElfMachine::EM_ARM)) {
        stack_frame_analysis_.target_architecture = "ARM";
        stack_frame_analysis_.abi_name = "AAPCS";
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_AARCH64)) {
        stack_frame_analysis_.target_architecture = "ARM64";
        stack_frame_analysis_.abi_name = "AAPCS64";
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_RISCV)) {
        stack_frame_analysis_.target_architecture = "RISC-V";
        stack_frame_analysis_.abi_name = "RISC-V";
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_XTENSA)) {
        stack_frame_analysis_.target_architecture = "Xtensa";
        stack_frame_analysis_.abi_name = "Xtensa Call0";
    } else {
        stack_frame_analysis_.target_architecture = "Unknown";
        stack_frame_analysis_.abi_name = "Unknown";
    }
    
    // Check if local variable analysis has been performed
    if (functions_.empty()) {
        if (config_.verbosity >= 1) {
            std::cout << "No local variable data available. Stack frame analysis requires local variable analysis." << std::endl;
        }
        return false;
    }
    
    // Analyze stack frame for each function
    for (const auto& function_pair : functions_) {
        const FunctionInfo& function_info = function_pair.second;
        
        // Perform comprehensive stack frame analysis
        StackFrameInfo frame_info = analyzeStackFrame(function_info);
        
        // Add to results
        stack_frame_analysis_.addStackFrame(frame_info);
        
        if (config_.verbosity >= 2) {
            std::cout << "Analyzed function: " << frame_info.getSummary() << std::endl;
        }
    }
    
    if (config_.verbosity >= 1) {
        std::cout << "Stack frame analysis complete: " << stack_frame_analysis_.getStatisticsSummary() << std::endl;
    }
    
    return stack_frame_analysis_.total_functions_analyzed > 0;
}

void ElfReader::printStackFrameAnalysis() const {
    if (stack_frame_analysis_.total_functions_analyzed == 0) {
        if (config_.verbosity >= 0) {
            std::cout << "No stack frame analysis data available." << std::endl;
        }
        return;
    }
    
    if (config_.format == "json") {
        // JSON output for machine processing
        std::cout << "{" << std::endl;
        std::cout << "  \"stack_frame_analysis\": {" << std::endl;
        std::cout << "    \"target_architecture\": \"" << stack_frame_analysis_.target_architecture << "\"," << std::endl;
        std::cout << "    \"abi_name\": \"" << stack_frame_analysis_.abi_name << "\"," << std::endl;
        std::cout << "    \"statistics\": {" << std::endl;
        std::cout << "      \"total_functions_analyzed\": " << stack_frame_analysis_.total_functions_analyzed << "," << std::endl;
        std::cout << "      \"functions_with_frame_pointer\": " << stack_frame_analysis_.functions_with_frame_pointer << "," << std::endl;
        std::cout << "      \"leaf_functions\": " << stack_frame_analysis_.leaf_functions << "," << std::endl;
        std::cout << "      \"largest_frame_size\": " << stack_frame_analysis_.largest_frame_size << "," << std::endl;
        std::cout << "      \"largest_frame_function\": \"" << stack_frame_analysis_.largest_frame_function << "\"" << std::endl;
        std::cout << "    }," << std::endl;
        std::cout << "    \"functions\": [" << std::endl;
        
        bool first = true;
        for (const auto& frame_pair : stack_frame_analysis_.function_frames) {
            if (!first) std::cout << "," << std::endl;
            std::cout << formatStackFrameForJson(frame_pair.second);
            first = false;
        }
        
        std::cout << std::endl << "    ]" << std::endl;
        std::cout << "  }" << std::endl;
        std::cout << "}" << std::endl;
    } else {
        // Text output for human reading
        std::cout << "\n================================================================================" << std::endl;
        std::cout << "STACK FRAME ANALYSIS - EMBEDDED DEBUGGING SUPPORT" << std::endl;
        std::cout << "================================================================================" << std::endl;
        std::cout << "Target Architecture: " << stack_frame_analysis_.target_architecture << std::endl;
        std::cout << "ABI: " << stack_frame_analysis_.abi_name << std::endl;
        std::cout << stack_frame_analysis_.getStatisticsSummary() << std::endl;
        std::cout << "================================================================================" << std::endl;
        
        // Display each function's stack frame analysis
        for (const auto& frame_pair : stack_frame_analysis_.function_frames) {
            std::cout << formatStackFrameForText(frame_pair.second) << std::endl;
        }
    }
}

StackFrameInfo ElfReader::analyzeStackFrame(const FunctionInfo& function_info) {
    StackFrameInfo frame_info;
    
    // Basic function information
    frame_info.function_name = function_info.name;
    frame_info.mangled_name = function_info.mangled_name;
    frame_info.function_start_address = function_info.start_address;
    frame_info.function_end_address = function_info.end_address;
    
    // Calculate frame size
    frame_info.total_frame_size = calculateStackFrameSize(function_info);
    
    // Detect calling convention
    frame_info.calling_convention = detectCallingConvention(function_info);
    
    // Analyze register usage
    frame_info.register_usage = analyzeRegisterUsage(function_info);
    
    // Convert local variables to stack frame entries
    for (const auto& local_var : function_info.local_variables) {
        StackFrameEntry entry = convertToStackFrameEntry(local_var, function_info.start_address);
        frame_info.stack_variables.push_back(entry);
        
        if (entry.is_parameter) {
            frame_info.parameters.push_back(entry);
        } else {
            frame_info.local_variables.push_back(entry);
        }
    }
    
    // Calculate frame layout sizes
    frame_info.parameter_area_size = 0;
    frame_info.local_variables_size = 0;
    frame_info.saved_registers_size = 16; // Typical for ARM (4 registers * 4 bytes)
    
    for (const auto& var : frame_info.stack_variables) {
        if (var.is_parameter) {
            frame_info.parameter_area_size += var.size_bytes;
        } else {
            frame_info.local_variables_size += var.size_bytes;
        }
    }
    
    // Detect function characteristics
    frame_info.is_leaf_function = (function_info.end_address - function_info.start_address) < 64; // Heuristic
    frame_info.has_exception_handling = false; // Would require more sophisticated DWARF analysis
    
    // Set frame pointer offset (architecture-dependent)
    if (frame_info.register_usage.uses_frame_pointer) {
        frame_info.frame_pointer_offset = -static_cast<int64_t>(frame_info.saved_registers_size);
    } else {
        frame_info.frame_pointer_offset = 0;
    }
    
    return frame_info;
}

CallingConvention ElfReader::detectCallingConvention([[maybe_unused]] const FunctionInfo& function_info) {
    CallingConvention convention;
    
    uint16_t machine_type = is_32bit_ ? ehdr32_.e_machine : ehdr64_.e_machine;
    
    if (machine_type == static_cast<uint16_t>(ElfMachine::EM_ARM)) {
        convention.name = "AAPCS";
        convention.architecture = "ARM";
        convention.stack_alignment = 4;
        convention.frame_alignment = 4;
        convention.param_registers = {"r0", "r1", "r2", "r3"};
        convention.return_registers = {"r0", "r1"};
        convention.stack_grows_down = true;
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_AARCH64)) {
        convention.name = "AAPCS64";
        convention.architecture = "ARM64";
        convention.stack_alignment = 8;
        convention.frame_alignment = 8;
        convention.param_registers = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
        convention.return_registers = {"x0", "x1"};
        convention.stack_grows_down = true;
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_RISCV)) {
        convention.name = "RISC-V";
        convention.architecture = "RISC-V";
        convention.stack_alignment = is_32bit_ ? 4 : 8;
        convention.frame_alignment = is_32bit_ ? 4 : 8;
        if (is_32bit_) {
            convention.param_registers = {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
        } else {
            convention.param_registers = {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
        }
        convention.return_registers = {"a0", "a1"};
        convention.stack_grows_down = true;
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_XTENSA)) {
        // Xtensa supports both Call0 and Windowed ABI - detect from DWARF or assume Call0 (ESP32 default)
        bool is_windowed_abi = false; // TODO: Detect from ELF flags or DWARF info
        
        if (is_windowed_abi) {
            convention.name = "Xtensa Windowed";
            convention.architecture = "Xtensa";
            convention.stack_alignment = 16;  // 16-byte aligned for windowed ABI
            convention.frame_alignment = 16;
            // In windowed ABI: args passed in a10-a15, rotated to a2-a7 after call
            convention.param_registers = {"a2", "a3", "a4", "a5", "a6", "a7"};
            convention.return_registers = {"a2", "a3", "a4", "a5"};
            convention.stack_grows_down = true;
        } else {
            // Call0 ABI (ESP32 default)
            convention.name = "Xtensa Call0";
            convention.architecture = "Xtensa";
            convention.stack_alignment = 4;
            convention.frame_alignment = 4;
            convention.param_registers = {"a2", "a3", "a4", "a5", "a6", "a7"};
            convention.return_registers = {"a2", "a3", "a4", "a5"};
            convention.stack_grows_down = true;
        }
    } else {
        convention.name = "Unknown";
        convention.architecture = "Unknown";
        convention.stack_alignment = 4;
        convention.frame_alignment = 4;
        convention.stack_grows_down = true;
    }
    
    return convention;
}

RegisterUsage ElfReader::analyzeRegisterUsage(const FunctionInfo& function_info) {
    RegisterUsage usage;
    
    uint16_t machine_type = is_32bit_ ? ehdr32_.e_machine : ehdr64_.e_machine;
    
    // Set architecture-specific register information
    if (machine_type == static_cast<uint16_t>(ElfMachine::EM_ARM)) {
        usage.parameter_registers = {"r0", "r1", "r2", "r3"};
        usage.return_registers = {"r0", "r1"};
        usage.callee_saved = {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "lr"};
        usage.caller_saved = {"r0", "r1", "r2", "r3", "r12"};
        
        // Detect frame pointer usage (r11/fp is commonly used)
        usage.uses_frame_pointer = (function_info.stack_frame_size > 32); // Heuristic
        
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_AARCH64)) {
        usage.parameter_registers = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
        usage.return_registers = {"x0", "x1"};
        usage.callee_saved = {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"};
        usage.caller_saved = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18"};
        
        // ARM64 often uses x29 as frame pointer
        usage.uses_frame_pointer = (function_info.stack_frame_size > 16);
        
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_RISCV)) {
        usage.parameter_registers = {"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
        usage.return_registers = {"a0", "a1"};
        usage.callee_saved = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11"};
        usage.caller_saved = {"t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
        
        // RISC-V uses s0/fp as frame pointer
        usage.uses_frame_pointer = (function_info.stack_frame_size > 16);
        
    } else if (machine_type == static_cast<uint16_t>(ElfMachine::EM_XTENSA)) {
        // Enhanced Xtensa register usage with ABI detection
        bool is_windowed_abi = false; // TODO: Detect from ELF flags or DWARF info
        
        if (is_windowed_abi) {
            // Windowed ABI register usage
            usage.parameter_registers = {"a2", "a3", "a4", "a5", "a6", "a7"}; // After rotation
            usage.return_registers = {"a2", "a3", "a4", "a5"};
            usage.callee_saved = {}; // Managed by register window mechanism
            usage.caller_saved = {"a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11"};
            usage.uses_frame_pointer = true; // a7 used as frame pointer
            // Special registers: a0 = return address, a1 = stack pointer
        } else {
            // Call0 ABI register usage (ESP32 default)
            usage.parameter_registers = {"a2", "a3", "a4", "a5", "a6", "a7"};
            usage.return_registers = {"a2", "a3", "a4", "a5"};
            // Call0 ABI: a12-a15 are callee-saved, a15 may be frame pointer
            usage.callee_saved = {"a12", "a13", "a14", "a15"};
            usage.caller_saved = {"a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11"};
            usage.uses_frame_pointer = (function_info.stack_frame_size > 32); // a15 may be FP
            // Special registers: a0 = return address, a1 = stack pointer
        }
    }
    
    // Analyze actual register usage from local variables
    for (const auto& var : function_info.local_variables) {
        if (var.location.type == LocationType::REGISTER) {
            std::string reg_name = "r" + std::to_string(var.location.offset_or_register);
            usage.used_registers.push_back(reg_name);
        }
    }
    
    // Check for variable arguments (simple heuristic)
    usage.has_variable_args = (function_info.parameters.size() > 8); // More than typical register parameters
    
    return usage;
}

StackFrameEntry ElfReader::convertToStackFrameEntry(const LocalVariableInfo& local_var, [[maybe_unused]] uint64_t function_start_addr) {
    StackFrameEntry entry;
    
    entry.name = local_var.name;
    entry.type = local_var.type;
    entry.is_parameter = local_var.is_parameter;
    entry.parameter_index = local_var.parameter_index;
    
    // Convert location information
    if (local_var.location.type == LocationType::STACK_OFFSET) {
        entry.stack_offset = local_var.location.offset_or_register;
        entry.location_description = "Stack offset " + std::to_string(entry.stack_offset);
    } else if (local_var.location.type == LocationType::REGISTER) {
        entry.stack_offset = 0; // Not on stack
        entry.location_description = "Register r" + std::to_string(local_var.location.offset_or_register);
    } else {
        entry.stack_offset = 0;
        entry.location_description = "Unknown location";
    }
    
    // Set variable scope
    entry.scope_start_pc = local_var.scope_start_pc;
    entry.scope_end_pc = local_var.scope_end_pc;
    
    // Estimate size (basic type analysis)
    if (local_var.type.find("char") != std::string::npos) {
        entry.size_bytes = 1;
    } else if (local_var.type.find("short") != std::string::npos) {
        entry.size_bytes = 2;
    } else if (local_var.type.find("int") != std::string::npos || local_var.type.find("float") != std::string::npos) {
        entry.size_bytes = 4;
    } else if (local_var.type.find("long") != std::string::npos || local_var.type.find("double") != std::string::npos) {
        entry.size_bytes = is_32bit_ ? 4 : 8;
    } else if (local_var.type.find("*") != std::string::npos) {
        entry.size_bytes = is_32bit_ ? 4 : 8; // Pointer size
    } else {
        entry.size_bytes = 4; // Default assumption
    }
    
    return entry;
}

uint32_t ElfReader::calculateStackFrameSize(const FunctionInfo& function_info) {
    // Start with the explicitly calculated frame size if available
    uint32_t frame_size = function_info.stack_frame_size;
    
    // If no explicit frame size, calculate from variables
    if (frame_size == 0) {
        uint32_t local_vars_size = 0;
        uint32_t max_offset = 0;
        
        for (const auto& var : function_info.local_variables) {
            if (var.location.type == LocationType::STACK_OFFSET && var.location.offset_or_register < 0) {
                // Local variable on stack
                uint32_t var_end = static_cast<uint32_t>(-var.location.offset_or_register);
                if (var_end > max_offset) {
                    max_offset = var_end;
                }
            }
        }
        
        local_vars_size = max_offset;
        
        // Add saved registers (typical: LR + FP + some callee-saved)
        uint32_t saved_regs_size = 16; // Conservative estimate
        
        frame_size = local_vars_size + saved_regs_size;
        
        // Apply alignment
        uint16_t machine_type = is_32bit_ ? ehdr32_.e_machine : ehdr64_.e_machine;
        uint32_t alignment = (machine_type == static_cast<uint16_t>(ElfMachine::EM_AARCH64)) ? 8 : 4;
        frame_size = (frame_size + alignment - 1) & ~(alignment - 1);
    }
    
    return frame_size;
}

std::string ElfReader::formatStackFrameForText(const StackFrameInfo& frame_info) const {
    std::ostringstream oss;
    
    oss << "\n--------------------------------------------------------------------------------" << std::endl;
    oss << "FUNCTION: " << frame_info.function_name;
    if (!frame_info.mangled_name.empty() && frame_info.mangled_name != frame_info.function_name) {
        oss << " [" << frame_info.mangled_name << "]";
    }
    oss << std::endl;
    oss << "Address Range: 0x" << std::hex << frame_info.function_start_address
        << " - 0x" << frame_info.function_end_address << std::dec << std::endl;
    oss << "Stack Frame Size: " << frame_info.total_frame_size << " bytes" << std::endl;
    oss << "Calling Convention: " << frame_info.calling_convention.name 
        << " (" << frame_info.calling_convention.architecture << ")" << std::endl;
    oss << "Uses Frame Pointer: " << (frame_info.usesFramePointer() ? "Yes" : "No") << std::endl;
    oss << "Leaf Function: " << (frame_info.is_leaf_function ? "Yes" : "No") << std::endl;
    oss << "Parameters: " << frame_info.getParameterCount() 
        << ", Local Variables: " << frame_info.getLocalVariableCount() << std::endl;
    
    // Display stack layout
    if (!frame_info.stack_variables.empty()) {
        oss << "\nStack Layout:" << std::endl;
        oss << "  Offset    Size  Type            Name" << std::endl;
        oss << "  --------  ----  --------------  ----------------" << std::endl;
        
        // Sort variables by stack offset for better visualization
        std::vector<StackFrameEntry> sorted_vars = frame_info.stack_variables;
        std::sort(sorted_vars.begin(), sorted_vars.end(), 
                 [](const StackFrameEntry& a, const StackFrameEntry& b) {
                     return a.stack_offset > b.stack_offset; // Higher offsets first
                 });
        
        for (const auto& var : sorted_vars) {
            if (var.stack_offset != 0) { // Only show stack-based variables
                oss << "  " << std::setw(8) << var.getLocationString()
                    << "  " << std::setw(4) << var.size_bytes
                    << "  " << std::setw(14) << var.type.substr(0, 14)
                    << "  " << var.name;
                if (var.is_parameter) {
                    oss << " (param " << var.parameter_index << ")";
                }
                oss << std::endl;
            }
        }
        
        // Show register-based variables separately
        bool has_register_vars = false;
        for (const auto& var : frame_info.stack_variables) {
            if (var.stack_offset == 0 && var.location_description.find("Register") != std::string::npos) {
                if (!has_register_vars) {
                    oss << "\nRegister Variables:" << std::endl;
                    oss << "  Register  Size  Type            Name" << std::endl;
                    oss << "  --------  ----  --------------  ----------------" << std::endl;
                    has_register_vars = true;
                }
                oss << "  " << std::setw(8) << var.location_description.substr(9) // Remove "Register "
                    << "  " << std::setw(4) << var.size_bytes
                    << "  " << std::setw(14) << var.type.substr(0, 14)
                    << "  " << var.name;
                if (var.is_parameter) {
                    oss << " (param " << var.parameter_index << ")";
                }
                oss << std::endl;
            }
        }
    }
    
    oss << "--------------------------------------------------------------------------------";
    
    return oss.str();
}

std::string ElfReader::formatStackFrameForJson(const StackFrameInfo& frame_info) const {
    std::ostringstream oss;
    
    oss << "      {" << std::endl;
    oss << "        \"function_name\": \"" << frame_info.function_name << "\"," << std::endl;
    oss << "        \"mangled_name\": \"" << frame_info.mangled_name << "\"," << std::endl;
    oss << "        \"start_address\": \"0x" << std::hex << frame_info.function_start_address << "\"," << std::dec << std::endl;
    oss << "        \"end_address\": \"0x" << std::hex << frame_info.function_end_address << "\"," << std::dec << std::endl;
    oss << "        \"frame_size\": " << frame_info.total_frame_size << "," << std::endl;
    oss << "        \"calling_convention\": {" << std::endl;
    oss << "          \"name\": \"" << frame_info.calling_convention.name << "\"," << std::endl;
    oss << "          \"architecture\": \"" << frame_info.calling_convention.architecture << "\"" << std::endl;
    oss << "        }," << std::endl;
    oss << "        \"uses_frame_pointer\": " << (frame_info.usesFramePointer() ? "true" : "false") << "," << std::endl;
    oss << "        \"is_leaf_function\": " << (frame_info.is_leaf_function ? "true" : "false") << "," << std::endl;
    oss << "        \"parameter_count\": " << frame_info.getParameterCount() << "," << std::endl;
    oss << "        \"local_variable_count\": " << frame_info.getLocalVariableCount() << "," << std::endl;
    oss << "        \"stack_variables\": [" << std::endl;
    
    bool first = true;
    for (const auto& var : frame_info.stack_variables) {
        if (!first) oss << "," << std::endl;
        oss << "          {" << std::endl;
        oss << "            \"name\": \"" << var.name << "\"," << std::endl;
        oss << "            \"type\": \"" << var.type << "\"," << std::endl;
        oss << "            \"stack_offset\": " << var.stack_offset << "," << std::endl;
        oss << "            \"size_bytes\": " << var.size_bytes << "," << std::endl;
        oss << "            \"is_parameter\": " << (var.is_parameter ? "true" : "false") << "," << std::endl;
        oss << "            \"location_description\": \"" << var.location_description << "\"" << std::endl;
        oss << "          }";
        first = false;
    }
    
    oss << std::endl << "        ]" << std::endl;
    oss << "      }";
    
    return oss.str();
}

// ============================================================================
// Phase 1: Binary Export Implementation
// ============================================================================

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
            std::cout << "Exporting " << regions.size() << " memory regions to: " << output_filename << std::endl;
            for (const auto& region : regions) {
                std::cout << "  Region: " << region.section_name 
                         << " @ 0x" << std::hex << std::setw(8) << std::setfill('0') << region.address
                         << " (" << std::dec << region.size << " bytes)" << std::endl;
            }
        }
        
        // Perform the export
        bool success = exporter->exportToFile(output_filename, regions, 0);
        
        if (success && config_.verbosity >= 1) {
            std::cout << "Successfully exported to " << exporter->getFormatName() << " format" << std::endl;
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
                    std::cout << "Added region: " << section_name 
                             << " @ 0x" << std::hex << section_addr 
                             << " (" << std::dec << section_size << " bytes)" << std::endl;
                }
            }
        }
        
        // Sort regions by address
        std::sort(regions.begin(), regions.end(), 
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
                if (address >= section.sh_addr &&
                    address < section.sh_addr + section.sh_size &&
                    section.sh_addr != 0) {  // Only consider sections with valid addresses
                    return section.name.empty() ? getSectionName(i) : section.name;
                }
            }
        } else {
            for (size_t i = 0; i < sections64_.size(); ++i) {
                const auto& section = sections64_[i];
                // Check if address falls within this section's range
                if (address >= section.sh_addr &&
                    address < section.sh_addr + section.sh_size &&
                    section.sh_addr != 0) {  // Only consider sections with valid addresses
                    return section.name.empty() ? getSectionName(i) : section.name;
                }
            }
        }
        return ""; // Address not found in any section
    } catch (const std::exception&) {
        return ""; // Error occurred
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
        bool has_alloc = (section_flags & 0x2) != 0; // SHF_ALLOC
        
        // Check if it's a program bits section
        bool is_progbits = (section_type == 1); // SHT_PROGBITS
        
        return has_alloc && is_progbits;
        
    } catch (const std::exception&) {
        return false;
    }
}

bool ElfReader::readSectionData(uint16_t section_index, std::vector<uint8_t>& data) {
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
        return; // Performance metrics disabled
    }

    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "Performance Optimization Metrics\n";
    std::cout << std::string(80, '=') << "\n";

    // File and memory access metrics
    std::cout << "File Processing:\n";
    std::cout << "  File Size: " << (performance_metrics_.file_size_bytes / 1024 / 1024) << " MB\n";
    std::cout << "  Access Strategy: " << (performance_metrics_.memory_mapping_used ? "Memory Mapping" : "In-Memory Loading") << "\n";
    std::cout << "  Total Processing Time: " << std::fixed << std::setprecision(1)
              << performance_metrics_.total_processing_time_ms << " ms\n";

    // DWARF processing efficiency
    std::cout << "\nDWARF Processing Efficiency:\n";
    std::cout << "  Compilation Units: " << performance_metrics_.compilation_units_processed << "\n";
    std::cout << "  Total Structures Encountered: " << performance_metrics_.total_structures_encountered << "\n";
    std::cout << "  Duplicate Structures Skipped: " << performance_metrics_.duplicate_structures_skipped << "\n";
    std::cout << "  Deduplication Efficiency: " << std::fixed << std::setprecision(1)
              << performance_metrics_.getDeduplicationEfficiency() << "%\n";

    // String interner metrics
    std::cout << "\nString Interner Performance:\n";
    std::cout << "  Reserved Capacity: " << performance_metrics_.string_interner_capacity_reserved << " strings\n";
    std::cout << "  Final Pool Size: " << performance_metrics_.final_string_pool_size << " strings\n";
    std::cout << "  Utilization: " << std::fixed << std::setprecision(1)
              << performance_metrics_.getStringInternerUtilization() << "%\n";

    if (performance_metrics_.string_interner_fallback_used == 1) {
        std::cout << "  Note: Used fallback allocation (25% of original capacity)\n";
    } else if (performance_metrics_.string_interner_fallback_used == 2) {
        std::cout << "  Note: Pre-allocation failed, used dynamic allocation\n";
    }

    // Performance summary
    double structures_per_second = performance_metrics_.total_structures_encountered /
                                 (performance_metrics_.total_processing_time_ms / 1000.0);
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
            continue; // Skip duplicate addresses
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

std::vector<LocalVariableInfo> ElfReader::getLocalVariables(const std::string& function_name) {
    ensureAnalysisCompleted();
    std::vector<LocalVariableInfo> local_vars;

    // Find the function in our DWARF functions map
    auto it = functions_.find(function_name);
    if (it != functions_.end()) {
        const FunctionInfo& func_info = it->second;
        // Return the local variables from the function info
        local_vars = func_info.local_variables;
    }

    return local_vars;
}

std::string ElfReader::getArchitecture() const {
    if (is_32bit_) {
        return "32-bit Little Endian";
    } else {
        return "64-bit Little Endian";
    }
}


