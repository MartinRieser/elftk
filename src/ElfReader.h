/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "ElfExceptions.h"
#include "ElfMemoryValidator.h"
#include "ElfStructures.h"
#include "ElfSymbolExtractor.h"
#include "FileAccessStrategy.h"
// StringInterner replaced with ThreadSafeStringInterner
#include "ThreadSafeContainers.h"

// Parallel processing support
#include "ParallelWorkDistribution.h"
#include "ThreadPool.h"

// Forward declarations
struct ExportMemoryRegion;
class OutputGenerator;
class DwarfTypeResolver;

// Forward declarations for libdwarf
typedef struct Dwarf_Debug_s* Dwarf_Debug;
typedef struct Dwarf_Error_s* Dwarf_Error;

/**
 * @brief Cross-platform libdwarf API wrapper
 *
 * Abstracts platform-specific differences in libdwarf API between
 * different operating systems and library versions.
 */
class DwarfInitializer {
public:
    /**
     * @brief Initialize libdwarf with platform-appropriate API
     * @param filename ELF file path
     * @param dbg Output debug context
     * @return true if initialization succeeded
     */
    static bool initialize(const std::string& filename, Dwarf_Debug& dbg);

    /**
     * @brief Clean up libdwarf resources with platform-appropriate API
     * @param dbg Debug context to clean up
     */
    static void cleanup(Dwarf_Debug dbg);
};

/**
 * @file ElfReader.h
 * @brief Main class for analyzing ARM ELF binaries and extracting structure information
 *
 * This file contains the ElfReader class, which is the core component for parsing
 * ARM ELF (Executable and Linkable Format) binary files and extracting detailed
 * information about C++ classes, C structures, variables, and their memory layouts.
 *
 * The class uses DWARF debug information to automatically discover and analyze
 * structure members, providing precise memory addresses and type information.
 *
 * @author ELF Symbol Reader Project
 * @date 2025
 */

/**
 * @brief Performance optimization constants for ELF processing
 *
 * These constants define thresholds and multipliers used for performance optimizations
 * when processing large ELF files, particularly embedded firmware binaries.
 */
namespace ElfOptimization {
/** @brief Memory mapping threshold - files larger than this use mmap instead of loading into RAM */
constexpr size_t DEFAULT_MMAP_THRESHOLD = 10 * 1024 * 1024;  // 10MB

/** @brief String interner capacity multiplier per MB of file size for large files */
constexpr size_t STRING_CAPACITY_MULTIPLIER = 1000;

/** @brief File size threshold above which to pre-allocate string interner capacity */
constexpr size_t STRING_CAPACITY_THRESHOLD_MB = 20;

/** @brief Maximum string interner capacity to prevent excessive memory usage */
constexpr size_t MAX_STRING_CAPACITY = 200000;  // Cap at 200K strings

/** @brief Progress reporting interval for compilation unit processing */
constexpr int PROGRESS_REPORT_INTERVAL = 100;

/** @brief Enable performance metrics collection and reporting */
constexpr bool ENABLE_PERFORMANCE_METRICS = true;
}  // namespace ElfOptimization

/**
 * @brief Type size constants for DWARF type resolution
 *
 * Standard sizes for C/C++ types on ARM embedded systems (32-bit).
 * These match ARM EABI (Embedded Application Binary Interface) specifications.
 */
namespace TypeSizes {
constexpr uint64_t CHAR_SIZE = 1;       ///< sizeof(char) = 1 byte
constexpr uint64_t SHORT_SIZE = 2;      ///< sizeof(short) = 2 bytes
constexpr uint64_t INT_SIZE = 4;        ///< sizeof(int) = 4 bytes
constexpr uint64_t LONG_LONG_SIZE = 8;  ///< sizeof(long long) = 8 bytes
constexpr uint64_t FLOAT_SIZE = 4;      ///< sizeof(float) = 4 bytes (IEEE 754 single precision)
constexpr uint64_t DOUBLE_SIZE = 8;     ///< sizeof(double) = 8 bytes (IEEE 754 double precision)
constexpr uint64_t POINTER_SIZE = 4;    ///< sizeof(void*) = 4 bytes on 32-bit ARM
constexpr uint64_t DEFAULT_SIZE = 4;    ///< Default size for unknown types
}  // namespace TypeSizes

/**
 * @brief ELF structure size constants
 *
 * Fixed sizes defined by ELF specification for 32-bit and 64-bit formats.
 */
namespace ElfSizes {
constexpr size_t ELF32_SYM_SIZE = 16;  ///< sizeof(Elf32_Sym) = 16 bytes
constexpr size_t ELF64_SYM_SIZE = 24;  ///< sizeof(Elf64_Sym) = 24 bytes
}  // namespace ElfSizes

/**
 * @brief Safety limits and thresholds for parsing
 *
 * These constants prevent unbounded operations and protect against malformed input.
 */
namespace ParsingLimits {
constexpr size_t MAX_STRING_LENGTH = 4096;          ///< Maximum string read from ELF file (4KB)
constexpr size_t MAX_CACHE_SIZE = 1000;             ///< Maximum cached type entries
constexpr uint64_t LOW_MEMORY_THRESHOLD = 0x10000;  ///< 64KB - typical RAM start for embedded
constexpr uint32_t DEFAULT_VECTOR_ENTRY_SIZE = 4;   ///< Interrupt vector entry size (ARM)
constexpr uint32_t MIN_SIGNIFICANT_IRQ = 16;        ///< First user-definable IRQ on ARM Cortex-M
}  // namespace ParsingLimits

/**
 * @brief ASCII character range constants
 *
 * Used for validating printable characters when reading strings and constants.
 */
namespace AsciiChars {
constexpr int PRINTABLE_MIN = 32;   ///< First printable ASCII (space)
constexpr int PRINTABLE_MAX = 126;  ///< Last printable ASCII (~)
constexpr int BACKSLASH = 92;       ///< Backslash character (requires escaping)
}  // namespace AsciiChars

/**
 * @brief Performance optimization: Custom key type for efficient DWARF structure deduplication
 *
 * Uses std::pair instead of string concatenation for better performance and memory efficiency.
 * Avoids string allocation overhead when checking for duplicate structures during DWARF parsing.
 */
using DieKey = std::pair<std::string, uint64_t>;  // (structure_name, die_offset)

/**
 * @brief Custom hash function for DieKey to enable use in unordered containers
 */
struct DieKeyHash {
    std::size_t operator()(const DieKey& key) const noexcept {
        // Combine string hash with offset using standard hash combination technique
        auto h1 = std::hash<std::string>{}(key.first);
        auto h2 = std::hash<uint64_t>{}(key.second);
        return h1 ^ (h2 << 1);  // Avoid simple XOR to reduce hash collisions
    }
};

/**
 * @brief Performance metrics collection for optimization analysis
 *
 * Tracks the effectiveness of various performance optimizations including
 * deduplication, memory allocation efficiency, and processing time breakdown.
 */
struct PerformanceMetrics {
    // DWARF processing metrics
    size_t total_structures_encountered = 0;  ///< Total structure DIEs processed
    size_t duplicate_structures_skipped = 0;  ///< Structures skipped due to deduplication
    size_t compilation_units_processed = 0;   ///< Number of compilation units processed

    // Memory allocation metrics
    size_t string_interner_capacity_reserved = 0;  ///< Pre-allocated string capacity
    size_t string_interner_fallback_used = 0;      ///< Whether fallback allocation was used
    size_t final_string_pool_size = 0;             ///< Final number of unique strings

    // Timing metrics (in milliseconds)
    double dwarf_parsing_time_ms = 0.0;         ///< Time spent parsing DWARF info
    double structure_extraction_time_ms = 0.0;  ///< Time spent extracting structures
    double total_processing_time_ms = 0.0;      ///< Total ELF processing time

    // File access metrics
    bool memory_mapping_used = false;  ///< Whether file used memory mapping
    size_t file_size_bytes = 0;        ///< Size of processed ELF file

    /**
     * @brief Calculate deduplication efficiency percentage
     * @return Percentage of duplicate structures avoided (0-100)
     */
    double getDeduplicationEfficiency() const {
        if (total_structures_encountered == 0)
            return 0.0;
        return (static_cast<double>(duplicate_structures_skipped) / total_structures_encountered) *
               100.0;
    }

    /**
     * @brief Calculate string interner utilization percentage
     * @return Percentage of reserved capacity actually used (0-100+)
     */
    double getStringInternerUtilization() const {
        if (string_interner_capacity_reserved == 0)
            return 0.0;
        return (static_cast<double>(final_string_pool_size) / string_interner_capacity_reserved) *
               100.0;
    }
};

struct Config {
    std::string inputFile;
    std::string format = "csv";
    bool functionsOnly = false;
    bool variablesOnly = false;
    int verbosity = 0;
    bool showSections = false;  ///< Show section names in output for all symbols
    size_t mmapThreshold =
        ElfOptimization::DEFAULT_MMAP_THRESHOLD;  ///< Memory mapping threshold for large files

    // Binary Export Options
    std::string exportFormat;    ///< Export format ("hex", "s19", "s28", "s37", "bin")
    bool constantsOnly = false;  ///< Show only constants

    // Memory Layout Options
    bool extractInterruptVectors = false;  ///< Extract and display interrupt vector table
    bool extractMemoryRegions = false;     ///< Extract and display memory region mapping
    bool showMemoryLayout = false;         ///< Show ELF memory layout from program headers

    // Symbol extraction options
    bool enableElfSymbolExtraction = true;  ///< Enable ELF symbol table extraction
    bool enableCxxDemangling = true;        ///< Enable C++ symbol demangling
    bool showMangledNames = false;          ///< Show original mangled names in brackets
    bool enableSectionDiscovery = true;     ///< Enable section-based variable discovery

    // External validation framework options
    std::string validateTool;  ///< External validation tool ("gdb", "objdump", "readelf", "all")
    std::string validationOutput;  ///< Output file for validation report

    // Parallel processing options (always enabled with auto-detection)
    bool enableParallelProcessing = true;  ///< Enable parallel DWARF processing (always on)
    size_t threadCount = 0;                ///< Number of worker threads (0 = auto-detect)
    size_t parallelCUTThreshold = 10;      ///< Minimum CUs to enable parallel processing
    bool enableWorkStealing = true;        ///< Enable work-stealing load balancing

    // Enhanced Symbol Extraction Options (default for comprehensive analysis)
    size_t maxArrayExpansion =
        10;  ///< Maximum array elements to expand (default: 10 for reasonable output)
    bool hierarchicalOutput = true;  ///< Enable hierarchical symbol display (default: true)
    uint32_t hierarchyDepth = 0;     ///< Maximum hierarchy depth (0 = unlimited, default: 0)
    bool showAllMembers = true;  ///< Show all members including nested structures (default: true)
    bool flattenOutput = false;  ///< Flatten hierarchical output to legacy format (default: false)
};

/**
 * @class ElfReader
 * @brief Core class for ARM/RISC-V ELF binary analysis and structure extraction
 *
 * ElfReader is the main analysis engine that processes ARM, RISC-V, ARM64, and Xtensa ELF binary
 * files and extracts detailed information about C++ classes, C structures, global variables, and
 * functions. It automatically discovers structure layouts using DWARF debug information and
 * provides member-level analysis with precise memory addresses.
 *
 * ## Key Features:
 * - Automatic structure discovery from DWARF debug info (no hardcoded definitions)
 * - Member-level analysis with recursive expansion (5+ levels deep)
 * - ARM ABI-compliant memory layout calculation
 * - C++ name demangling and namespace support
 * - Support for ARM architectures (Cortex-M/A/R, classic ARM) and RISC-V (RV32/RV64)
 *
 * ## Usage Example:
 * ```cpp
 * try {
 *     ElfReader reader("firmware.elf");
 *     reader.analyzeMemberParameters();  // Outputs analysis to stdout
 * } catch (const std::exception& e) {
 *     std::cerr << "Analysis failed: " << e.what() << std::endl;
 * }
 * ```
 *
 * ## Input Requirements:
 * - ARM, RISC-V, or Xtensa ELF binary (32-bit or 64-bit, little-endian)
 * - Must be compiled with debug information (`-g` flag)
 * - DWARF debug sections must be present
 *
 * ## Output Format:
 * The analysis produces formatted output showing:
 * - Architecture information (32-bit Little Endian, Entry Point)
 * - Global variables with addresses and types
 * - Structure members with nested expansion
 * - Function symbols with addresses
 *
 * @see analyzeMemberParameters() for the main analysis entry point
 * @see ElfStructures.h for ELF format definitions
 */
class ElfReader {
public:
    /**
     * @brief Constructs an ElfReader and loads the specified ELF binary file
     *
     * Creates a new ElfReader instance and immediately loads the specified ARM ELF
     * binary file into memory for analysis. The constructor performs initial validation
     * of the ELF format and extracts basic header information.
     *
     * ## What happens during construction:
     * 1. File is loaded into memory buffer
     * 2. ELF header is parsed and validated
     * 3. Architecture detection (32-bit ARM, little-endian)
     * 4. Section headers are extracted
     * 5. Symbol tables and string tables are parsed
     * 6. DWARF debug information is processed (if present)
     *
     * @param filename Path to the ARM ELF binary file to analyze
     *
     * @throws ElfReaderExceptions::ElfFileError if file cannot be opened, read, or is invalid
     * @throws ElfReaderExceptions::MemoryAccessError if file access violates memory boundaries
     *
     * ## Example Usage:
     * ```cpp
     * // Input: ARM ELF file compiled with debug info
     * ElfReader reader("examples/cpp/main.elf");
     *
     * // After construction, reader contains:
     * // - File data loaded in memory
     * // - ELF header parsed (architecture: ARM, 32-bit, little-endian)
     * // - Sections discovered (symbol table, string tables, debug info)
     * // - DWARF types extracted (classes, structs, variables)
     * ```
     *
     * ## Input File Requirements:
     * - Must be ARM ELF binary (32-bit, little-endian)
     * - Compiled with `-g` flag for debug information
     * - Contains .symtab, .strtab sections
     * - Preferably contains .debug_info, .debug_str sections
     *
     * @note The constructor is explicit to prevent implicit string-to-ElfReader conversions
     * @see analyzeMemberParameters() to perform the actual structure analysis
     */
    explicit ElfReader(const std::string& filename);
    ElfReader(const std::string& filename, const Config& config);
    explicit ElfReader(const Config& config);

    /**
     * @brief Default destructor
     *
     * The destructor is defaulted because all member variables use RAII
     * (Resource Acquisition Is Initialization) and will clean up automatically.
     * No manual cleanup is needed for vectors, maps, or other containers.
     */
    ~ElfReader();

    /**
     * @brief Performs complete member-level analysis and outputs results to stdout
     *
     * This is the main entry point for ELF analysis. It processes all discovered
     * symbols and structures, recursively expands structure members, calculates
     * precise memory addresses, and outputs formatted results showing the complete
     * memory layout of the ARM binary.
     *
     * ## Analysis Process:
     * 1. **Symbol Processing**: Iterates through all global symbols (variables, functions)
     * 2. **Type Resolution**: Matches symbols with DWARF type information
     * 3. **Structure Expansion**: Recursively expands C++ classes and C structures
     * 4. **Address Calculation**: Computes precise member addresses using ARM ABI rules
     * 5. **Output Generation**: Formats and prints analysis results to stdout
     *
     * ## Output Format Example:
     * ```
     * Member-Level ELF Analysis: firmware.elf
     * ================================================================================
     * Architecture: 32-bit Little Endian
     * Entry Point: 0x08000001
     *
     * Variables and struct members:
     * --------------------------------------------------------------------------------
     * global_int, 0x20000000, int
     * sensor_data.temperature, 0x20000010, float
     * sensor_data.humidity, 0x20000014, uint8_t
     * device_config.settings.timeout, 0x20000020, uint32_t
     *
     * Functions:
     * --------------------------------------------------------------------------------
     * main, 0x08000001, function
     * init_sensors, 0x08000045, function
     * ```
     *
     * ## What gets analyzed:
     * - **Global Variables**: All global variables with their types and addresses
     * - **Structure Members**: Recursive expansion of C++ classes and C structures
     * - **Nested Types**: Deep nesting (5+ levels) with full path names
     * - **Arrays**: Multi-dimensional arrays with element types
     * - **Functions**: All function symbols with entry point addresses
     *
     * @throws std::runtime_error if analysis fails due to corrupted debug information
     * @throws std::runtime_error if required DWARF sections are malformed
     *
     * ## Example Usage:
     * ```cpp
     * ElfReader reader("firmware.elf");
     *
     * // Input state: ELF file loaded, DWARF parsed, types discovered
     * reader.analyzeMemberParameters();
     *
     * // Output: Complete analysis printed to stdout
     * // Side effects: None (read-only analysis)
     * ```
     *
     * @note This method only reads data and produces output; it doesn't modify the ELF file
     * @note Output goes to stdout; redirect to file if needed: `./program file.elf > analysis.txt`
     * @see expandStructureMembers() for the recursive structure expansion logic
     */
    void analyzeMemberParameters();

    /**
     * @brief Perform binary export to specified format
     *
     * Extracts loadable sections from the ELF file and exports them to the
     * format specified in config_.exportFormat with optional address offset.
     *
     * @return true if export succeeded, false on error
     */
    bool performBinaryExport();

    // ==========================================
    // Library API Methods
    // ==========================================

    /**
     * @brief Get all variables found in the ELF binary
     *
     * Extracts all global variables, struct members, and constants from the ELF file
     * and returns them as a vector of MemberInfo structures for programmatic access.
     *
     * @return Vector of MemberInfo structures containing variable information
     * @note This method performs the same analysis as analyzeMemberParameters() but returns data
     * instead of printing
     * @example
     * ```cpp
     * ElfReader reader("firmware.elf");
     * auto variables = reader.getVariables();
     * for (const auto& var : variables) {
     *     std::cout << var.name << " at 0x" << std::hex << var.address << std::endl;
     * }
     * ```
     */
    std::vector<MemberInfo> getVariables();

    /**
     * @brief Get all functions found in the ELF binary
     *
     * Extracts all function information including addresses, stack frames, and local variables.
     *
     * @return Vector of FunctionInfo structures containing function details
     * @example
     * ```cpp
     * ElfReader reader("firmware.elf");
     * auto functions = reader.getFunctions();
     * for (const auto& func : functions) {
     *     std::cout << func.name << " at 0x" << std::hex << func.start_address << std::endl;
     * }
     * ```
     */
    std::vector<FunctionInfo> getFunctions();

    /**
     * @brief Get only constants from the ELF binary
     *
     * Filters variables to return only those marked as constants with their values.
     *
     * @return Vector of MemberInfo structures containing only constant variables
     * @example
     * ```cpp
     * ElfReader reader("firmware.elf");
     * auto constants = reader.getConstants();
     * for (const auto& constant : constants) {
     *     std::cout << constant.name << " = " << constant.constant_value << std::endl;
     * }
     * ```
     */
    std::vector<MemberInfo> getConstants();

    /**
     * @brief Get architecture information from the ELF binary
     *
     * Returns architecture details extracted from ELF header.
     *
     * @return String describing the architecture (e.g., "32-bit Little Endian")
     */
    std::string getArchitecture() const;

    /**
     * @brief Get entry point address from the ELF binary
     *
     * Returns the entry point address where program execution begins.
     *
     * @return Entry point address as a 64-bit integer
     */
    uint64_t getEntryPoint() const;

    /**
     * @brief Add enhanced symbols to the analysis results
     *
     * Integrates ELF symbol table analysis results with DWARF analysis.
     * Converts enhanced symbols to MemberInfo format and merges with existing results.
     *
     * @param enhanced_symbols Enhanced symbols from ElfSymbolExtractor
     */
    void addEnhancedSymbols(const std::vector<ExtractedSymbol>& enhanced_symbols);

    // ========================================================================
    // Advanced Type Resolution
    // ========================================================================

    /**
     * @brief Type identifier for unique type resolution
     *
     * Contains multiple identifiers for robust type lookup when dealing with
     * potentially ambiguous type names. Uses C++ linkage names as the primary
     * unique identifier, with qualified names as fallback for C structures.
     */
    struct TypeIdentifier {
        std::string linkage_name;    ///< C++ mangled name for unique identification
        std::string qualified_name;  ///< Namespace-qualified name (e.g., "Namespace::TypeName")
        Dwarf_Off die_offset;        ///< DWARF DIE offset for direct access

        TypeIdentifier() : die_offset(0) {}
    };

    /**
     * @brief Follow DWARF type reference chain to resolve the actual type
     *
     * Resolves type ambiguity by following DW_AT_type reference chains through
     * const/volatile/typedef/pointer qualifiers until reaching the underlying
     * structure or class definition. Extracts both the C++ linkage name (when
     * available) for unique identification and the qualified name as fallback.
     *
     * This is critical for correctly identifying types in programs where multiple
     * different types may share the same simple name (common in C++ with nested
     * types or templates).
     *
     * @param dbg DWARF debug handle
     * @param start_die Starting DIE (variable, member, parameter, etc.)
     * @return TypeIdentifier containing linkage_name, qualified_name, and DIE offset
     *
     * ## Example Resolution Chain:
     * ```
     * Variable DIE
     *   → DW_AT_type → const qualifier DIE
     *     → DW_AT_type → typedef DIE
     *       → DW_AT_type → structure DIE (final type)
     *         → DW_AT_linkage_name: mangled C++ name (unique)
     *         → DW_AT_name: simple name
     * ```
     *
     * ## Return Value:
     * - linkage_name: C++ mangled name (empty for plain C structs)
     * - qualified_name: Namespace::TypeName or simple TypeName
     * - die_offset: DWARF DIE offset of the final type
     */
    TypeIdentifier resolveTypeIdentifier(Dwarf_Debug dbg, Dwarf_Die start_die) const;

    // ========================================================================
    // Type Match Confidence System
    // ========================================================================

    /**
     * @brief Type match confidence levels for strict constants mode
     *
     * Confidence scoring prevents wrong type expansion in constants mode.
     * Higher confidence = more reliable type match.
     */
    enum class TypeMatchConfidence {
        EXACT_LINKAGE_NAME,    ///< Unique C++ mangled name - 100% confidence
        EXACT_QUALIFIED_NAME,  ///< Fully qualified name, no ambiguity - 90% confidence
        EXACT_DIE_OFFSET,      ///< DIE offset match - 85% confidence
        SINGLE_SIMPLE_MATCH,   ///< Simple name with only ONE match - 70% confidence
        AMBIGUOUS_NAME,        ///< Simple name, multiple matches - 20% confidence
        NO_MATCH               ///< Type not found - 0% confidence
    };

    /**
     * @brief Get confidence level for a type name match
     *
     * Evaluates how reliably we can resolve a type name to the correct type.
     * Used in constants mode to prevent expanding structures with wrong members.
     *
     * @param type_name Type name to evaluate (could be linkage name, qualified name, or simple
     * name)
     * @return TypeMatchConfidence indicating reliability of the match
     *
     * ## Confidence Levels:
     * - EXACT_LINKAGE_NAME (100%): C++ mangled name (e.g., "N9Namespace8TypeNameE") - UNIQUE!
     * - EXACT_QUALIFIED_NAME (90%): Fully qualified name (e.g., "Namespace::TypeName") - usually
     * unique
     * - EXACT_DIE_OFFSET (85%): Type with DIE offset key (e.g., "TypeName@0x1a2b3c") - unique per
     * compilation unit
     * - SINGLE_SIMPLE_MATCH (70%): Simple name with exactly one type definition (safe)
     * - AMBIGUOUS_NAME (20%): Simple name with multiple possible types (DANGEROUS!)
     * - NO_MATCH (0%): Type not found in registry
     *
     * ## Usage Example:
     * ```cpp
     * if (config_.constantsOnly) {
     *     auto confidence = getTypeMatchConfidence(type_name);
     *     if (confidence == TypeMatchConfidence::AMBIGUOUS_NAME) {
     *         // DON'T expand - better to show no members than WRONG members!
     *         return single_unexpanded_member;
     *     }
     * }
     * ```
     */
    TypeMatchConfidence getTypeMatchConfidence(const std::string& type_name) const;

private:
    // Binary Export Helper Methods
    std::vector<ExportMemoryRegion> extractMemoryRegions();
    std::string getSectionName(uint16_t section_index) const;
    std::string getSectionNameForAddress(uint64_t address) const;
    bool isSectionLoadable(uint16_t section_index);
    bool readSectionData(uint16_t section_index, std::vector<uint8_t>& data) const;

    // Refactored analysis methods
    void analyzeInterruptVectors();
    void analyzeMemoryRegions();
    void analyzeVariablesAndMembers();
    void analyzeFunctions();

    /**
     * @brief Template method to process symbol table (32-bit or 64-bit)
     *
     * Eliminates code duplication between 32-bit and 64-bit symbol processing.
     * Handles demangling, duplicate detection, type resolution, and member expansion.
     *
     * @tparam SymbolType Either Elf32_Sym or Elf64_Sym
     * @param symbols Vector of symbols to process
     * @param processed_symbols Set of already-processed symbol names (for deduplication)
     * @param all_members Vector to append discovered members to
     */
    template<typename ElfSymType>
    void processSymbolTable(const std::vector<ElfSymType>& symbols,
                            std::set<std::string>& processed_symbols,
                            std::vector<MemberInfo>& all_members) {
        for (const auto& symbol : symbols) {
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

                // Use demangled name for display
                std::string display_name =
                    (demangled_name != symbol_name) ? demangled_name : symbol_name;

                if (!type_name.empty()) {
                    auto members = expandStructureMembers(display_name, type_name, symbol_address);
                    all_members.insert(all_members.end(), members.begin(), members.end());
                } else {
                    // If we don't know the structure, just show the object itself
                    uint64_t object_size =
                        4;  // Default size for unknown objects (OBJECT type always returns 0)
                    MemberInfo object_member(string_interner_.intern(display_name),
                                             symbol_address,
                                             string_interner_.intern("OBJECT"),
                                             object_size);
                    if (config_.showSections) {
                        object_member.section_name = getSectionNameForAddress(symbol_address);
                    }
                    all_members.push_back(object_member);
                }
            }
        }
    }
    // ========================================================================
    // Core File Data Members
    // ========================================================================

    Config config_;

    /**
     * @brief Output generator for JSON/CSV formatting
     *
     * Handles all output generation for variables, functions, and analysis results.
     * Extracted from ElfReader to improve modularity and testability.
     */
    std::unique_ptr<OutputGenerator> output_generator_;

    /** @brief Path to the ELF binary file being analyzed */
    std::string filename_;

    /**
     * @brief File access strategy for efficient ELF file reading
     *
     * Handles file I/O with memory mapping optimization for large files.
     * Configurable threshold (default 100MB) for mmap vs regular I/O.
     * Platform-specific optimizations are applied automatically.
     */
    std::unique_ptr<FileAccessStrategy> file_access_;

    /**
     * @brief Memory validator for safe ELF file operations
     *
     * Provides comprehensive bounds checking and input validation for all ELF
     * file access operations. Prevents buffer overflows, integer overflow attacks,
     * and malicious input processing vulnerabilities.
     */
    std::unique_ptr<ElfReaderUtils::ElfMemoryValidator> memory_validator_;

    /**
     * @brief String interning system for memory optimization
     *
     * Manages a pool of unique strings to eliminate duplicate string storage.
     * Symbol names, type names, and member names are interned to reduce memory usage
     * by 15-30% in typical ELF files with many repeated identifiers.
     *
     * Example: Multiple symbols named "main" share the same string object
     */
    mutable ThreadSafeStringInterner string_interner_;

    /**
     * @brief Cache for demangled C++ symbol names
     *
     * Stores the mapping from mangled name → demangled name to avoid
     * repeated expensive demangling operations for the same symbol.
     *
     * Example: "_ZN9Namespace7MyClass8myMethodE" → "Namespace::MyClass::myMethod"
     *
     * Performance impact: Reduces demangling overhead by ~80% for large
     * firmware binaries with many C++ symbols.
     */
    mutable std::unordered_map<std::string, std::string> demangled_cache_;

    /**
     * @brief Flag indicating if this is a 32-bit ELF file
     *
     * ARM embedded systems typically use 32-bit ELF format.
     * - true: 32-bit ELF (ELFCLASS32) - typical for ARM Cortex-M/A/R
     * - false: 64-bit ELF (ELFCLASS64) - used for ARM64/AArch64
     */
    bool is_32bit_;

    /**
     * @brief Flag indicating byte order (endianness) of the ELF file
     *
     * ARM processors typically use little-endian byte ordering.
     * - true: Little-endian (LSB first) - standard for ARM
     * - false: Big-endian (MSB first) - rare for ARM
     */
    bool is_little_endian_;

    // ========================================================================
    // ELF Header Information
    // ========================================================================

    /**
     * @brief ELF header structure (32-bit or 64-bit)
     *
     * Union containing either 32-bit or 64-bit ELF header. The correct
     * variant is selected based on is_32bit_ flag. Contains essential
     * information like entry point, architecture, and section locations.
     *
     * Example content for ARM Cortex-M:
     * - Entry point: 0x08000001 (ARM Thumb mode)
     * - Machine type: EM_ARM (0x28)
     * - Section header offset: points to section table
     */
    union {
        Elf32_Ehdr ehdr32_;  ///< 32-bit ELF header (most common for ARM)
        Elf64_Ehdr ehdr64_;  ///< 64-bit ELF header (for ARM64/AArch64)
    };

    // ========================================================================
    // ELF Sections and Symbols
    // ========================================================================

    /**
     * @brief 32-bit section headers describing ELF file structure
     *
     * Each section header describes a segment of the ELF file (code, data,
     * symbols, strings, debug info). Used when is_32bit_ is true.
     *
     * Example sections in ARM firmware:
     * - .text: Program code
     * - .data: Initialized global variables
     * - .bss: Uninitialized global variables
     * - .symtab: Symbol table
     * - .debug_info: DWARF debug information
     */
    std::vector<Elf32_Shdr> sections32_;

    /** @brief 64-bit section headers (for ARM64 binaries) */
    std::vector<Elf64_Shdr> sections64_;

    /**
     * @brief 32-bit symbol table entries
     *
     * Contains all symbols (functions, variables, etc.) found in the ELF file.
     * Each symbol has a name, address, size, and type information.
     *
     * Example symbols:
     * - main: function at 0x08000001
     * - global_counter: variable at 0x20000000
     * - sensor_data: structure at 0x20000010
     */
    std::vector<Elf32_Sym> symbols32_;

    /** @brief 64-bit symbol table entries (for ARM64 binaries) */
    std::vector<Elf64_Sym> symbols64_;

    // ========================================================================
    // String and Type Information
    // ========================================================================

    /**
     * @brief String tables mapping section indices to string data
     *
     * ELF files store strings (symbol names, section names) in dedicated
     * string table sections. This map provides access to string data by
     * section index.
     *
     * Key: Section table index, Value: Raw string data with null terminators
     */
    std::map<uint32_t, std::vector<char>> string_tables_;

    /**
     * @brief Type information discovered from DWARF debug data
     *
     * Maps type names to detailed structure information including member
     * layouts, sizes, and relationships. Built during DWARF parsing.
     *
     * Example entries:
     * - "SensorData" -> TypeInfo with temperature, humidity members
     * - "MyNamespace::DeviceConfig" -> TypeInfo with nested structures
     */
    ThreadSafeTypeRegistry types_;

    /**
     * @brief Performance optimization: Fast structure deduplication tracking
     *
     * Uses optimized DieKey (pair<name, offset>) instead of string concatenation
     * for O(1) lookup to prevent duplicate structure processing during DWARF parsing.
     * Significantly faster than string-based keys for large ELF files.
     *
     * Key: (structure_name, die_offset), Value: processing complete flag
     */
    std::unordered_map<DieKey, bool, DieKeyHash> processed_dies_;

    /**
     * @brief Performance metrics collection for optimization analysis
     *
     * Tracks timing, memory usage, and effectiveness of various optimizations.
     * Only collected when ElfOptimization::ENABLE_PERFORMANCE_METRICS is true.
     */
    mutable PerformanceMetrics performance_metrics_;

    /**
     * @brief Advanced type information with DWARF 5 features
     *
     * Maps type names to enhanced type information including qualifiers,
     * template parameters, optimization hints, and performance data.
     *
     * Example entries:
     * - "const MyData" -> AdvancedTypeInfo with CONST qualifier
     * - "MyTemplate<int, 42>" -> AdvancedTypeInfo with template parameters
     */
    std::map<std::string, AdvancedTypeInfo> advanced_types_;

    /**
     * @brief Type resolution cache for performance optimization
     *
     * LRU cache storing recently resolved types to avoid redundant DWARF processing.
     * Maps type identifier to cached resolution result with timestamp.
     */
    mutable std::map<std::string, std::pair<AdvancedTypeInfo, uint64_t>> type_cache_;

    /**
     * @brief Template specialization registry
     *
     * Tracks all discovered template specializations for advanced C++ analysis.
     * Maps template base name to list of specializations with parameters.
     */
    std::map<std::string, std::vector<TemplateInfo>> template_specializations_;

    /**
     * @brief Interrupt vector table information
     *
     * Contains extracted interrupt vector table data when --interrupt-vectors flag is used.
     * Provides comprehensive mapping of interrupt vectors to handler functions.
     */
    InterruptVectorTable interrupt_vector_table_;
    MemoryRegionMap memory_region_map_;

    // ========================================================================
    // Parallel Processing Infrastructure
    // ========================================================================

    /**
     * @brief Thread pool for parallel DWARF processing
     *
     * Provides worker threads for parallel compilation unit processing,
     * symbol table analysis, and structure member expansion.
     */
    std::unique_ptr<ThreadPool> thread_pool_;

    // ========================================================================
    // DWARF Debug Information Structures
    // ========================================================================

    /**
     * @brief Structure containing variable information from DWARF debug data
     *
     * This internal structure holds comprehensive information about variables
     * discovered in the DWARF debug sections, including both the original
     * mangled names and human-readable demangled names.
     */
    struct VariableInfo {
        std::string name;            ///< Original symbol name (may be mangled)
        std::string demangled_name;  ///< Human-readable C++ name
        std::string type_name;       ///< DWARF-derived type name
        uint64_t address;            ///< Memory address in target system
        bool is_global;              ///< Global vs local variable scope
        bool is_constant;            ///< True if this is a constant variable
        std::string constant_value;  ///< String representation of constant value

        /** @brief Default constructor initializes to safe values */
        VariableInfo() : address(0), is_global(false), is_constant(false) {}

        /**
         * @brief Parameterized constructor for complete initialization
         *
         * @param n Original symbol name
         * @param dn Demangled human-readable name
         * @param tn Type name from DWARF
         * @param addr Memory address
         * @param global True if global scope
         */
        VariableInfo(const std::string_view n,
                     const std::string_view dn,
                     const std::string_view tn,
                     uint64_t addr,
                     bool global)
            : name(n),
              demangled_name(dn),
              type_name(tn),
              address(addr),
              is_global(global),
              is_constant(false) {}

        /**
         * @brief Constructor with constant value support
         *
         * @param n Original symbol name
         * @param dn Demangled human-readable name
         * @param tn Type name from DWARF
         * @param addr Memory address
         * @param global True if global scope
         * @param constant True if this is a constant
         * @param const_val String representation of constant value
         */
        VariableInfo(const std::string_view n,
                     const std::string_view dn,
                     const std::string_view tn,
                     uint64_t addr,
                     bool global,
                     bool constant,
                     const std::string_view const_val)
            : name(n),
              demangled_name(dn),
              type_name(tn),
              address(addr),
              is_global(global),
              is_constant(constant),
              constant_value(const_val) {}
    };

    // ========================================================================
    // DWARF Debug Data Storage
    // ========================================================================

    /**
     * @brief Raw DWARF .debug_info section data
     *
     * Contains the complete .debug_info section as raw bytes. This section
     * contains the main DWARF debugging information including type definitions,
     * variable locations, and structure layouts.
     */
    std::vector<uint8_t> debug_info_data_;

    /**
     * @brief Raw DWARF .debug_str section data
     *
     * Contains string data referenced by DWARF debug entries. Type names,
     * variable names, and other string literals are stored here to avoid
     * duplication in the main debug info section.
     */
    std::vector<uint8_t> debug_str_data_;

    /**
     * @brief Parsed DWARF Debug Information Entries (DIEs)
     *
     * Maps DWARF offset positions to parsed DIE structures. Each DIE represents
     * a program element (type, variable, function) with its attributes.
     *
     * Key: Offset in DWARF section, Value: Parsed DIE with attributes
     */
    std::map<uint32_t, DwarfDIE> dwarf_dies_;

    /**
     * @brief Variable information extracted from DWARF
     *
     * Maps symbol names to comprehensive variable information including
     * addresses, types, and scope. Built during DWARF processing.
     *
     * Key: Symbol name, Value: Complete variable information
     */
    std::map<std::string, VariableInfo> dwarf_variables_;

    /**
     * @brief Enhanced symbols from ELF symbol table analysis
     *
     * Stores enhanced symbols extracted from ELF symbol table analysis that
     * complement DWARF debug information. Includes array bounds, weak symbols,
     * cross-reference symbols, and comprehensive ELF analysis results.
     *
     * Populated by addEnhancedSymbols() and integrated into analysis output.
     */
    std::vector<ExtractedSymbol> enhanced_symbols_;

    /**
     * @brief Function information with local variable analysis
     *
     * Maps function names to complete function information including local variables,
     * parameters, and stack frame layout. Only populated when local variable analysis
     * CLI options are enabled.
     *
     * Key: Function name, Value: Complete function information with local variables
     */
    std::map<std::string, FunctionInfo> functions_;

    /**
     * @brief Flag indicating if DWARF debug information was found and parsed
     *
     * - true: DWARF sections present and successfully parsed
     * - false: No DWARF debug info (file compiled without -g flag)
     */
    bool has_dwarf_info_;
    bool analysis_completed_;  // Flag to track if analyzeMemberParameters() has been called

    // Library API helper method
    void ensureAnalysisCompleted();

    /**
     * @brief Common initialization logic for all constructors
     * @param filename ELF file to analyze
     * @param config Configuration settings
     */
    void initializeElfReader(const std::string& filename, const Config& config);

    // ========================================================================
    // Core ELF Parsing Methods
    // ========================================================================

    /**
     * @brief Loads the complete ELF binary file into memory
     *
     * Opens and reads the entire ELF binary file specified in the constructor
     * into the data_ member variable. This provides random access to all
     * parts of the file during subsequent parsing operations.
     *
     * ## Process:
     * 1. Opens file in binary mode
     * 2. Determines file size
     * 3. Reads entire file into memory buffer
     * 4. Validates minimum file size
     *
     * @throws std::runtime_error if file cannot be opened
     * @throws std::runtime_error if file is too small to be valid ELF
     * @throws std::runtime_error if file read operation fails
     *
     * ## Example Input/Output:
     * ```
     * Input: filename_ = "firmware.elf" (50KB ARM binary)
     * Output: data_ = {0x7F, 0x45, 0x4C, 0x46, ...} (51,200 bytes loaded)
     * Side effect: File handle opened, read, and automatically closed
     * ```
     */
    void loadFile();

    /**
     * @brief Parses and validates the ELF file header
     *
     * Extracts and validates the ELF header (first 52+ bytes of file),
     * determines architecture (32/64-bit), endianness, and stores essential
     * information for subsequent parsing steps.
     *
     * ## Validation performed:
     * 1. ELF magic number verification (0x7F 'E' 'L' 'F')
     * 2. Architecture detection (32-bit/64-bit)
     * 3. Endianness detection (little/big endian)
     * 4. ARM architecture verification
     * 5. ELF header integrity checks
     *
     * @throws std::invalid_argument if file is not a valid ELF
     * @throws std::invalid_argument if not ARM architecture
     * @throws std::invalid_argument if unsupported ELF variant
     *
     * ## Example Input/Output:
     * ```
     * Input: data_[0..51] = {0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, ...}
     * Output: is_32bit_ = true, is_little_endian_ = true
     *         ehdr32_.e_entry = 0x08000001 (entry point)
     *         ehdr32_.e_machine = EM_ARM (0x28)
     * ```
     */
    void parseElfHeader();

    /**
     * @brief Extracts all section headers from the ELF file
     *
     * Reads the section header table to identify all sections in the ELF file
     * (code, data, symbols, strings, debug info). Each section header describes
     * the location, size, and type of a file segment.
     *
     * ## Sections typically found:
     * - .text: Executable code
     * - .data: Initialized global variables
     * - .bss: Uninitialized global variables
     * - .symtab: Symbol table
     * - .strtab: String table
     * - .debug_info: DWARF debug information
     *
     * @throws std::runtime_error if section headers are corrupted
     * @throws std::runtime_error if section count is invalid
     *
     * ## Example Input/Output:
     * ```
     * Input: ELF file with 15 sections
     * Output: sections32_ contains 15 Elf32_Shdr entries:
     *   [0]: {name=".text", offset=0x1000, size=0x2000, type=SHT_PROGBITS}
     *   [1]: {name=".data", offset=0x3000, size=0x500, type=SHT_PROGBITS}
     *   [2]: {name=".symtab", offset=0x3500, size=0x800, type=SHT_SYMTAB}
     * ```
     */
    void parseSectionHeaders();

    /**
     * @brief Extracts string tables used for symbol and section names
     *
     * Locates and loads all string table sections (.strtab, .shstrtab, etc.)
     * into memory. String tables contain null-terminated strings referenced
     * by symbols and section headers.
     *
     * ## String tables processed:
     * - .shstrtab: Section header names
     * - .strtab: Symbol names
     * - Other string tables as needed
     *
     * @throws std::runtime_error if required string tables are missing
     * @throws std::runtime_error if string table format is invalid
     *
     * ## Example Input/Output:
     * ```
     * Input: .strtab section at offset 0x4000, size 200 bytes
     * Output: string_tables_[3] = {".text\0.data\0main\0sensor_init\0..."}
     * Usage: symbol names can now be resolved by string table index
     * ```
     */
    void parseStringTables();

    /**
     * @brief Parses the symbol table to extract functions and variables
     *
     * Reads the .symtab section to extract all symbols (functions, global
     * variables, etc.) with their addresses, sizes, types, and names.
     * Symbols are the primary way to identify program elements in ELF files.
     *
     * ## Symbol types processed:
     * - STT_FUNC: Function symbols (main, init_sensors, etc.)
     * - STT_OBJECT: Variable symbols (global_counter, sensor_data, etc.)
     * - STT_NOTYPE: Generic symbols
     *
     * @throws std::runtime_error if symbol table is corrupted
     * @throws std::runtime_error if string table references are invalid
     *
     * ## Example Input/Output:
     * ```
     * Input: .symtab with 50 symbol entries
     * Output: symbols32_ contains 50 Elf32_Sym entries:
     *   [0]: {name="main", addr=0x08000001, size=64, type=STT_FUNC}
     *   [1]: {name="global_counter", addr=0x20000000, size=4, type=STT_OBJECT}
     *   [2]: {name="sensor_data", addr=0x20000010, size=12, type=STT_OBJECT}
     * ```
     */
    void parseSymbolTable();

    /**
     * @brief Orchestrates DWARF debug information parsing
     *
     * Main entry point for processing DWARF debug sections. Attempts modern
     * libdwarf parsing first, falls back to legacy parsing if needed.
     * DWARF provides detailed type information essential for structure analysis.
     *
     * ## DWARF sections processed:
     * - .debug_info: Type definitions and variable information
     * - .debug_str: String data for debug entries
     * - .debug_abbrev: Abbreviation tables
     * - Other DWARF sections as available
     *
     * @throws std::runtime_error if DWARF parsing fails completely
     * @note Sets has_dwarf_info_ flag based on parsing success
     *
     * ## Example Input/Output:
     * ```
     * Input: ELF with .debug_info (5KB) and .debug_str (1KB) sections
     * Output: has_dwarf_info_ = true
     *         types_ populated with discovered structures
     *         dwarf_variables_ populated with variable info
     * Effect: Enables detailed structure member analysis
     * ```
     */
    void parseDebugInfo();
    void validateElfFile();

    // ========================================================================
    // Parallel Processing Methods
    // ========================================================================

    /**
     * @brief Initialize parallel processing infrastructure
     *
     * Sets up thread pool and work distribution coordinator if parallel
     * processing is enabled in the configuration.
     */
    void initializeParallelProcessing();

    /**
     * @brief Shutdown parallel processing infrastructure
     *
     * Gracefully shuts down thread pool and work distributor, ensuring
     * all pending work is completed before exit.
     */
    void shutdownParallelProcessing();

    /**
     * @brief Parse DWARF compilation units in parallel
     *
     * Distributes compilation unit processing across worker threads for
     * improved performance on large ELF files with many compilation units.
     *
     * @param dbg libdwarf debug context
     * @return true if parallel parsing succeeded
     */
    bool parseDwarfCompilationUnitsParallel(Dwarf_Debug dbg);

    /**
     * @brief Parse DWARF compilation units sequentially (fallback)
     *
     * Sequential compilation unit processing used when parallel processing
     * is disabled or when the CU count is below the parallel threshold.
     *
     * @param dbg libdwarf debug context
     * @return true if sequential parsing succeeded
     */
    bool parseDwarfCompilationUnitsSequential(Dwarf_Debug dbg);

    // ========================================================================
    // Modern DWARF Parsing Methods (using libdwarf)
    // ========================================================================

    /**
     * @brief Primary DWARF parser using modern libdwarf library
     *
     * Uses the robust libdwarf library to parse DWARF debug information.
     * This is the preferred parsing method as it handles all DWARF versions
     * (2-5) and provides comprehensive error handling.
     *
     * ## Process:
     * 1. Initialize libdwarf with ELF file
     * 2. Iterate through compilation units
     * 3. Process Debug Information Entries (DIEs)
     * 4. Extract type and variable information
     * 5. Build type hierarchy and relationships
     *
     * @return true if DWARF parsing succeeded, false if no debug info available
     * @throws std::runtime_error if libdwarf encounters critical errors
     *
     * ## Example Input/Output:
     * ```
     * Input: ELF file with .debug_info section
     * Output: types_ = {"SensorData" -> TypeInfo, "Config" -> TypeInfo}
     *         dwarf_variables_ = {"sensor" -> VariableInfo, "config" -> VariableInfo}
     *         return true (success)
     * ```
     */
    bool parseDwarfWithLibdwarf();

    /**
     * @brief Processes a single compilation unit from DWARF data
     *
     * A compilation unit represents one source file (.c/.cpp) and all its
     * included headers. Each unit contains types, functions, and variables
     * defined in that translation unit.
     *
     * @param dbg libdwarf debug context handle
     * @param cu_die Debug Information Entry representing the compilation unit
     *
     * @throws std::runtime_error if compilation unit is malformed
     *
     * ## Example Input/Output:
     * ```
     * Input: cu_die representing "main.cpp" with 25 child DIEs
     * Process: Recursively process all child DIEs (types, vars, functions)
     * Output: types_ and dwarf_variables_ populated with discoveries from main.cpp
     * ```
     */
    void processCompilationUnit(Dwarf_Debug dbg, Dwarf_Die cu_die);

    /**
     * @brief Recursively processes a DWARF Debug Information Entry (DIE)
     *
     * DIEs are the core building blocks of DWARF debug information. Each DIE
     * represents a program element (type, variable, function, etc.) with
     * attributes describing its properties.
     *
     * ## DIE Types Processed:
     * - DW_TAG_structure_type: C structures and C++ classes
     * - DW_TAG_class_type: C++ classes
     * - DW_TAG_variable: Global and static variables
     * - DW_TAG_member: Structure/class members
     * - DW_TAG_array_type: Array types
     * - DW_TAG_pointer_type: Pointer types
     * - DW_TAG_namespace: C++ namespaces
     *
     * @param dbg libdwarf debug context handle
     * @param die Debug Information Entry to process
     * @param namespace_prefix Current namespace path (e.g., "MyNamespace::")
     *
     * ## Example Input/Output:
     * ```
     * Input: DIE for "struct SensorData" with 3 member DIEs
     * Process: Extract structure name, size, member layout
     * Output: types_["SensorData"] = {members: [temperature, humidity, status]}
     * Recurse: Process 3 member DIEs to get complete layout
     * ```
     */
    void processDwarfDie(Dwarf_Debug dbg, Dwarf_Die die, const std::string& namespace_prefix = "");

    /**
     * @brief Extracts variable information from a DWARF variable DIE
     *
     * Processes variables (global, static, local) to extract their names,
     * types, memory addresses, and scope information. This information
     * is essential for matching ELF symbols with detailed type data.
     *
     * @param dbg libdwarf debug context handle
     * @param var_die DIE representing a variable (DW_TAG_variable)
     * @param namespace_prefix Current namespace context
     *
     * ## Example Input/Output:
     * ```
     * Input: var_die for global variable "sensor_data" at 0x20000010
     * Output: dwarf_variables_["sensor_data"] = {
     *           name: "_Z11sensor_dataE",
     *           demangled_name: "sensor_data",
     *           type_name: "SensorData",
     *           address: 0x20000010,
     *           is_global: true
     *         }
     * ```
     */
    void processDwarfVariable(Dwarf_Debug dbg,
                              Dwarf_Die var_die,
                              const std::string& namespace_prefix = "");

    /**
     * @brief Extract constant value from DWARF attribute
     *
     * Extracts and formats constant values from DW_AT_const_value attributes,
     * handling different DWARF forms (data1, data2, data4, data8, sdata, string).
     *
     * @param dbg DWARF debug context
     * @param const_attr DW_AT_const_value attribute
     * @return String representation of the constant value
     */
    std::string extractConstantValue(Dwarf_Debug dbg, Dwarf_Attribute const_attr);

    /**
     * @brief Extract constant value from memory by reading ELF sections
     *
     * Reads the actual constant value from the ELF file memory sections
     * based on the type information and memory address.
     *
     * @param type_die Type DIE (should be DW_TAG_const_type)
     * @param address Memory address where the constant is stored
     * @return String representation of the constant value read from memory
     */
    std::string
    extractConstantValueFromMemory(Dwarf_Debug dbg, Dwarf_Die type_die, uint64_t address);

    /**
     * @brief Read constant value from address based on type information
     *
     * @param address Memory address to read from
     * @param byte_size Size in bytes to read
     * @param type_die Type DIE for encoding information
     * @return String representation of the value
     */
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - address and byte_size have distinct
    // semantic meanings: address is memory location, byte_size is amount of data to read
    std::string readConstantValueFromAddress(Dwarf_Debug dbg,
                                             uint64_t address,
                                             uint64_t byte_size,
                                             Dwarf_Die type_die);

    /**
     * @brief Read null-terminated string from memory address
     *
     * @param address Address where string starts
     * @return String content (empty if not readable)
     */
    std::string readStringFromAddress(uint64_t address);

    /**
     * @brief Read memory content from ELF sections at specified address
     *
     * Reads actual bytes from ELF file data based on memory address and section mapping.
     * Used for extracting constant values from the binary data.
     *
     * @param address Memory address to read from
     * @param size Number of bytes to read
     * @return String containing the raw bytes read from memory
     */
    std::string readMemoryAtAddress(uint64_t address, uint64_t size) const;

    /**
     * @brief Read constant value from memory and format based on type
     *
     * Universal function to read constant values from ELF memory sections (.rodata, etc.)
     * and format them as strings based on their type (float, int, char, etc.)
     *
     * @param address Memory address to read from
     * @param type_name DWARF type name (e.g., "float", "int32_t", "unsigned char")
     * @param size Size in bytes to read
     * @return Formatted string representation of the value, or empty string if unable to read
     */
    std::string readConstantValueFromMemory(uint64_t address,
                                            const std::string& type_name,
                                            uint64_t size) const;

    /**
     * @brief Helper method to generate generic parameter names for any structure
     *
     * Maps parameter indices to generic but consistent names for any structure
     * containing constant parameters, regardless of naming convention.
     *
     * @param param_index Index of the parameter within the structure
     * @return Generic parameter name string
     */
    std::string getGenericParamName(size_t param_index) const;

    /**
     * @brief Processes function DIEs to extract local variable information
     *
     * Analyzes function DIEs to extract local variables, parameters, and stack frame
     * information. Only processes functions when local variable analysis is enabled
     * via CLI options.
     *
     * @param dbg libdwarf debug context handle
     * @param function_die Function DIE (DW_TAG_subprogram)
     * @param namespace_prefix Namespace context for the function
     *
     * ## Processing Steps:
     * 1. Extract function name and address range
     * 2. Process all child DIEs for parameters (DW_TAG_formal_parameter)
     * 3. Process all child DIEs for local variables (DW_TAG_variable)
     * 4. Parse location expressions for variable storage
     * 5. Calculate stack frame size and layout
     *
     * @note Only active when Config::showLocalVariables or related options are enabled
     */
    void processFunctionScope(Dwarf_Debug dbg,
                              Dwarf_Die function_die,
                              const std::string& namespace_prefix = "");

    /**
     * @brief Parses DWARF location expressions to determine variable storage
     *
     * Converts DWARF location expressions into human-readable variable locations.
     * Handles common location opcodes for embedded systems analysis.
     *
     * @param location_attr DWARF location attribute from variable DIE
     * @return VariableLocation with parsed storage information
     *
     * ## Supported Location Types:
     * - DW_OP_fbreg: Stack offset relative to frame base
     * - DW_OP_reg0-31: CPU register storage
     * - DW_OP_breg0-31: Register + offset
     * - DW_OP_addr: Fixed memory address (globals)
     * - DW_OP_piece: Multi-location variables
     */
    VariableLocation parseLocationExpression(Dwarf_Attribute location_attr);

    /**
     * @brief Converts location information to human-readable format
     *
     * Creates descriptive strings for variable locations suitable for display
     * and debugging. Handles architecture-specific register naming.
     *
     * @param location Variable location information
     * @return Human-readable string ("SP+8", "r4", "0x20000100", etc.)
     *
     * ## Example Output:
     * - Stack variables: "SP+8", "FP-12"
     * - Register variables: "r4", "r0"
     * - Memory addresses: "0x20000100"
     * - Complex: "r4+16", "optimized_out"
     */
    std::string formatLocationDescription(const VariableLocation& location);

    /**
     * @brief Extracts the name attribute from a DWARF DIE
     *
     * Utility function to safely extract string names from DWARF DIEs.
     * Handles missing names gracefully and provides fallback values.
     *
     * @param dbg libdwarf debug context handle
     * @param die DIE to extract name from
     * @return String name or empty string if no name attribute
     *
     * ## Example Input/Output:
     * ```
     * Input: DIE with DW_AT_name = "SensorData"
     * Output: return "SensorData"
     *
     * Input: DIE with no DW_AT_name attribute
     * Output: return "" (empty string)
     * ```
     */
    // Type resolution methods moved to dwarf/DwarfTypeResolver

    /**
     * @brief Process DWARF 5 type qualifiers
     *
     * Handles advanced DWARF 5 type qualifiers such as immutable, packed, atomic,
     * and dynamic types. Extracts qualifier information and associates it with
     * the underlying base type.
     *
     * @param dbg libdwarf debug context handle
     * @param die DWARF 5 type qualifier DIE
     * @param namespace_prefix Current namespace context
     * @param qualifier Type of qualifier being processed
     *
     * ## Supported DWARF 5 Qualifiers:
     * - DW_TAG_immutable_type: const/immutable qualifiers
     * - DW_TAG_packed_type: structure packing attributes
     * - DW_TAG_atomic_type: atomic type qualifiers (C11/C++11)
     * - DW_TAG_dynamic_type: runtime-sized types
     */
    void processDwarf5TypeQualifier(Dwarf_Debug dbg,
                                    Dwarf_Die die,
                                    const std::string& namespace_prefix,
                                    TypeQualifiers qualifier);

    /**
     * @brief Process DWARF 5 template parameters
     *
     * Extracts template parameter information for C++ template analysis.
     * Handles both type parameters and value parameters with their respective
     * attributes and default values.
     *
     * @param dbg libdwarf debug context handle
     * @param die Template parameter DIE
     * @param namespace_prefix Current namespace context
     * @param is_type_parameter True for type params, false for value params
     *
     * ## Template Parameter Processing:
     * - Extracts parameter names and types
     * - Handles default parameter values
     * - Associates parameters with template specializations
     * - Builds template signature strings
     */
    void processDwarfTemplateParameter(Dwarf_Debug dbg,
                                       Dwarf_Die die,
                                       const std::string& namespace_prefix,
                                       bool is_type_parameter);

    /**
     * @brief Type resolution caching system
     *
     * Retrieves cached type information to avoid redundant DWARF processing.
     * Implements time-based cache expiration and hit tracking.
     *
     * @param type_name Name of the type to look up in cache
     * @return Cached AdvancedTypeInfo or empty object if cache miss
     */
    AdvancedTypeInfo getCachedTypeInfo(const std::string& type_name) const;

    /**
     * @brief Caches type information with timestamp and LRU management
     *
     * @param type_name Name of the type to cache
     * @param info Advanced type information to store
     */
    void cacheTypeInfo(const std::string& type_name, const AdvancedTypeInfo& info);

    /**
     * @brief Type name deduplication using string interning
     *
     * @param type_name Type name to deduplicate
     * @return Interned type name string
     */
    std::string deduplicateTypeName(const std::string& type_name);

    /**
     * @brief Optimizes type dependency resolution order
     *
     * Analyzes type dependencies and builds optimization hints
     * for better resolution performance.
     */
    void optimizeTypeDependencies();

    /**
     * @brief Prints comprehensive type resolution statistics
     *
     * Displays cache hit rates, resolution times, and type qualifier usage.
     * Only active when verbosity is enabled.
     */
    void printTypeResolutionStats() const;

    // ========================================================================
    // Interrupt Vector Table Analysis Methods
    // ========================================================================

    /**
     * @brief Extract interrupt vector table from ELF sections
     *
     * Analyzes ELF sections to locate and extract interrupt vector table entries.
     * Typically looks for vector tables in .isr_vector, .vector_table, or at the
     * start of flash memory for embedded ARM systems.
     *
     * ## Supported Architectures:
     * - ARM Cortex-M: Standard NVIC interrupt vector table format
     * - ARM Cortex-A/R: Vector table with branch instructions
     * - RISC-V: Interrupt vector tables with handler addresses
     *
     * @return True if interrupt vectors were successfully extracted
     */
    bool extractInterruptVectorTable();

    /**
     * @brief Print formatted interrupt vector table information
     *
     * Displays extracted interrupt vectors in a human-readable format with:
     * - Vector numbers and priorities
     * - Handler function names and addresses
     * - Architecture-specific interrupt descriptions
     */
    void printInterruptVectorTable() const;

    /**
     * @brief Extract memory region mapping from ELF program headers
     *
     * Parses ELF program headers to create a comprehensive memory layout map
     * with validation and embedded systems analysis.
     *
     * @return True if memory regions were successfully extracted
     */
    bool extractMemoryRegionMapping();

    /**
     * @brief Print memory region mapping results
     *
     * Displays formatted memory layout with regions, permissions, validation
     * results, and embedded systems memory usage analysis.
     */
    void printMemoryRegionMapping() const;

    /**
     * @brief Parse program headers to extract memory regions
     */
    bool parseMemoryRegionsFromProgramHeaders();

    /**
     * @brief Parse 32-bit program header
     */
    bool parseProgramHeader32(uint64_t offset, MemoryRegion& region);

    /**
     * @brief Parse 64-bit program header
     */
    bool parseProgramHeader64(uint64_t offset, MemoryRegion& region);

    /**
     * @brief Classify memory regions by type
     */
    void classifyMemoryRegions();

    /**
     * @brief Validate memory layout and detect issues
     */
    void validateMemoryLayout();

    /**
     * @brief Analyze memory layout characteristics
     */
    void analyzeMemoryLayoutCharacteristics();

    /**
     * @brief Validate single memory region
     */
    void validateSingleRegion(MemoryRegion& region);

    /**
     * @brief Check for region overlaps
     */
    void checkRegionOverlaps();

    /**
     * @brief Validate global layout characteristics
     */
    void validateGlobalLayout();

    /**
     * @brief Get segment type description string
     */
    std::string getSegmentTypeDescription(ElfSegmentType type) const;

    /**
     * @brief Get region type name string
     */
    std::string getRegionTypeName(MemoryRegionType type) const;

    /**
     * @brief Classify non-loadable region by segment type
     */
    MemoryRegionType classifyNonLoadableRegion(ElfSegmentType type) const;

    /**
     * @brief Classify ESP32/Xtensa-specific memory regions by address ranges
     * @param region Memory region to classify
     * @param readable Whether region has read permission
     * @param writable Whether region has write permission
     * @param executable Whether region has execute permission
     */
    void
    classifyESP32MemoryRegion(MemoryRegion& region, bool readable, bool writable, bool executable);

    /**
     * @brief Format memory size for human-readable display
     */
    std::string formatMemorySize(uint64_t size) const;

    /**
     * @brief Identify potential interrupt handler functions
     *
     * Uses heuristics to identify functions that could be interrupt handlers:
     * - Function name patterns (_Handler, IRQ*, *_ISR)
     * - Function location in memory
     * - Function characteristics (size, parameters)
     *
     * @return Vector of potential interrupt handler functions
     */
    std::vector<FunctionInfo> identifyInterruptHandlers() const;

    /**
     * @brief Get common ARM Cortex-M interrupt descriptions
     *
     * Provides standard descriptions for ARM Cortex-M system exceptions
     * and user-defined interrupt vectors.
     *
     * @param vector_number Zero-based vector number
     * @return Human-readable description of the interrupt
     */
    std::string getArmInterruptDescription(uint32_t vector_number) const;

    /**
     * @brief Extract interrupt vectors from a specific ELF section
     *
     * Searches for a section with the given name and attempts to parse
     * interrupt vector entries from it.
     *
     * @param section_name Name of the section to search for
     * @return True if vectors were successfully extracted from the section
     */
    bool extractVectorFromSection(const std::string& section_name);

    /**
     * @brief Extract vector data from a section by index
     *
     * Parses raw section data to extract interrupt vector entries.
     * Assumes 32-bit addresses in little-endian format.
     *
     * @param section_index Index of the section in section_headers_
     * @return True if vector data was successfully parsed
     */
    bool extractVectorDataFromSection(size_t section_index);

    /**
     * @brief Extract ARM Cortex-M vectors from .text section
     *
     * Specialized extraction for ARM Cortex-M systems where the vector
     * table is located at the beginning of the .text section.
     *
     * @return True if ARM vectors were successfully extracted
     */
    bool extractArmCortexMVectors();

    /**
     * @brief Read raw data from an ELF section
     *
     * Uses the file access strategy to read section data from the ELF file.
     *
     * @param section_index Index of the section to read
     * @param data Output vector to store the section data
     * @return True if section data was successfully read
     */
    bool readSectionData(size_t section_index, std::vector<uint8_t>& data) const;

    /**
     * @brief Parses array type information from DWARF
     *
     * Extracts array dimensions, element types, and size information from
     * DWARF array type DIEs. Supports multi-dimensional arrays.
     *
     * @param dbg libdwarf debug context handle
     * @param array_die DIE representing an array type (DW_TAG_array_type)
     * @return Formatted array type string with dimensions
     *
     * ## Example Input/Output:
     * ```
     * Input: array_die for "float[3][5]" (3x5 float array)
     * Output: return "float[3][5]"
     *
     * Input: array_die for "uint8_t[64]" (64-element byte array)
     * Output: return "uint8_t[64]"
     * ```
     */
    // parseArrayType moved to dwarf/DwarfTypeResolver

    /**
     * @brief Extracts complete structure information from a DWARF structure DIE
     *
     * Processes structure or class DIEs to extract all member information,
     * including names, types, offsets, and nested structures. Builds complete
     * TypeInfo structures for use during member expansion.
     *
     * @param dbg libdwarf debug context handle
     * @param struct_die DIE representing a structure or class
     * @param full_name Fully qualified name including namespace
     *
     * ## Example Input/Output:
     * ```
     * Input: struct_die for "struct SensorData" with 3 members
     * Process: Extract each member's name, type, offset
     * Output: types_["SensorData"] = {
     *           members: [
     *             {name: "temperature", type: "float", offset: 0},
     *             {name: "humidity", type: "uint8_t", offset: 4},
     *             {name: "status", type: "uint16_t", offset: 5}
     *           ]
     *         }
     * ```
     */
    void extractStructureFromDie(Dwarf_Debug dbg,
                                 Dwarf_Die struct_die,
                                 const std::string& full_name,
                                 const std::string& linkage_name = "");

    // ========================================================================
    // Enhanced Symbol and Type Resolution Methods
    // ========================================================================

    /**
     * @brief Finds the DWARF type information for a given symbol name
     *
     * Searches through the parsed DWARF variable information to find the
     * type associated with a specific symbol. Essential for linking ELF
     * symbols with their detailed type information.
     *
     * @param symbol_name Name of the symbol to look up
     * @return Type name string, or "unknown" if not found
     *
     * ## Example Input/Output:
     * ```
     * Input: symbol_name = "sensor_data"
     * Output: return "SensorData" (found in dwarf_variables_)
     *
     * Input: symbol_name = "undefined_var"
     * Output: return "unknown" (not found in DWARF data)
     * ```
     */
    std::string findTypeForSymbol(const std::string& symbol_name) const;

    /**
     * @brief Demangles C++ mangled symbol names to human-readable form
     *
     * C++ compilers mangle symbol names to encode type information and
     * namespace details. This function converts mangled names back to
     * readable C++ syntax.
     *
     * @param mangled_name Mangled C++ symbol name from ELF
     * @return Demangled human-readable name
     *
     * ## Example Input/Output:
     * ```
     * Input: mangled_name = "_ZN11MyNamespace9SensorData4initEv"
     * Output: return "MyNamespace::SensorData::init()"
     *
     * Input: mangled_name = "simple_c_function"
     * Output: return "simple_c_function" (no change for C symbols)
     * ```
     */
    std::string demangleCppName(const std::string& mangled_name) const;

    /**
     * @brief Cleans symbol names by removing prefixes and suffixes
     *
     * ELF symbols often have compiler-added prefixes or suffixes. This
     * function normalizes symbol names for consistent matching with DWARF data.
     *
     * @param symbol_name Raw symbol name from ELF symbol table
     * @return Cleaned symbol name for matching
     *
     * ## Example Input/Output:
     * ```
     * Input: symbol_name = "_ZN11sensor_dataE"
     * Output: return "sensor_data" (removed mangling artifacts)
     *
     * Input: symbol_name = "__global_var_suffix"
     * Output: return "global_var" (removed compiler artifacts)
     * ```
     */
    std::string getCleanSymbolName(const std::string& symbol_name) const;

    // ========================================================================
    // Legacy DWARF Methods (Deprecated - will be removed in future versions)
    // ========================================================================

    /**
     * @deprecated Use parseDwarfWithLibdwarf() instead
     * @brief Legacy DWARF parser implementation
     * @return true if parsing succeeded
     */
    bool parseDwarfInfo();

    /**
     * @deprecated Legacy DIE parsing method
     * @brief Parses a single DWARF DIE from raw bytes
     */
    DwarfDIE parseDwarfDIE(const uint8_t* data, size_t& offset, size_t max_size);

    /**
     * @deprecated Use libdwarf string resolution instead
     * @brief Resolves DWARF string from offset
     */
    std::string getDwarfString(uint32_t string_offset) const;

    /**
     * @deprecated Legacy type extraction
     * @brief Extracts types from legacy DWARF parser
     */
    void extractTypesFromDwarf(const DwarfDIE& die, const std::string& namespace_prefix = "");

    /**
     * @deprecated Use extractStructureFromDie() instead
     * @brief Legacy class processing
     */
    void processDwarfClass(const DwarfDIE& class_die, const std::string& full_name);

    /**
     * @deprecated Use extractStructureFromDie() instead
     * @brief Legacy structure processing
     */
    void processDwarfStructure(const DwarfDIE& struct_die, const std::string& full_name);

    // ========================================================================
    // Utility and Helper Methods
    // ========================================================================

    /**
     * @brief Retrieves string from ELF string table
     *
     * @param strtab_index Index of the string table section
     * @param offset Offset within the string table
     * @return String at the specified location
     */
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - strtab_index and offset have distinct
    // meanings: strtab_index identifies which string table, offset is position within that table
    std::string getString(uint32_t strtab_index, uint32_t offset) const;

    /**
     * @brief Converts ELF symbol type enum to human-readable string
     *
     * @param symbol_type ELF symbol type (STT_FUNC, STT_OBJECT, etc.)
     * @return Human-readable type name ("function", "variable", etc.)
     */
    std::string getTypeName(SymbolType symbol_type) const;

    /**
     * @brief Recursively expands structure members with calculated addresses
     *
     * This is the core method for structure member analysis. It takes a base
     * structure and recursively expands all members, calculating precise
     * memory addresses based on ARM ABI alignment rules.
     *
     * @param base_name Base variable name (e.g., "sensor_data")
     * @param type_name Structure type name (e.g., "SensorData")
     * @param base_address Base memory address of the structure
     * @param offset Current offset within nested structures
     * @return Vector of MemberInfo with complete member details
     *
     * ## Example Input/Output:
     * ```
     * Input: base_name="sensor_data", type_name="SensorData",
     *        base_address=0x20000010, offset=0
     * Output: [
     *   {name="sensor_data.temperature", addr=0x20000010, type="float"},
     *   {name="sensor_data.humidity", addr=0x20000014, type="uint8_t"},
     *   {name="sensor_data.config.timeout", addr=0x20000015, type="uint16_t"}
     * ]
     * ```
     */
    std::vector<MemberInfo> expandStructureMembers(const std::string& base_name,
                                                   const std::string& type_name,
                                                   uint64_t base_address,
                                                   uint32_t offset = 0) const;

    /**
     * @brief Template method to read typed values from ELF file data
     * @param offset Byte offset in the ELF file
     * @return Value of type T read from the specified offset
     */
    template<typename T>
    T readValue(size_t offset) const;

    /**
     * @brief Template method to read structures from ELF file data
     * @param offset Byte offset in the ELF file
     * @param structure Reference to structure to populate
     */
    template<typename T>
    void readStruct(size_t offset, T& structure) const;

    /**
     * @brief Swaps byte order for endianness conversion
     * @param data Pointer to data to swap
     * @param size Size of data in bytes
     */
    void swapEndianness(void* data, size_t size) const;

    /**
     * @brief Fallback type size estimator when libdwarf is not available
     *
     * Provides simple heuristic-based type size estimation for use when
     * libdwarf is disabled or unavailable. Uses type name patterns
     * to estimate common type sizes.
     *
     * @param type_name Name of the type to estimate size for
     * @return Estimated size in bytes
     */
    uint64_t estimateTypeSizeFallback(const std::string& type_name) const;

    // ========================================================================
    // DWARF Member Extraction Methods (for proper parameter naming)
    // ========================================================================

#if HAVE_LIBDWARF
    /**
     * @brief Extract actual member names and offsets from DWARF information
     *
     * Uses libdwarf to find the type definition and extract real member names
     * instead of using generic parameter_N names.
     *
     * @param type_name Name of the type to find members for
     * @return Vector of (member_name, member_offset) pairs
     */
    std::vector<std::pair<std::string, uint32_t>>
    extractDwarfMembers(const std::string& type_name) const;

    /**
     * @brief Find a type DIE by name in DWARF information
     *
     * Searches through all compilation units to find a type DIE matching the given name.
     *
     * @param dbg libdwarf debug context
     * @param type_name Name of the type to find
     * @param type_die Output parameter for found type DIE
     * @return true if type found, false otherwise
     */
    bool
    findDwarfTypeByName(Dwarf_Debug dbg, const std::string& type_name, Dwarf_Die& type_die) const;

    /**
     * @brief Search for a type within a specific compilation unit
     *
     * @param dbg libdwarf debug context
     * @param cu_die Compilation unit DIE to search within
     * @param type_name Name of the type to find
     * @param type_die Output parameter for found type DIE
     * @return true if type found, false otherwise
     */
    bool searchForTypeInCU(Dwarf_Debug dbg,
                           Dwarf_Die cu_die,
                           const std::string& type_name,
                           Dwarf_Die& type_die) const;

    /**
     * @brief Check if a DIE matches the target type name
     *
     * @param dbg libdwarf debug context
     * @param die DIE to check
     * @param type_name Target type name
     * @param found_die Output parameter for matching DIE
     * @return true if DIE matches, false otherwise
     */
    bool isMatchingTypeDie(Dwarf_Debug dbg,
                           Dwarf_Die die,
                           const std::string& type_name,
                           Dwarf_Die& found_die) const;
    bool isBasicType(const std::string& type_name) const;

    /**
     * @brief Extract member information from a type DIE
     *
     * @param dbg libdwarf debug context
     * @param type_die Type DIE to extract members from
     * @param members Output vector to populate with (name, offset) pairs
     */
    void extractMembersFromDwarfDie(Dwarf_Debug dbg,
                                    Dwarf_Die type_die,
                                    std::vector<std::pair<std::string, uint32_t>>& members) const;
#endif  // HAVE_LIBDWARF

    /**
     * @brief Extract generic parameter names as fallback when DWARF extraction fails
     *
     * Uses generic parameter_N naming only when actual DWARF member names cannot be extracted.
     * This is the last resort for parameter naming.
     *
     * @param base_name Base name for the structure
     * @param struct_address Address of the structure in memory
     * @param members Output vector to populate with MemberInfo objects
     */
    void extractGenericParameters(const std::string& base_name,
                                  uint64_t struct_address,
                                  std::vector<MemberInfo>& members) const;

    /**
     * @brief Get actual member names and offsets from existing DWARF type information
     *
     * Uses the already parsed type information to extract real member names
     * instead of using generic parameter_N names.
     *
     * @param type_name Name of the type to find members for
     * @return Vector of (member_name, member_offset) pairs
     */
    std::vector<std::pair<std::string, uint32_t>>
    getActualMemberNames(const std::string& type_name) const;

#if HAVE_LIBDWARF
    /**
     * @brief Direct DWARF member extraction for structures with incomplete type resolution
     *
     * Uses libdwarf to directly parse DWARF and follow type references to extract
     * member names and offsets for any structure, especially when the existing
     * type resolution infrastructure doesn't find the information.
     *
     * @param type_name Name of the type to find members for
     * @return Vector of (member_name, member_offset) pairs
     */
    std::vector<std::pair<std::string, uint32_t>>
    extractDwarfMembersDirect(const std::string& type_name) const;
#endif  // HAVE_LIBDWARF

    // Helper methods for enhanced member name resolution
    std::string resolveTypedefChain(const std::string& type_name) const;
    std::vector<std::pair<std::string, uint32_t>>
    getMembersFromDwarfVariables(const std::string& underlying_type,
                                 std::optional<TypeInfo>& type_info) const;
    std::vector<std::pair<std::string, uint32_t>>
    extractMembersFromTemplateChain(const std::string& template_type,
                                    std::optional<TypeInfo>& type_info) const;

    // ========================================================================
    // ELF Header Accessor Methods
    // ========================================================================

    /** @brief Gets number of sections in the ELF file */
    uint16_t getSectionCount() const;

    /** @brief Gets offset to section header table */
    uint32_t getSectionHeaderOffset() const;

    /** @brief Gets size of each section header entry */
    uint16_t getSectionHeaderSize() const;

    /** @brief Gets index of section name string table */
    uint16_t getSectionNameIndex() const;

    /**
     * @brief Template accessor for section headers (32-bit or 64-bit)
     * @return Reference to appropriate section vector based on ELF class
     */
    template<typename SectionType>
    const std::vector<SectionType>& getSections() const;

    /**
     * @brief Template accessor for symbol table entries (32-bit or 64-bit)
     * @return Reference to appropriate symbol vector based on ELF class
     */
    template<typename SymbolType>
    const std::vector<SymbolType>& getSymbols() const;

    /**
     * @brief Display comprehensive performance optimization metrics
     *
     * Outputs detailed performance statistics including deduplication efficiency,
     * memory allocation patterns, timing breakdown, and optimization effectiveness.
     * Only available when ElfOptimization::ENABLE_PERFORMANCE_METRICS is enabled.
     *
     * Metrics include:
     * - DWARF processing efficiency (structures processed vs duplicates skipped)
     * - String interner utilization and memory allocation success
     * - File access strategy effectiveness (memory mapping vs in-memory)
     * - Timing breakdown for major processing phases
     */
    void printPerformanceMetrics() const;

private:
};