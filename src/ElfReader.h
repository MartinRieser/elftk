/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "ElfStructures.h"
#include "ElfExceptions.h"
#include "FileAccessStrategy.h"
#include "StringInterner.h"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <utility>

// Forward declarations for Phase 1
struct ExportMemoryRegion;

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
}

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
    size_t total_structures_encountered = 0;     ///< Total structure DIEs processed
    size_t duplicate_structures_skipped = 0;     ///< Structures skipped due to deduplication
    size_t compilation_units_processed = 0;      ///< Number of compilation units processed

    // Memory allocation metrics
    size_t string_interner_capacity_reserved = 0; ///< Pre-allocated string capacity
    size_t string_interner_fallback_used = 0;     ///< Whether fallback allocation was used
    size_t final_string_pool_size = 0;            ///< Final number of unique strings

    // Timing metrics (in milliseconds)
    double dwarf_parsing_time_ms = 0.0;          ///< Time spent parsing DWARF info
    double structure_extraction_time_ms = 0.0;   ///< Time spent extracting structures
    double total_processing_time_ms = 0.0;       ///< Total ELF processing time

    // File access metrics
    bool memory_mapping_used = false;            ///< Whether file used memory mapping
    size_t file_size_bytes = 0;                 ///< Size of processed ELF file

    /**
     * @brief Calculate deduplication efficiency percentage
     * @return Percentage of duplicate structures avoided (0-100)
     */
    double getDeduplicationEfficiency() const {
        if (total_structures_encountered == 0) return 0.0;
        return (static_cast<double>(duplicate_structures_skipped) / total_structures_encountered) * 100.0;
    }

    /**
     * @brief Calculate string interner utilization percentage
     * @return Percentage of reserved capacity actually used (0-100+)
     */
    double getStringInternerUtilization() const {
        if (string_interner_capacity_reserved == 0) return 0.0;
        return (static_cast<double>(final_string_pool_size) / string_interner_capacity_reserved) * 100.0;
    }
};

struct Config {
    std::string inputFile;
    std::string format = "csv";
    bool functionsOnly = false;
    bool variablesOnly = false;
    int verbosity = 0;
    bool showSections = false;                     ///< Show section names in output for all symbols
    size_t mmapThreshold = ElfOptimization::DEFAULT_MMAP_THRESHOLD;  ///< Memory mapping threshold for large files

    // Binary Export Options
    std::string exportFormat;                  ///< Export format ("hex", "s19", "s28", "s37", "bin")
    bool constantsOnly = false;                ///< Show only constants

    // Local Variable Analysis Options
    bool showLocalVariables = false;       ///< Enable local variable analysis and display
    bool showStackLayout = false;          ///< Show function stack frame layout

    // Memory Layout Options
    bool extractInterruptVectors = false;  ///< Extract and display interrupt vector table
    bool extractMemoryRegions = false;     ///< Extract and display memory region mapping

    // Phase 2A.2: External Validation Framework Options (keep for future use)
    std::string validateTool;              ///< External validation tool ("gdb", "objdump", "readelf", "all")
    std::string validationOutput;          ///< Output file for validation report
};

/**
 * @class ElfReader
 * @brief Core class for ARM/RISC-V ELF binary analysis and structure extraction
 * 
 * ElfReader is the main analysis engine that processes ARM, RISC-V, ARM64, and Xtensa ELF binary files
 * and extracts detailed information about C++ classes, C structures, global
 * variables, and functions. It automatically discovers structure layouts using
 * DWARF debug information and provides member-level analysis with precise
 * memory addresses.
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
     * @brief Phase 1: Perform binary export to specified format
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
     * @note This method performs the same analysis as analyzeMemberParameters() but returns data instead of printing
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
     * @brief Get local variables for a specific function
     *
     * Extracts local variables and parameters for the specified function.
     *
     * @param function_name Name of the function to analyze
     * @return Vector of LocalVariableInfo structures for the function
     * @example
     * ```cpp
     * ElfReader reader("firmware.elf");
     * auto locals = reader.getLocalVariables("main");
     * for (const auto& var : locals) {
     *     std::cout << var.name << " (" << var.type << ")" << std::endl;
     * }
     * ```
     */
    std::vector<LocalVariableInfo> getLocalVariables(const std::string& function_name);

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

private:
    // Phase 1: Binary Export Helper Methods
    std::vector<ExportMemoryRegion> extractMemoryRegions();
    std::string getSectionName(uint16_t section_index) const;
    std::string getSectionNameForAddress(uint64_t address) const;
    bool isSectionLoadable(uint16_t section_index);
    bool readSectionData(uint16_t section_index, std::vector<uint8_t>& data);
    void generateJsonOutput(const std::vector<MemberInfo>& members);
    void generateCsvOutput(const std::vector<MemberInfo>& members);
    void generateFunctionJsonOutput(const std::vector<FunctionInfo>& functions);
    void generateFunctionCsvOutput(const std::vector<FunctionInfo>& functions);
    // ========================================================================
    // Core File Data Members
    // ========================================================================
    
    Config config_;

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
     * @brief String interning system for memory optimization
     *
     * Manages a pool of unique strings to eliminate duplicate string storage.
     * Symbol names, type names, and member names are interned to reduce memory usage
     * by 15-30% in typical ELF files with many repeated identifiers.
     *
     * Example: Multiple symbols named "main" share the same string object
     */
    mutable StringInterner string_interner_;
    
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
    std::map<std::string, TypeInfo> types_;

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
     * @brief Phase 7.1B: Advanced type information with DWARF 5 features
     * 
     * Maps type names to enhanced type information including qualifiers,
     * template parameters, optimization hints, and performance data.
     * 
     * Example entries:
     * - "const SensorData" -> AdvancedTypeInfo with CONST qualifier
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
     * @brief Phase 7.2: Interrupt vector table information
     * 
     * Contains extracted interrupt vector table data when --interrupt-vectors flag is used.
     * Provides comprehensive mapping of interrupt vectors to handler functions.
     */
    InterruptVectorTable interrupt_vector_table_;
    MemoryRegionMap memory_region_map_;
    
    /**
     * @brief Stack frame analysis results container
     * 
     * Contains comprehensive stack frame analysis data for all functions when
     * --stack-layout or related CLI options are enabled. Provides detailed
     * embedded debugging information including variable locations, calling
     * conventions, and register usage patterns.
     */
    StackFrameAnalysisResults stack_frame_analysis_;
    
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
        std::string name;           ///< Original symbol name (may be mangled)
        std::string demangled_name; ///< Human-readable C++ name  
        std::string type_name;      ///< DWARF-derived type name
        uint64_t address;           ///< Memory address in target system
        bool is_global;             ///< Global vs local variable scope
        bool is_constant;           ///< True if this is a constant variable
        std::string constant_value; ///< String representation of constant value
        
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
        VariableInfo(const std::string& n, const std::string& dn, const std::string& tn, uint64_t addr, bool global)
            : name(n), demangled_name(dn), type_name(tn), address(addr), is_global(global), is_constant(false) {}
            
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
        VariableInfo(const std::string& n, const std::string& dn, const std::string& tn, uint64_t addr, bool global, bool constant, const std::string& const_val)
            : name(n), demangled_name(dn), type_name(tn), address(addr), is_global(global), is_constant(constant), constant_value(const_val) {}
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
     * @brief Phase 7.1A: Function information with local variable analysis
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
    void processDwarfVariable(Dwarf_Debug dbg, Dwarf_Die var_die, const std::string& namespace_prefix = "");
    
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
    std::string extractConstantValueFromMemory(Dwarf_Debug dbg, Dwarf_Die type_die, uint64_t address);
    
    /**
     * @brief Read constant value from address based on type information
     * 
     * @param address Memory address to read from
     * @param byte_size Size in bytes to read
     * @param type_die Type DIE for encoding information
     * @return String representation of the value
     */
    std::string readConstantValueFromAddress(Dwarf_Debug dbg, uint64_t address, uint64_t byte_size, Dwarf_Die type_die);
    
    /**
     * @brief Read null-terminated string from memory address
     * 
     * @param address Address where string starts
     * @return String content (empty if not readable)
     */
    std::string readStringFromAddress(uint64_t address);
    
    /**
     * @brief Phase 7.1A: Processes function DIEs to extract local variable information
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
    void processFunctionScope(Dwarf_Debug dbg, Dwarf_Die function_die, const std::string& namespace_prefix = "");
    
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
    std::string getDwarfDieName(Dwarf_Debug dbg, Dwarf_Die die);
    
    /**
     * @brief Resolves a type DIE to its string representation
     * 
     * Follows type references and chains to produce human-readable type names.
     * Handles complex types including pointers, arrays, and typedefs.
     * 
     * @param dbg libdwarf debug context handle
     * @param type_die DIE representing a type definition
     * @return Resolved type name string
     * 
     * ## Example Input/Output:
     * ```
     * Input: type_die pointing to "float*" (pointer to float)
     * Output: return "float*"
     * 
     * Input: type_die pointing to typedef "Temperature_t" -> "float"  
     * Output: return "Temperature_t" (or "float" depending on resolution depth)
     * ```
     */
    std::string resolveDwarfType(Dwarf_Debug dbg, Dwarf_Die type_die);
    
    // Phase 2A.1: Enhanced type metadata extraction
    struct TypeMetadata {
        std::string type_name;
        uint64_t byte_size = 0;
        uint32_t alignment = 0;
        bool is_typedef = false;
        std::string underlying_type;
        bool is_union = false;
        bool is_bitfield = false;
        uint32_t bit_offset = 0;
        uint32_t bit_size = 0;
        std::string enum_values;
    };
    TypeMetadata extractTypeMetadata(Dwarf_Debug dbg, Dwarf_Die type_die);
    
    // Helper function to estimate size from type name
    uint64_t estimateTypeSize(const std::string& type_name) const;
    
    /**
     * @brief Phase 7.1B: Process DWARF 5 type qualifiers
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
    void processDwarf5TypeQualifier(Dwarf_Debug dbg, Dwarf_Die die, 
                                   const std::string& namespace_prefix, 
                                   TypeQualifiers qualifier);
    
    /**
     * @brief Phase 7.1B: Process DWARF 5 template parameters
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
    void processDwarfTemplateParameter(Dwarf_Debug dbg, Dwarf_Die die,
                                      const std::string& namespace_prefix,
                                      bool is_type_parameter);
    
    /**
     * @brief Phase 7.1B: Type resolution caching system
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
    // Phase 7.2: Interrupt Vector Table Analysis Methods
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
    void classifyESP32MemoryRegion(MemoryRegion& region, bool readable, bool writable, bool executable);
    
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
    bool readSectionData(size_t section_index, std::vector<uint8_t>& data);
    
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
    std::string parseArrayType(Dwarf_Debug dbg, Dwarf_Die array_die);
    
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
    void extractStructureFromDie(Dwarf_Debug dbg, Dwarf_Die struct_die, const std::string& full_name);
    
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
    std::vector<MemberInfo> expandStructureMembers(
        const std::string& base_name,
        const std::string& type_name,
        uint64_t base_address,
        uint32_t offset = 0
    ) const;
    
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
    
    // ========================================================================
    // Stack Frame Analysis Methods (Embedded Debugging Support)
    // ========================================================================
    
    /**
     * @brief Extract comprehensive stack frame analysis information
     * 
     * Performs complete stack frame analysis on all functions in the ELF file,
     * extracting detailed information about variable locations, calling conventions,
     * register usage, and embedded debugging support. This method is automatically
     * called when --stack-layout or related CLI options are enabled.
     * 
     * The analysis includes:
     * - Stack frame layout and variable mapping
     * - Parameter passing analysis (registers vs stack)
     * - Local variable locations and lifetimes
     * - Calling convention detection and validation
     * - Frame pointer usage analysis
     * - Register allocation patterns
     * 
     * @return True if stack frame analysis was successful, false on error
     * 
     * @note This method populates stack_frame_analysis_ with comprehensive results
     * @see printStackFrameAnalysis() for formatted output display
     * @see StackFrameAnalysisResults for detailed data structure documentation
     */
    bool extractStackFrameAnalysis();
    
    /**
     * @brief Display comprehensive stack frame analysis results
     * 
     * Outputs formatted stack frame analysis information to stdout, providing
     * professional embedded debugging information including:
     * - Function-by-function stack frame layouts
     * - Variable location mappings (stack offsets, registers)
     * - Calling convention summaries
     * - Architecture-specific analysis statistics
     * - Memory usage patterns and optimization opportunities
     * 
     * The output format adapts to the configured verbosity level and output format
     * (text, JSON, CSV) specified in the configuration.
     * 
     * @note Only displays results if extractStackFrameAnalysis() was previously successful
     * @see Config::showStackLayout for enabling stack layout display
     * @see Config::format for controlling output format (text/json/csv)
     */
    void printStackFrameAnalysis() const;

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
    
    /**
     * @brief Analyze stack frame layout for a specific function
     * 
     * Performs detailed analysis of a single function's stack frame, extracting:
     * - Total frame size and memory layout
     * - Variable locations and stack offsets
     * - Parameter passing analysis (registers vs stack)
     * - Local variable allocation patterns
     * - Calling convention identification
     * 
     * @param function_info Function information from local variable analysis
     * @return Complete StackFrameInfo structure with embedded debugging details
     */
    StackFrameInfo analyzeStackFrame(const FunctionInfo& function_info);
    
    /**
     * @brief Detect calling convention for target architecture
     * 
     * Analyzes the target architecture and function characteristics to determine
     * the calling convention in use (AAPCS, AAPCS64, RISC-V, etc.).
     * 
     * @param function_info Function to analyze for calling convention detection
     * @return CallingConvention structure with architecture-specific details
     */
    CallingConvention detectCallingConvention([[maybe_unused]] const FunctionInfo& function_info);
    
    /**
     * @brief Analyze register usage patterns for a function
     * 
     * Examines DWARF location expressions and function characteristics to
     * determine register usage patterns, including:
     * - Parameter passing registers
     * - Return value registers  
     * - Callee-saved vs caller-saved register usage
     * - Frame pointer usage detection
     * 
     * @param function_info Function to analyze for register usage
     * @return RegisterUsage structure with detailed register analysis
     */
    RegisterUsage analyzeRegisterUsage(const FunctionInfo& function_info);
    
    /**
     * @brief Convert local variable to stack frame entry
     * 
     * Transforms LocalVariableInfo from DWARF analysis into StackFrameEntry
     * with enhanced embedded debugging information and precise location mapping.
     * 
     * @param local_var Local variable information from DWARF analysis
     * @param function_start_addr Function start address for scope calculation
     * @return StackFrameEntry with embedded debugging enhancements
     */
    StackFrameEntry convertToStackFrameEntry(const LocalVariableInfo& local_var, 
                                            [[maybe_unused]] uint64_t function_start_addr);
    
    /**
     * @brief Calculate total stack frame size for a function
     * 
     * Analyzes all local variables, parameters, and saved registers to
     * calculate the total stack frame size with proper alignment considerations.
     * 
     * @param function_info Function to calculate frame size for
     * @return Total frame size in bytes with architecture-appropriate alignment
     */
    uint32_t calculateStackFrameSize(const FunctionInfo& function_info);
    
    /**
     * @brief Format stack frame analysis for text output
     * 
     * Creates human-readable formatted output for stack frame analysis results
     * suitable for embedded debugging and development workflows.
     * 
     * @param frame_info Stack frame information to format
     * @return Formatted string with comprehensive stack frame details
     */
    std::string formatStackFrameForText(const StackFrameInfo& frame_info) const;
    
    /**
     * @brief Format stack frame analysis for JSON output
     * 
     * Creates machine-readable JSON output for stack frame analysis results
     * suitable for integration with automated tools and IDEs.
     * 
     * @param frame_info Stack frame information to format
     * @return JSON-formatted string with complete stack frame data
     */
    std::string formatStackFrameForJson(const StackFrameInfo& frame_info) const;
};