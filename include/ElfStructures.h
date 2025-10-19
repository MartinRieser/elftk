/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @file ElfStructures.h
 * @brief Core data structures for ELF format and DWARF debug information parsing
 * 
 * This file defines all the fundamental data structures used in ARM ELF binary analysis:
 * 
 * ## Structure Categories:
 * 1. **ELF Format Structures**: Direct representations of ELF binary format elements
 * 2. **DWARF Debug Structures**: Structures for parsing debug information from DWARF sections
 * 3. **Type System Structures**: High-level representations for C/C++ type information
 * 4. **Analysis Result Structures**: Output structures for member-level analysis results
 * 
 * ## Design Philosophy:
 * - **Memory Layout Accurate**: ELF structures match exact binary layout for direct reading
 * - **Platform Independent**: 32-bit and 64-bit variants handle different ARM architectures
 * - **Type Safety**: Strong typing with enums to prevent invalid values
 * - **Performance Oriented**: Efficient member access methods and minimal memory overhead
 * 
 * ## Usage Context:
 * These structures are used throughout the ElfReader implementation to:
 * - Parse raw binary data from ARM ELF files
 * - Extract and organize DWARF debug information
 * - Build type hierarchies for structure member analysis
 * - Store analysis results for formatted output
 * 
 * @note All structures are designed for little-endian ARM systems
 * @see ElfReader.h for usage examples and API documentation
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <variant>

/**
 * @brief Forward declarations for libdwarf types
 * 
 * These forward declarations allow us to use libdwarf types in our structures
 * without including the full libdwarf.h header, which reduces compilation
 * dependencies and potential header conflicts.
 */
typedef struct Dwarf_Debug_s* Dwarf_Debug;  ///< libdwarf debug context handle
typedef struct Dwarf_Die_s* Dwarf_Die;      ///< libdwarf Debug Information Entry handle  
typedef struct Dwarf_Error_s* Dwarf_Error;  ///< libdwarf error information handle
typedef struct Dwarf_Attribute_s* Dwarf_Attribute;  ///< libdwarf attribute handle

// ============================================================================
// ELF Format Enumerations
// ============================================================================

/**
 * @brief ELF file class specification (32-bit vs 64-bit architecture)
 * 
 * This enum identifies whether an ELF file is designed for 32-bit or 64-bit
 * architectures. For ARM embedded systems, ELFCLASS32 is most common.
 * 
 * ## Usage in ARM Development:
 * - **ELFCLASS32**: ARM Cortex-M, Cortex-A32, Cortex-R series (most common)
 * - **ELFCLASS64**: ARM64/AArch64 processors, Cortex-A53/A57/A72 etc.
 * 
 * @note Value stored in EI_CLASS byte (offset 4) of ELF identification
 */
enum class ElfClass : uint8_t {
    ELFCLASS32 = 1,  ///< 32-bit architecture (standard for ARM embedded systems)
    ELFCLASS64 = 2   ///< 64-bit architecture (ARM64/AArch64 systems)
};

/**
 * @brief ELF data encoding specification (byte order/endianness)
 * 
 * Specifies the byte ordering used in the ELF file's data structures.
 * ARM processors typically use little-endian encoding.
 * 
 * ## Practical Impact:
 * - **ELFDATA2LSB**: Multi-byte values stored least significant byte first
 * - **ELFDATA2MSB**: Multi-byte values stored most significant byte first
 * 
 * ## ARM Endianness:
 * Modern ARM cores default to little-endian, though some support big-endian mode.
 * All ARM Cortex-M processors are little-endian only.
 * 
 * @note Value stored in EI_DATA byte (offset 5) of ELF identification
 */
enum class ElfData : uint8_t {
    ELFDATA2LSB = 1, ///< Little-endian (LSB first) - standard for ARM
    ELFDATA2MSB = 2  ///< Big-endian (MSB first) - rare for ARM
};

/**
 * @brief ELF machine architecture types
 * 
 * Defines the target processor architecture for ELF files. This enum contains
 * the machine types supported by ELFSymbolReader for embedded system analysis.
 * 
 * ## Supported Architectures:
 * - **EM_ARM**: 32-bit ARM processors (Cortex-M/A/R series, classic ARM)
 * - **EM_AARCH64**: 64-bit ARM processors (ARM64/AArch64, Cortex-A53/57/72)
 * - **EM_RISCV**: RISC-V processors (both RV32 and RV64 variants)
 * - **EM_XTENSA**: Tensilica Xtensa processors (ESP32, ESP32-S2, ESP32-S3)
 * 
 * ## Architecture Detection:
 * The machine type is stored in the ELF header's e_machine field and combined
 * with ELFCLASS32/ELFCLASS64 to determine the exact target configuration.
 * 
 * ## RISC-V Note:
 * Unlike ARM which has separate machine types for 32-bit and 64-bit variants,
 * RISC-V uses a single EM_RISCV value with ELFCLASS32/ELFCLASS64 distinction.
 */
enum class ElfMachine : uint16_t {
    EM_ARM = 0x28,      ///< ARM 32-bit processors (ARM7, ARM9, Cortex-M/A/R)
    EM_AARCH64 = 0xB7,  ///< ARM 64-bit processors (ARM64/AArch64)  
    EM_RISCV = 0xF3,    ///< RISC-V processors (both RV32 and RV64)
    EM_XTENSA = 0x5E    ///< Tensilica Xtensa processors (ESP32, ESP32-S2, ESP32-S3)
};

/**
 * @brief ELF section types for different kinds of file content
 * 
 * Each section in an ELF file has a type that determines its purpose and
 * how it should be processed. This enum covers the most common section types
 * encountered in ARM embedded development.
 * 
 * ## Critical Sections for Analysis:
 * - **SHT_SYMTAB**: Contains symbol table for functions and variables
 * - **SHT_STRTAB**: Contains string data referenced by other sections
 * - **SHT_PROGBITS**: Contains actual program code and initialized data
 * - **SHT_NOBITS**: Represents uninitialized data (BSS section)
 * 
 * @note Additional debug section types are handled separately by DWARF parsing
 */
enum class SectionType : uint32_t {
    SHT_NULL = 0,       ///< Unused section header entry
    SHT_PROGBITS = 1,   ///< Program data (.text, .data sections)
    SHT_SYMTAB = 2,     ///< Symbol table (functions, variables)
    SHT_STRTAB = 3,     ///< String table (symbol names, section names)
    SHT_RELA = 4,       ///< Relocation entries with explicit addends
    SHT_HASH = 5,       ///< Hash table for symbol lookup
    SHT_DYNAMIC = 6,    ///< Dynamic linking information
    SHT_NOTE = 7,       ///< File notes and auxiliary information
    SHT_NOBITS = 8,     ///< Uninitialized data (.bss section)
    SHT_REL = 9,        ///< Relocation entries without explicit addends
    SHT_SHLIB = 10,     ///< Reserved section type
    SHT_DYNSYM = 11     ///< Dynamic symbol table
};

/**
 * @brief ELF symbol types for different program elements
 * 
 * Symbols in ELF files represent various program elements. The symbol type
 * is encoded in the st_info field and determines how the symbol should be
 * interpreted during analysis.
 * 
 * ## ARM Symbol Analysis:
 * - **STT_FUNC**: ARM Thumb functions have LSB set in address (indicates Thumb mode)
 * - **STT_OBJECT**: Global variables, arrays, structures in embedded firmware
 * - **STT_NOTYPE**: Generic symbols, often compiler-generated labels
 * 
 * ## Usage in Structure Analysis:
 * Only STT_FUNC and STT_OBJECT symbols are typically relevant for member-level
 * analysis, as they represent the actual functions and variables defined in
 * the source code.
 */
enum class SymbolType : uint8_t {
    STT_NOTYPE = 0,   ///< Symbol type not specified (generic symbol)
    STT_OBJECT = 1,   ///< Symbol represents a data object (variable, array, struct)
    STT_FUNC = 2,     ///< Symbol represents a function or method
    STT_SECTION = 3,  ///< Symbol represents a section (compiler-generated)
    STT_FILE = 4      ///< Symbol represents source file name (compiler-generated)
};

// ============================================================================
// DWARF Debug Information Enumerations
// ============================================================================

/**
 * @brief DWARF Debug Information Entry (DIE) tags
 * 
 * DWARF tags identify the type of program element represented by each Debug
 * Information Entry. These tags are essential for structure analysis as they
 * tell us whether we're looking at a class, variable, function, etc.
 * 
 * ## Key Tags for Structure Analysis:
 * - **DW_TAG_structure_type**: C structures and C++ classes (primary target)
 * - **DW_TAG_class_type**: C++ classes with inheritance and methods
 * - **DW_TAG_member**: Individual members within structures/classes
 * - **DW_TAG_variable**: Global and static variables
 * - **DW_TAG_namespace**: C++ namespace definitions
 * - **DW_TAG_compile_unit**: Compilation unit root (source file)
 * 
 * ## Type System Tags:
 * - **DW_TAG_array_type**: Arrays with dimension information
 * - **DW_TAG_pointer_type**: Pointer types and references
 * - **DW_TAG_base_type**: Fundamental types (int, float, char, etc.)
 * - **DW_TAG_typedef**: Type aliases and custom type names
 * 
 * @note Values correspond to DWARF standard specification
 * @see DWARF Debugging Information Format specification for complete details
 */
enum class DwarfTag : uint32_t {
    // Type definition tags - critical for structure analysis
    DW_TAG_array_type = 0x01,              ///< Array type with dimensions
    DW_TAG_class_type = 0x02,              ///< C++ class type
    DW_TAG_entry_point = 0x03,             ///< Program entry point
    DW_TAG_enumeration_type = 0x04,        ///< Enumeration type (enum)
    DW_TAG_formal_parameter = 0x05,        ///< Function parameter
    DW_TAG_imported_declaration = 0x08,    ///< Imported declaration
    DW_TAG_label = 0x0a,                   ///< Program label
    DW_TAG_lexical_block = 0x0b,          ///< Lexical scope block
    DW_TAG_member = 0x0d,                  ///< Structure/class member (critical)
    DW_TAG_pointer_type = 0x0f,            ///< Pointer type
    DW_TAG_reference_type = 0x10,          ///< C++ reference type
    DW_TAG_compile_unit = 0x11,            ///< Compilation unit root (critical)
    DW_TAG_string_type = 0x12,             ///< String type
    DW_TAG_structure_type = 0x13,          ///< C structure type (critical)
    DW_TAG_subroutine_type = 0x15,         ///< Function type signature
    DW_TAG_typedef = 0x16,                 ///< Type definition alias
    DW_TAG_union_type = 0x17,              ///< Union type
    DW_TAG_unspecified_parameters = 0x18,  ///< Variable function parameters
    DW_TAG_variant = 0x19,                 ///< Variant type
    DW_TAG_common_block = 0x1a,            ///< Common block (Fortran)
    DW_TAG_common_inclusion = 0x1b,        ///< Common inclusion (Fortran)
    DW_TAG_inheritance = 0x1c,             ///< C++ inheritance relationship
    DW_TAG_inlined_subroutine = 0x1d,      ///< Inlined function instance
    DW_TAG_module = 0x1e,                  ///< Module (Fortran/Modula)
    DW_TAG_ptr_to_member_type = 0x1f,      ///< C++ pointer-to-member type
    DW_TAG_set_type = 0x20,                ///< Set type (Pascal)
    DW_TAG_subrange_type = 0x21,           ///< Array subrange
    DW_TAG_with_stmt = 0x22,               ///< With statement (Pascal)
    DW_TAG_access_declaration = 0x23,      ///< Access declaration
    DW_TAG_base_type = 0x24,               ///< Fundamental type (int, float, etc.)
    DW_TAG_catch_block = 0x25,             ///< Exception catch block
    DW_TAG_const_type = 0x26,              ///< Const-qualified type
    DW_TAG_constant = 0x27,                ///< Named constant
    DW_TAG_enumerator = 0x28,              ///< Enumeration value
    DW_TAG_file_type = 0x29,               ///< File type (Pascal)
    DW_TAG_friend = 0x2a,                  ///< C++ friend declaration
    DW_TAG_namelist = 0x2b,                ///< Namelist (Fortran)
    DW_TAG_namelist_item = 0x2c,           ///< Namelist item (Fortran)
    DW_TAG_packed_type = 0x2d,             ///< Packed type
    DW_TAG_subprogram = 0x2e,              ///< Function/method definition
    DW_TAG_template_type_parameter = 0x2f,  ///< C++ template type parameter
    DW_TAG_template_value_parameter = 0x30, ///< C++ template value parameter
    DW_TAG_thrown_type = 0x31,             ///< Exception type
    DW_TAG_try_block = 0x32,               ///< Exception try block
    DW_TAG_variant_part = 0x33,            ///< Variant part (Ada)
    DW_TAG_variable = 0x34,                ///< Variable declaration (critical)
    DW_TAG_volatile_type = 0x35,           ///< Volatile-qualified type
    DW_TAG_dwarf_procedure = 0x36,         ///< DWARF procedure
    DW_TAG_restrict_type = 0x37,           ///< Restrict-qualified type (C99)
    DW_TAG_interface_type = 0x38,          ///< Interface type (Java)
    DW_TAG_namespace = 0x39,               ///< C++ namespace (critical)
    DW_TAG_imported_module = 0x3a,         ///< Imported module
    DW_TAG_unspecified_type = 0x3b,        ///< Unspecified type
    DW_TAG_partial_unit = 0x3c,            ///< Partial compilation unit
    DW_TAG_imported_unit = 0x3d,           ///< Imported compilation unit
    DW_TAG_condition = 0x3f,               ///< Condition (Ada)
    DW_TAG_shared_type = 0x40              ///< Shared type (UPC)
};

/**
 * @brief DWARF attribute codes for DIE properties
 * 
 * DWARF attributes provide detailed information about each Debug Information Entry.
 * These attributes are crucial for extracting structure member layouts, variable
 * addresses, type relationships, and other essential information for analysis.
 * 
 * ## Critical Attributes for Structure Analysis:
 * - **DW_AT_name**: Element name (variable name, structure name, etc.)
 * - **DW_AT_type**: Type reference for variables and members
 * - **DW_AT_byte_size**: Size of structures, classes, and data types
 * - **DW_AT_data_member_location**: Offset of members within structures
 * - **DW_AT_location**: Memory address of variables and objects
 * 
 * ## ARM Embedded Development Context:
 * - **DW_AT_low_pc/high_pc**: Function address ranges for ARM Thumb mode detection
 * - **DW_AT_external**: Distinguishes global variables from static/local ones
 * - **DW_AT_declaration**: Identifies forward declarations vs definitions
 * 
 * @note Not all attributes are used in current implementation - focus on structure analysis
 */
enum class DwarfAttribute : uint32_t {
    // Navigation and structure attributes
    DW_AT_sibling = 0x01,                ///< Sibling DIE reference
    DW_AT_location = 0x02,               ///< Variable/object memory location (critical)
    DW_AT_name = 0x03,                   ///< Element name string (critical)
    DW_AT_ordering = 0x09,               ///< Array ordering
    DW_AT_byte_size = 0x0b,              ///< Size in bytes (critical for structures)
    DW_AT_bit_offset = 0x0c,             ///< Bit field offset
    DW_AT_bit_size = 0x0d,               ///< Bit field size
    
    // Compilation unit attributes
    DW_AT_stmt_list = 0x10,              ///< Line number table reference
    DW_AT_low_pc = 0x11,                 ///< Function/block start address
    DW_AT_high_pc = 0x12,                ///< Function/block end address  
    DW_AT_language = 0x13,               ///< Source language (C, C++, etc.)
    DW_AT_member = 0x14,                 ///< Structure member reference
    DW_AT_discr = 0x15,                  ///< Discriminant reference
    DW_AT_discr_value = 0x16,            ///< Discriminant value
    DW_AT_visibility = 0x17,             ///< Symbol visibility
    DW_AT_import = 0x18,                 ///< Import declaration
    DW_AT_string_length = 0x19,          ///< String length
    DW_AT_common_reference = 0x1a,       ///< Common block reference
    DW_AT_comp_dir = 0x1b,               ///< Compilation directory
    DW_AT_const_value = 0x1c,            ///< Constant value
    DW_AT_containing_type = 0x1d,        ///< Containing type reference
    DW_AT_default_value = 0x1e,          ///< Default parameter value
    
    // Function and scope attributes
    DW_AT_inline = 0x20,                 ///< Inline function flag
    DW_AT_is_optional = 0x21,            ///< Optional parameter flag
    DW_AT_lower_bound = 0x22,            ///< Array lower bound
    DW_AT_producer = 0x25,               ///< Compiler identification
    DW_AT_prototyped = 0x27,             ///< Function prototype flag
    DW_AT_return_addr = 0x2a,            ///< Return address
    DW_AT_start_scope = 0x2c,            ///< Scope start address
    DW_AT_bit_stride = 0x2e,             ///< Array bit stride
    DW_AT_upper_bound = 0x2f,            ///< Array upper bound
    
    // Advanced attributes
    DW_AT_abstract_origin = 0x31,        ///< Abstract origin reference
    DW_AT_accessibility = 0x32,          ///< C++ access level (public/private/protected)
    DW_AT_address_class = 0x33,          ///< Address class
    DW_AT_artificial = 0x34,             ///< Compiler-generated flag
    DW_AT_base_types = 0x35,             ///< Base types reference
    DW_AT_calling_convention = 0x36,     ///< Function calling convention
    DW_AT_count = 0x37,                  ///< Array element count
    DW_AT_data_member_location = 0x38,   ///< Member offset within structure (critical)
    DW_AT_decl_column = 0x39,            ///< Declaration column number
    DW_AT_decl_file = 0x3a,              ///< Declaration file reference
    DW_AT_decl_line = 0x3b,              ///< Declaration line number
    DW_AT_declaration = 0x3c,            ///< Declaration flag (vs definition)
    DW_AT_discr_list = 0x3d,             ///< Discriminant list
    DW_AT_encoding = 0x3e,               ///< Base type encoding (signed, unsigned, float)
    DW_AT_external = 0x3f,               ///< External linkage flag (critical for globals)
    DW_AT_frame_base = 0x40,             ///< Frame base for local variables
    DW_AT_friend = 0x41,                 ///< C++ friend declaration
    DW_AT_identifier_case = 0x42,        ///< Identifier case sensitivity
    DW_AT_macro_info = 0x43,             ///< Macro information reference
    DW_AT_namelist_item = 0x44,          ///< Namelist item (Fortran)
    DW_AT_priority = 0x45,               ///< Priority
    DW_AT_segment = 0x46,                ///< Segment reference
    DW_AT_specification = 0x47,          ///< Specification reference
    DW_AT_static_link = 0x48,            ///< Static link
    DW_AT_type = 0x49,                   ///< Type reference (critical for variables)
    DW_AT_use_location = 0x4a,           ///< Use location
    DW_AT_variable_parameter = 0x4b,     ///< Variable parameter flag
    DW_AT_virtuality = 0x4c,             ///< C++ virtual function flag
    DW_AT_vtable_elem_location = 0x4d,   ///< C++ vtable element location
    DW_AT_allocated = 0x4e,              ///< Allocated flag
    DW_AT_associated = 0x4f,             ///< Associated flag
    DW_AT_data_location = 0x50,          ///< Data location
    DW_AT_byte_stride = 0x51,            ///< Array byte stride
    DW_AT_entry_pc = 0x52,               ///< Entry point address
    DW_AT_use_UTF8 = 0x53,               ///< UTF-8 string flag
    DW_AT_extension = 0x54,              ///< Vendor extension
    DW_AT_ranges = 0x55,                 ///< Address ranges
    DW_AT_trampoline = 0x56,             ///< Trampoline flag
    DW_AT_call_column = 0x57,            ///< Call site column
    DW_AT_call_file = 0x58,              ///< Call site file
    DW_AT_call_line = 0x59,              ///< Call site line
    DW_AT_description = 0x5a             ///< Description string
};

// ============================================================================
// DWARF Debug Information Entry (DIE) Structure
// ============================================================================

/**
 * @brief DWARF Debug Information Entry structure for legacy parsing
 * 
 * This structure represents a parsed DWARF Debug Information Entry (DIE) from
 * the legacy DWARF parser. It contains all the information needed to understand
 * program elements like structures, variables, functions, etc.
 * 
 * ## Structure Layout:
 * - **offset**: Position in DWARF section for DIE identification
 * - **abbrev_code**: References abbreviation table for attribute definitions
 * - **tag**: Type of program element (structure, variable, function, etc.)
 * - **has_children**: Whether this DIE has child DIEs (e.g., structure members)
 * - **attributes**: Key-value map of all DIE properties
 * - **children**: Nested DIEs for complex structures
 * 
 * ## Usage in Structure Analysis:
 * ```cpp
 * DwarfDIE struct_die;
 * if (struct_die.tag == static_cast<uint32_t>(DwarfTag::DW_TAG_structure_type)) {
 *     std::string name = struct_die.getName();
 *     uint32_t size = struct_die.getByteSize();
 *     // Process structure members from children vector
 * }
 * ```
 * 
 * @note This structure is used by the legacy DWARF parser - modern parsing uses libdwarf directly
 * @deprecated Prefer libdwarf-based parsing over this legacy structure representation
 */
struct DwarfDIE {
    uint32_t offset;        ///< Offset in DWARF section (unique identifier for this DIE)
    uint32_t abbrev_code;   ///< Abbreviation code referencing attribute definitions
    uint32_t tag;           ///< DWARF tag identifying element type (DW_TAG_structure_type, etc.)
    bool has_children;      ///< True if this DIE has child DIEs
    
    /**
     * @brief Attribute storage using variant for different value types
     * 
     * DWARF attributes can have different value types:
     * - uint32_t: Most numeric values, offsets, sizes
     * - uint64_t: Large addresses, 64-bit values  
     * - std::string: Names, string constants
     */
    std::map<DwarfAttribute, std::variant<uint32_t, uint64_t, std::string>> attributes;
    
    std::vector<DwarfDIE> children;  ///< Child DIEs (e.g., structure members, nested scopes)
    
    // ========================================================================
    // Convenience Methods for Common Attribute Access
    // ========================================================================
    
    /**
     * @brief Get the name attribute of this DIE
     * @return Element name or empty string if no name attribute
     * 
     * ## Usage Examples:
     * - Structure: "SensorData", "DeviceConfig"
     * - Variable: "global_counter", "sensor_readings"  
     * - Function: "init_device", "process_data"
     */
    std::string getName() const {
        auto it = attributes.find(DwarfAttribute::DW_AT_name);
        return (it != attributes.end()) ? std::get<std::string>(it->second) : "";
    }
    
    /**
     * @brief Get the byte size attribute of this DIE
     * @return Size in bytes or 0 if no size attribute
     * 
     * ## ARM Embedded Context:
     * - Structures: Total size including padding (e.g., 12 bytes for 3 fields)
     * - Base types: Standard sizes (4 for int, 1 for char, 4 for float)
     * - Arrays: Total array size (element_size × element_count)
     */
    uint32_t getByteSize() const {
        auto it = attributes.find(DwarfAttribute::DW_AT_byte_size);
        return (it != attributes.end()) ? std::get<uint32_t>(it->second) : 0;
    }
    
    /**
     * @brief Get the type reference attribute of this DIE
     * @return DWARF offset to type DIE or 0 if no type attribute
     * 
     * This is used for variables and members to reference their type definition.
     * The returned offset points to another DIE that describes the actual type.
     */
    uint32_t getType() const {
        auto it = attributes.find(DwarfAttribute::DW_AT_type);
        return (it != attributes.end()) ? std::get<uint32_t>(it->second) : 0;
    }
    
    /**
     * @brief Get the data member location attribute (member offset within structure)
     * @return Offset in bytes from structure start or 0 if no location attribute
     * 
     * ## ARM ABI Alignment Examples:
     * - First member: offset 0
     * - Second member: offset based on previous member size + alignment padding
     * - Nested structures: offset includes all preceding members and padding
     */
    uint32_t getDataMemberLocation() const {
        auto it = attributes.find(DwarfAttribute::DW_AT_data_member_location);
        return (it != attributes.end()) ? std::get<uint32_t>(it->second) : 0;
    }
};

// ============================================================================
// ELF Binary Format Structures  
// ============================================================================

/**
 * @brief 32-bit ELF header structure - maps directly to binary format
 * 
 * This structure represents the ELF header exactly as it appears in the binary file.
 * All fields are positioned to match the ELF specification for direct memory mapping.
 * 
 * ## ARM Embedded Context:
 * - **e_machine**: Should be EM_ARM (0x28) for ARM processors
 * - **e_entry**: Program entry point, LSB set indicates ARM Thumb mode
 * - **e_shoff**: Critical for finding section headers containing symbols and debug info
 * - **e_shstrndx**: Points to section name string table
 * 
 * ## Memory Layout (52 bytes total):
 * ```
 * Offset | Field        | Size | Purpose
 * -------|-------------|------|----------------------------------
 * 16     | e_type       | 2    | Object file type (executable, etc.)
 * 18     | e_machine    | 2    | Target architecture (ARM = 0x28)
 * 20     | e_version    | 4    | ELF version
 * 24     | e_entry      | 4    | Entry point address
 * 28     | e_phoff      | 4    | Program header offset
 * 32     | e_shoff      | 4    | Section header offset (critical)
 * 36     | e_flags      | 4    | Processor-specific flags
 * 40     | e_ehsize     | 2    | ELF header size
 * 42     | e_phentsize  | 2    | Program header entry size
 * 44     | e_phnum      | 2    | Program header count
 * 46     | e_shentsize  | 2    | Section header entry size  
 * 48     | e_shnum      | 2    | Section header count
 * 50     | e_shstrndx   | 2    | Section name string table index
 * ```
 * 
 * @note First 16 bytes (ELF identification) are handled separately in loadFile()
 */
struct Elf32_Ehdr {
    uint16_t e_type;      ///< Object file type (ET_EXEC, ET_DYN, etc.)
    uint16_t e_machine;   ///< Target architecture (EM_ARM=0x28, EM_AARCH64=0xB7, EM_RISCV=0xF3)
    uint32_t e_version;   ///< ELF version (typically 1)
    uint32_t e_entry;     ///< Entry point virtual address (critical for ARM Thumb detection)
    uint32_t e_phoff;     ///< Program header table offset
    uint32_t e_shoff;     ///< Section header table offset (critical for analysis)
    uint32_t e_flags;     ///< Processor-specific flags  
    uint16_t e_ehsize;    ///< ELF header size (typically 52 for 32-bit)
    uint16_t e_phentsize; ///< Program header entry size
    uint16_t e_phnum;     ///< Program header entry count
    uint16_t e_shentsize; ///< Section header entry size (typically 40 for 32-bit)
    uint16_t e_shnum;     ///< Section header entry count
    uint16_t e_shstrndx;  ///< Section header string table index
};

/**
 * @brief 64-bit ELF header structure (for ARM64/AArch64 systems)
 * @note Similar to 32-bit version but with 64-bit address fields for ARM64 support
 */
struct Elf64_Ehdr {
    uint16_t e_type;      ///< Object file type
    uint16_t e_machine;   ///< Target architecture (EM_ARM=0x28, EM_AARCH64=0xB7, EM_RISCV=0xF3)
    uint32_t e_version;   ///< ELF version
    uint64_t e_entry;     ///< Entry point virtual address (64-bit)
    uint64_t e_phoff;     ///< Program header table offset (64-bit)
    uint64_t e_shoff;     ///< Section header table offset (64-bit)
    uint32_t e_flags;     ///< Processor-specific flags
    uint16_t e_ehsize;    ///< ELF header size (typically 64 for 64-bit)
    uint16_t e_phentsize; ///< Program header entry size
    uint16_t e_phnum;     ///< Program header entry count
    uint16_t e_shentsize; ///< Section header entry size (typically 64 for 64-bit)
    uint16_t e_shnum;     ///< Section header entry count
    uint16_t e_shstrndx;  ///< Section header string table index
};

/**
 * @brief 32-bit ELF section header - describes individual file sections
 * 
 * Each section header describes a segment of the ELF file. Critical sections for
 * analysis include .symtab (symbols), .strtab (strings), .debug_info (DWARF).
 */
struct Elf32_Shdr {
    uint32_t sh_name;      ///< Section name string table offset
    uint32_t sh_type;      ///< Section type (SHT_SYMTAB, SHT_STRTAB, etc.)
    uint32_t sh_flags;     ///< Section flags
    uint32_t sh_addr;      ///< Virtual address in memory
    uint32_t sh_offset;    ///< Offset in file (critical for data access)
    uint32_t sh_size;      ///< Section size in bytes
    uint32_t sh_link;      ///< Link to related section (e.g., symbol table → string table)
    uint32_t sh_info;      ///< Additional section information
    uint32_t sh_addralign; ///< Alignment requirements
    uint32_t sh_entsize;   ///< Size of each entry (for tables)
    std::string name;      ///< Resolved section name (e.g., ".symtab", ".debug_info")
};

/**
 * @brief 64-bit ELF section header
 * @note Similar to 32-bit version with 64-bit address and size fields
 */
struct Elf64_Shdr {
    uint32_t sh_name;      ///< Section name string table offset
    uint32_t sh_type;      ///< Section type  
    uint64_t sh_flags;     ///< Section flags (64-bit)
    uint64_t sh_addr;      ///< Virtual address in memory (64-bit)
    uint64_t sh_offset;    ///< Offset in file (64-bit)
    uint64_t sh_size;      ///< Section size in bytes (64-bit)
    uint32_t sh_link;      ///< Link to related section
    uint32_t sh_info;      ///< Additional section information
    uint64_t sh_addralign; ///< Alignment requirements (64-bit)
    uint64_t sh_entsize;   ///< Size of each entry (64-bit)
    std::string name;      ///< Resolved section name
};

/**
 * @brief 32-bit ELF symbol table entry - represents functions and variables
 * 
 * Symbol entries are the primary way to identify program elements in ELF files.
 * Each symbol has a name, address, size, and type information essential for analysis.
 * 
 * ## ARM-Specific Notes:
 * - Function addresses with LSB set indicate ARM Thumb mode
 * - st_value contains the actual memory address where the symbol is located
 * - st_info encodes both symbol type (STT_FUNC, STT_OBJECT) and binding (local/global)
 */
struct Elf32_Sym {
    uint32_t st_name;   ///< Symbol name string table offset
    uint32_t st_value;  ///< Symbol address (ARM: LSB set = Thumb mode)
    uint32_t st_size;   ///< Symbol size in bytes
    uint8_t st_info;    ///< Symbol type and binding (encoded)
    uint8_t st_other;   ///< Symbol visibility
    uint16_t st_shndx;  ///< Related section index
    std::string name;   ///< Resolved symbol name (from string table)
    
    /** @brief Extract symbol type from st_info field (STT_FUNC, STT_OBJECT, etc.) */
    uint8_t getType() const { return st_info & 0xf; }
    
    /** @brief Extract symbol binding from st_info field (STB_LOCAL, STB_GLOBAL, etc.) */
    uint8_t getBind() const { return st_info >> 4; }
};

/**
 * @brief 64-bit ELF symbol table entry
 * @note Field order differs from 32-bit version due to alignment requirements
 */
struct Elf64_Sym {
    uint32_t st_name;   ///< Symbol name string table offset
    uint8_t st_info;    ///< Symbol type and binding
    uint8_t st_other;   ///< Symbol visibility
    uint16_t st_shndx;  ///< Related section index
    uint64_t st_value;  ///< Symbol address (64-bit)
    uint64_t st_size;   ///< Symbol size in bytes (64-bit)
    std::string name;   ///< Resolved symbol name
    
    /** @brief Extract symbol type from st_info field */
    uint8_t getType() const { return st_info & 0xf; }
    
    /** @brief Extract symbol binding from st_info field */
    uint8_t getBind() const { return st_info >> 4; }
};

// ============================================================================
// Type System and Analysis Result Structures
// ============================================================================

/**
 * @brief Individual member within a structure/class type
 * 
 * Represents a single member (field) within a C structure or C++ class,
 * including its name, type, position, and size information.
 */
struct TypeMember {
    std::string name;        ///< Member name (e.g., "temperature", "humidity")
    std::string type;        ///< Member type (e.g., "float", "uint32_t", "SensorConfig")
    uint32_t offset;         ///< Byte offset within containing structure
    uint32_t size;           ///< Size of this member in bytes
    bool is_struct = false;  ///< True if this member is itself a structure/class
    
    TypeMember(const std::string& n, const std::string& t, uint32_t o, uint32_t s, bool is_s = false)
        : name(n), type(t), offset(o), size(s), is_struct(is_s) {}
};

/**
 * @brief Complete type information for structures and classes
 * 
 * Contains all information needed to understand and expand a C/C++ type,
 * including total size, member layout, and DWARF identification.
 */
struct TypeInfo {
    uint32_t size;                        ///< Total structure size in bytes
    std::vector<TypeMember> members;      ///< All members with offsets and types
    uint64_t dwarf_offset;                ///< Unique DWARF DIE offset for identification
    std::string full_qualified_name;      ///< Full name (e.g., "MyNamespace::SensorData")
    
    TypeInfo() : size(0), dwarf_offset(0) {}
    TypeInfo(uint32_t s, std::vector<TypeMember> m, uint64_t offset = 0, const std::string& fqn = "") 
        : size(s), members(std::move(m)), dwarf_offset(offset), full_qualified_name(fqn) {}
};

/**
 * @brief Phase 7.1B: Advanced Type Resolution Data Structures (DWARF 5)
 */

/**
 * @enum TypeQualifiers
 * @brief DWARF 5 advanced type qualifiers for enhanced type analysis
 * 
 * Represents modern C++ type qualifiers and compiler optimizations
 * extracted from DWARF 5 debug information.
 */
enum class TypeQualifiers : uint32_t {
    NONE = 0x00,
    CONST = 0x01,        ///< const type qualifier
    VOLATILE = 0x02,     ///< volatile type qualifier  
    IMMUTABLE = 0x04,    ///< DWARF 5 immutable type (DW_TAG_immutable_type)
    PACKED = 0x08,       ///< DWARF 5 packed type (DW_TAG_packed_type)
    ATOMIC = 0x10,       ///< DWARF 5 atomic type (DW_TAG_atomic_type)
    DYNAMIC = 0x20       ///< DWARF 5 dynamic type (DW_TAG_dynamic_type)
};

/**
 * @brief Template parameter information for C++ template analysis
 */
struct TemplateParameter {
    std::string name;           ///< Parameter name (e.g., "T", "N")
    std::string type;           ///< Parameter type for type parameters
    std::string value;          ///< Parameter value for non-type parameters
    bool is_type_parameter;     ///< True for type params, false for value params
    
    TemplateParameter(const std::string& n, const std::string& t, const std::string& v, bool is_type)
        : name(n), type(t), value(v), is_type_parameter(is_type) {}
};

/**
 * @brief Complete template specialization information
 */
struct TemplateInfo {
    std::string template_name;                      ///< Base template name
    std::vector<TemplateParameter> parameters;      ///< Template parameters
    bool is_specialization;                         ///< True if this is a specialization
    std::string specialized_signature;              ///< Full specialization signature
    
    TemplateInfo() : is_specialization(false) {}
};

/**
 * @brief Type dependency tracking for optimized resolution
 */
struct TypeDependency {
    std::string dependent_type;     ///< Type that depends on another
    std::string base_type;          ///< Type being depended on
    std::string relationship;       ///< "pointer_to", "array_of", "member_of", etc.
    
    TypeDependency(const std::string& dep, const std::string& base, const std::string& rel)
        : dependent_type(dep), base_type(base), relationship(rel) {}
};

/**
 * @brief Compiler optimization hints extracted from DWARF
 */
struct OptimizationHints {
    bool is_optimized_away;         ///< Variable optimized out by compiler
    bool has_multiple_locations;    ///< Variable stored in multiple locations
    std::string optimization_info;   ///< Additional optimization details
    
    OptimizationHints() : is_optimized_away(false), has_multiple_locations(false) {}
};

/**
 * @brief Enhanced type information with DWARF 5 features
 * 
 * Extends the basic TypeInfo with advanced type resolution capabilities,
 * template analysis, and performance optimization hints.
 */
struct AdvancedTypeInfo {
    TypeQualifiers qualifiers;                      ///< DWARF 5 type qualifiers
    TemplateInfo template_info;                     ///< C++ template information
    std::vector<TypeDependency> dependencies;       ///< Type dependency graph
    OptimizationHints hints;                        ///< Compiler optimization data
    
    // Cache and performance data
    uint64_t resolution_time_ns;                    ///< Time spent resolving this type
    bool is_cached;                                 ///< True if loaded from cache
    uint32_t reference_count;                       ///< Number of references to this type
    
    AdvancedTypeInfo() : qualifiers(TypeQualifiers::NONE), resolution_time_ns(0), 
                        is_cached(false), reference_count(0) {}
};

/**
 * @brief Analysis result for individual structure members with calculated addresses
 * 
 * Represents the final output of member-level analysis, showing exactly where
 * each structure member is located in ARM memory.
 */
struct MemberInfo {
    std::string name;     ///< Full member path (e.g., "sensor_data.config.timeout")
    uint64_t address;     ///< Calculated ARM memory address
    std::string type;     ///< Member type string
    bool is_constant;     ///< True if this is a constant variable
    std::string constant_value; ///< String representation of constant value (if constant)
    std::string section_name;   ///< ELF section name where symbol is defined (e.g., ".text", ".data", ".rodata")

    // Phase 2A.1: Enhanced Variable Metadata
    uint64_t byte_size = 0;        ///< Size in bytes
    uint32_t alignment = 0;        ///< Alignment requirement in bytes
    uint64_t padding_bytes = 0;    ///< Padding bytes after this member
    bool is_typedef = false;       ///< True if this type is a typedef
    std::string underlying_type;   ///< Underlying type if typedef, or enum base type
    bool is_union = false;         ///< True if this is a union member
    bool is_bitfield = false;      ///< True if this is a bitfield member
    uint32_t bit_offset = 0;       ///< Bit offset within byte (for bitfields)
    uint32_t bit_size = 0;         ///< Size in bits (for bitfields)
    std::string enum_values;       ///< Enum values if this is an enum type
    
    MemberInfo(const std::string& n, uint64_t a, const std::string& t)
        : name(n), address(a), type(t), is_constant(false) {}
        
    MemberInfo(const std::string& n, uint64_t a, const std::string& t, bool constant, const std::string& const_val)
        : name(n), address(a), type(t), is_constant(constant), constant_value(const_val) {}
        
    // Phase 2A.1: Enhanced constructor with detailed metadata
    MemberInfo(const std::string& n, uint64_t a, const std::string& t, uint64_t size, uint32_t align = 0, 
               bool typedef_flag = false, const std::string& underlying = "", bool union_flag = false,
               bool bitfield_flag = false, uint32_t bit_off = 0, uint32_t bit_sz = 0, const std::string& enum_vals = "")
        : name(n), address(a), type(t), is_constant(false), byte_size(size), alignment(align),
          is_typedef(typedef_flag), underlying_type(underlying), is_union(union_flag), 
          is_bitfield(bitfield_flag), bit_offset(bit_off), bit_size(bit_sz), enum_values(enum_vals) {}
};

/**
 * @brief Phase 7.1A: Local Variable Location Analysis Data Structures
 */

/**
 * @enum LocationType
 * @brief Types of variable storage locations in DWARF debug information
 * 
 * Represents different ways variables can be stored during program execution.
 * These correspond to DWARF location expression opcodes.
 */
enum class LocationType {
    STACK_OFFSET,    ///< Variable on stack relative to frame pointer (DW_OP_fbreg)
    REGISTER,        ///< Variable stored in CPU register (DW_OP_reg0-31)  
    MEMORY_ADDRESS,  ///< Variable at fixed memory address (DW_OP_addr) - globals
    REGISTER_OFFSET, ///< Variable at register + offset (DW_OP_breg0-31)
    COMPOSITE,       ///< Variable split across multiple locations (DW_OP_piece)
    OPTIMIZED_OUT,   ///< Variable optimized away by compiler
    UNKNOWN          ///< Location cannot be determined
};

/**
 * @struct VariableLocation
 * @brief Describes where a variable is stored during execution
 * 
 * Parsed from DWARF location expressions, this structure provides human-readable
 * information about variable storage for debugging and analysis.
 */
struct VariableLocation {
    LocationType type;              ///< Type of storage location
    int64_t offset_or_register;     ///< Stack offset or register number
    std::string description;        ///< Human-readable description ("SP+8", "r4", etc.)
    
    VariableLocation() : type(LocationType::UNKNOWN), offset_or_register(0), description("unknown") {}
    
    VariableLocation(LocationType t, int64_t val, const std::string& desc)
        : type(t), offset_or_register(val), description(desc) {}
};

/**
 * @struct LocalVariableInfo  
 * @brief Information about function-local variables and parameters
 * 
 * Extends the current global variable analysis to include local variables
 * within function scopes, including their stack locations and lifetimes.
 */
struct LocalVariableInfo {
    std::string name;               ///< Variable name
    std::string type;               ///< Variable type (e.g., "uint32_t", "SensorData*")
    VariableLocation location;      ///< Where variable is stored
    uint64_t scope_start_pc;        ///< Program counter where variable becomes valid
    uint64_t scope_end_pc;          ///< Program counter where variable goes out of scope
    bool is_parameter;              ///< True if function parameter, false if local variable
    uint32_t parameter_index;       ///< Parameter position (0-based) if is_parameter is true
    
    LocalVariableInfo() : scope_start_pc(0), scope_end_pc(0), is_parameter(false), parameter_index(0) {}
    
    LocalVariableInfo(const std::string& n, const std::string& t, const VariableLocation& loc,
                      uint64_t start_pc, uint64_t end_pc, bool is_param, uint32_t param_idx = 0)
        : name(n), type(t), location(loc), scope_start_pc(start_pc), scope_end_pc(end_pc),
          is_parameter(is_param), parameter_index(param_idx) {}
};

/**
 * @struct FunctionInfo
 * @brief Enhanced function information with local variable analysis
 * 
 * Extends function analysis to include stack frame layout and local variable mapping.
 * Used for Phase 7.1A local variable analysis features.
 */
struct FunctionInfo {
    std::string name;                                    ///< Function name
    std::string mangled_name;                            ///< Mangled C++ name (if applicable)
    uint64_t start_address;                              ///< Function start address
    uint64_t end_address;                                ///< Function end address  
    uint32_t stack_frame_size;                           ///< Total stack frame size in bytes
    std::vector<LocalVariableInfo> local_variables;     ///< All local variables and parameters
    std::vector<LocalVariableInfo> parameters;          ///< Function parameters only (subset of local_variables)
    
    FunctionInfo() : start_address(0), end_address(0), stack_frame_size(0) {}
    
    /**
     * @brief Check if this function could be an interrupt handler
     * 
     * Uses heuristics to identify potential interrupt handlers based on:
     * - Function name patterns (e.g., "*_Handler", "IRQ*", "*_ISR")
     * - Address location in typical interrupt vector table regions
     * - Function characteristics (small size, no parameters)
     */
    bool isPotentialInterruptHandler() const {
        // Check function name patterns
        return (name.find("_Handler") != std::string::npos ||
                name.find("IRQ") != std::string::npos ||
                name.find("_ISR") != std::string::npos ||
                name.find("_handler") != std::string::npos ||
                name.find("interrupt") != std::string::npos);
    }
};

// ============================================================================
// Phase 7.2: Interrupt Vector Table Structures
// ============================================================================

/**
 * @brief Interrupt vector entry information
 * 
 * Represents a single entry in an interrupt vector table, containing
 * the vector number, handler address, and associated function information.
 */
struct InterruptVectorEntry {
    uint32_t vector_number;        ///< Vector number (0-based index)
    uint64_t handler_address;      ///< Address of interrupt handler function
    std::string handler_name;      ///< Name of handler function (if available)
    std::string description;       ///< Human-readable description of interrupt
    bool is_valid;                 ///< Whether this entry contains a valid handler
    
    InterruptVectorEntry() : vector_number(0), handler_address(0), is_valid(false) {}
    
    InterruptVectorEntry(uint32_t num, uint64_t addr, const std::string& name = "", 
                        const std::string& desc = "")
        : vector_number(num), handler_address(addr), handler_name(name), 
          description(desc), is_valid(true) {}
};

/**
 * @brief Complete interrupt vector table information
 * 
 * Contains all interrupt vectors discovered in an ELF file, along with
 * metadata about the vector table structure and target architecture.
 */
struct InterruptVectorTable {
    uint64_t base_address;                           ///< Base address of vector table
    uint32_t entry_size;                             ///< Size of each vector entry (typically 4 bytes)
    uint32_t total_entries;                          ///< Total number of vector entries
    std::string architecture;                        ///< Target architecture (ARM, RISC-V, etc.)
    std::vector<InterruptVectorEntry> vectors;       ///< All interrupt vector entries
    std::map<uint64_t, std::string> handler_functions; ///< Map of handler addresses to function names
    
    InterruptVectorTable() : base_address(0), entry_size(4), total_entries(0) {}
    
    /**
     * @brief Get number of valid interrupt handlers
     */
    size_t getValidHandlerCount() const {
        size_t count = 0;
        for (const auto& vector : vectors) {
            if (vector.is_valid) count++;
        }
        return count;
    }
    
    /**
     * @brief Find vector entry by number
     */
    const InterruptVectorEntry* findVector(uint32_t vector_number) const {
        for (const auto& vector : vectors) {
            if (vector.vector_number == vector_number) {
                return &vector;
            }
        }
        return nullptr;
    }
};

//==============================================================================
// Phase 7.2: Memory Region Mapping and Validation Data Structures
//==============================================================================

/**
 * @brief ELF program header types (segment types)
 * 
 * Defines the different types of program segments that can exist in an ELF file.
 * Each segment represents a loadable or informational region in memory.
 */
enum class ElfSegmentType : uint32_t {
    PT_NULL = 0,        ///< Unused program header entry
    PT_LOAD = 1,        ///< Loadable segment (code/data)
    PT_DYNAMIC = 2,     ///< Dynamic linking information
    PT_INTERP = 3,      ///< Interpreter path
    PT_NOTE = 4,        ///< Auxiliary information
    PT_SHLIB = 5,       ///< Reserved (unused)
    PT_PHDR = 6,        ///< Program header table itself
    PT_TLS = 7,         ///< Thread-local storage
    
    // Operating system-specific range
    PT_LOOS = 0x60000000,        ///< Start of OS-specific
    PT_HIOS = 0x6FFFFFFF,        ///< End of OS-specific
    
    // Processor-specific range  
    PT_LOPROC = 0x70000000,      ///< Start of processor-specific
    PT_HIPROC = 0x7FFFFFFF,      ///< End of processor-specific
    
    // ARM-specific segments
    PT_ARM_ARCHEXT = 0x70000000, ///< ARM architecture extensions
    PT_ARM_EXIDX = 0x70000001,   ///< ARM exception index table
    
    // GNU-specific segments
    PT_GNU_EH_FRAME = 0x6474e550, ///< GNU exception handling frame
    PT_GNU_STACK = 0x6474e551,     ///< GNU stack flags
    PT_GNU_RELRO = 0x6474e552      ///< GNU read-only relocation
};

/**
 * @brief ELF program header flags
 * 
 * Permission flags for memory segments (read, write, execute).
 */
enum class ElfSegmentFlags : uint32_t {
    PF_X = 1,        ///< Execute permission
    PF_W = 2,        ///< Write permission  
    PF_R = 4,        ///< Read permission
    PF_MASKOS = 0x0ff00000,   ///< OS-specific flags mask
    PF_MASKPROC = 0xf0000000  ///< Processor-specific flags mask
};

/**
 * @brief ELF Program Header structure (32-bit)
 * 
 * Describes a single program segment in the ELF file.
 * Program headers define how segments should be loaded into memory.
 */
struct Elf32_Phdr {
    uint32_t p_type;      ///< Segment type (PT_LOAD, PT_DYNAMIC, etc.)
    uint32_t p_offset;    ///< Offset from beginning of file
    uint32_t p_vaddr;     ///< Virtual address in memory
    uint32_t p_paddr;     ///< Physical address (for embedded systems)
    uint32_t p_filesz;    ///< Size of segment in file
    uint32_t p_memsz;     ///< Size of segment in memory
    uint32_t p_flags;     ///< Segment permissions (read/write/execute)
    uint32_t p_align;     ///< Alignment requirement
    
    Elf32_Phdr() : p_type(0), p_offset(0), p_vaddr(0), p_paddr(0), 
                    p_filesz(0), p_memsz(0), p_flags(0), p_align(0) {}
};

/**
 * @brief ELF Program Header structure (64-bit)
 * 
 * 64-bit version of program header with different field ordering.
 */
struct Elf64_Phdr {
    uint32_t p_type;      ///< Segment type
    uint32_t p_flags;     ///< Segment permissions (moved before addresses in 64-bit)
    uint64_t p_offset;    ///< Offset from beginning of file
    uint64_t p_vaddr;     ///< Virtual address in memory
    uint64_t p_paddr;     ///< Physical address (for embedded systems)
    uint64_t p_filesz;    ///< Size of segment in file  
    uint64_t p_memsz;     ///< Size of segment in memory
    uint64_t p_align;     ///< Alignment requirement
    
    Elf64_Phdr() : p_type(0), p_flags(0), p_offset(0), p_vaddr(0), p_paddr(0),
                    p_filesz(0), p_memsz(0), p_align(0) {}
};

/**
 * @brief Memory region classification
 * 
 * Classifies memory regions by their purpose and characteristics
 * for embedded systems analysis.
 */
enum class MemoryRegionType {
    CODE,           ///< Executable code (.text)
    DATA,           ///< Initialized data (.data)
    BSS,            ///< Uninitialized data (.bss)
    RODATA,         ///< Read-only data (.rodata)
    STACK,          ///< Stack region
    HEAP,           ///< Heap region
    DYNAMIC,        ///< Dynamic linking information
    TLS,            ///< Thread-local storage
    NOTE,           ///< Auxiliary information
    EXCEPTION,      ///< Exception handling data
    UNKNOWN         ///< Unknown or mixed purpose
};

/**
 * @brief Single memory region information
 * 
 * Represents a contiguous memory region with its characteristics,
 * permissions, and validation status.
 */
struct MemoryRegion {
    uint64_t virtual_address;     ///< Virtual memory address
    uint64_t physical_address;    ///< Physical memory address (embedded systems)
    uint64_t file_offset;         ///< Offset in ELF file
    uint64_t file_size;           ///< Size in file (may be less than memory size)
    uint64_t memory_size;         ///< Size in memory (includes BSS expansion)
    uint64_t alignment;           ///< Memory alignment requirement
    
    MemoryRegionType region_type; ///< Classification of memory region
    ElfSegmentType segment_type;  ///< ELF segment type
    uint32_t permissions;         ///< Read/Write/Execute flags
    
    std::string name;             ///< Human-readable region name
    std::string description;      ///< Detailed description
    bool is_loadable;            ///< Whether region should be loaded into memory
    bool is_valid;               ///< Whether region passed validation checks
    
    // Validation results
    struct ValidationInfo {
        bool address_valid;       ///< Virtual address is reasonable
        bool size_valid;          ///< Size is reasonable
        bool alignment_valid;     ///< Alignment requirements are met
        bool overlap_detected;    ///< Overlaps with other regions
        bool permission_conflict; ///< Permission conflicts detected
        std::vector<std::string> warnings; ///< Validation warnings
        std::vector<std::string> errors;   ///< Validation errors
        
        ValidationInfo() : address_valid(true), size_valid(true), alignment_valid(true),
                          overlap_detected(false), permission_conflict(false) {}
    } validation;
    
    MemoryRegion() : virtual_address(0), physical_address(0), file_offset(0),
                    file_size(0), memory_size(0), alignment(1),
                    region_type(MemoryRegionType::UNKNOWN), 
                    segment_type(ElfSegmentType::PT_NULL), permissions(0),
                    is_loadable(false), is_valid(true) {}
    
    /**
     * @brief Check if region has specific permission
     */
    bool hasPermission(ElfSegmentFlags flag) const {
        return (permissions & static_cast<uint32_t>(flag)) != 0;
    }
    
    /**
     * @brief Get permission string (e.g., "rwx", "r-x")
     */
    std::string getPermissionString() const {
        std::string result = "---";
        if (hasPermission(ElfSegmentFlags::PF_R)) result[0] = 'r';
        if (hasPermission(ElfSegmentFlags::PF_W)) result[1] = 'w';  
        if (hasPermission(ElfSegmentFlags::PF_X)) result[2] = 'x';
        return result;
    }
    
    /**
     * @brief Check if address range falls within this region
     */
    bool containsAddress(uint64_t address) const {
        return address >= virtual_address && 
               address < (virtual_address + memory_size);
    }
    
    /**
     * @brief Check if this region overlaps with another
     */
    bool overlaps(const MemoryRegion& other) const {
        uint64_t this_end = virtual_address + memory_size;
        uint64_t other_end = other.virtual_address + other.memory_size;
        
        return virtual_address < other_end && other.virtual_address < this_end;
    }
};

/**
 * @brief Complete memory layout mapping
 * 
 * Contains all memory regions discovered in an ELF file with
 * validation results and embedded systems analysis.
 */
struct MemoryRegionMap {
    std::vector<MemoryRegion> regions;        ///< All memory regions
    std::string architecture;                 ///< Target architecture
    uint64_t entry_point;                     ///< Program entry point address
    uint64_t total_virtual_size;              ///< Total virtual memory footprint
    uint64_t total_physical_size;             ///< Total physical memory usage
    
    // Memory layout characteristics
    struct LayoutInfo {
        uint64_t code_base_address;           ///< Base address of code regions
        uint64_t data_base_address;           ///< Base address of data regions
        uint64_t stack_address;               ///< Stack location (if known)
        uint64_t heap_address;                ///< Heap location (if known)
        bool has_physical_addresses;          ///< Whether p_paddr is meaningful
        bool is_position_independent;         ///< PIE/PIC binary
        std::string memory_model;             ///< Flat, Harvard, etc.
    } layout;
    
    // Validation results
    struct GlobalValidation {
        bool layout_valid;                    ///< Overall layout is valid
        bool no_overlaps;                     ///< No region overlaps detected
        bool addresses_reasonable;            ///< Addresses are in reasonable ranges
        bool sizes_reasonable;                ///< Sizes are reasonable
        size_t error_count;                   ///< Total validation errors
        size_t warning_count;                 ///< Total validation warnings
        std::vector<std::string> global_errors;   ///< Layout-wide errors
        std::vector<std::string> global_warnings; ///< Layout-wide warnings
        
        GlobalValidation() : layout_valid(true), no_overlaps(true), 
                           addresses_reasonable(true), sizes_reasonable(true),
                           error_count(0), warning_count(0) {}
    } validation;
    
    MemoryRegionMap() : entry_point(0), total_virtual_size(0), total_physical_size(0) {
        layout.code_base_address = 0;
        layout.data_base_address = 0; 
        layout.stack_address = 0;
        layout.heap_address = 0;
        layout.has_physical_addresses = false;
        layout.is_position_independent = false;
    }
    
    /**
     * @brief Get regions by type
     */
    std::vector<const MemoryRegion*> getRegionsByType(MemoryRegionType type) const {
        std::vector<const MemoryRegion*> result;
        for (const auto& region : regions) {
            if (region.region_type == type) {
                result.push_back(&region);
            }
        }
        return result;
    }
    
    /**
     * @brief Find region containing address
     */
    const MemoryRegion* findRegionContaining(uint64_t address) const {
        for (const auto& region : regions) {
            if (region.containsAddress(address)) {
                return &region;
            }
        }
        return nullptr;
    }
    
    /**
     * @brief Get total number of loadable regions
     */
    size_t getLoadableRegionCount() const {
        size_t count = 0;
        for (const auto& region : regions) {
            if (region.is_loadable) count++;
        }
        return count;
    }
    
    /**
     * @brief Calculate memory usage statistics
     */
    void calculateMemoryUsage() {
        total_virtual_size = 0;
        total_physical_size = 0;
        
        for (const auto& region : regions) {
            if (region.is_loadable) {
                // Calculate virtual memory span
                uint64_t region_end = region.virtual_address + region.memory_size;
                if (region_end > total_virtual_size) {
                    total_virtual_size = region_end;
                }
                
                // Add to physical size (file size for actual storage)
                total_physical_size += region.file_size;
            }
        }
    }
};

//==============================================================================
// Stack Frame Analysis Data Structures (Extended for Embedded Debugging)
//==============================================================================

/**
 * @brief Stack frame variable entry for detailed embedded debugging
 * 
 * Represents a single variable or parameter within a function's stack frame,
 * with precise location information for embedded debugging tools.
 */
struct StackFrameEntry {
    std::string name;                    ///< Variable or parameter name
    std::string type;                    ///< Data type (int, char*, struct MyStruct, etc.)
    int64_t stack_offset;                ///< Offset from frame pointer (negative = local vars, positive = parameters)
    uint32_t size_bytes;                 ///< Size in bytes (for bounds checking)
    uint64_t scope_start_pc;             ///< PC where variable becomes valid
    uint64_t scope_end_pc;               ///< PC where variable goes out of scope
    bool is_parameter;                   ///< true = function parameter, false = local variable
    uint32_t parameter_index;            ///< Parameter number (0-based, only valid if is_parameter = true)
    std::string location_description;    ///< Human-readable location description
    
    StackFrameEntry() : stack_offset(0), size_bytes(0), scope_start_pc(0), scope_end_pc(0), 
                       is_parameter(false), parameter_index(0) {}
    
    /**
     * @brief Check if variable is active at given program counter
     */
    bool isActiveAtPC(uint64_t pc) const {
        return (pc >= scope_start_pc && pc < scope_end_pc);
    }
    
    /**
     * @brief Get formatted location string for debugging output
     */
    std::string getLocationString() const {
        if (stack_offset < 0) {
            return "SP" + std::to_string(stack_offset);  // Local variables
        } else if (stack_offset > 0) {
            return "SP+" + std::to_string(stack_offset); // Parameters/return address area
        } else {
            return "SP+0";  // Frame pointer location
        }
    }
};

/**
 * @brief Register usage information for function analysis
 * 
 * Tracks which registers are used by a function for calling convention
 * analysis and embedded debugging support.
 */
struct RegisterUsage {
    std::vector<std::string> used_registers;     ///< List of registers used (r0, r1, sp, lr, etc.)
    std::vector<std::string> callee_saved;       ///< Registers that must be preserved
    std::vector<std::string> caller_saved;       ///< Registers that may be modified
    std::vector<std::string> parameter_registers; ///< Registers used for parameter passing
    std::vector<std::string> return_registers;    ///< Registers used for return values
    bool uses_frame_pointer;                     ///< Whether function uses frame pointer (FP/R11)
    bool has_variable_args;                      ///< Whether function accepts variable arguments
    
    RegisterUsage() : uses_frame_pointer(false), has_variable_args(false) {}
};

/**
 * @brief Stack frame calling convention information
 * 
 * Describes the calling convention used by a function, crucial for
 * embedded debugging and understanding parameter passing.
 */
struct CallingConvention {
    std::string name;                        ///< Convention name (AAPCS, AAPCS64, RISC-V, etc.)
    std::string architecture;                ///< Target architecture (ARM, ARM64, RISC-V)
    uint32_t stack_alignment;                ///< Required stack alignment (typically 4 or 8 bytes)
    uint32_t frame_alignment;                ///< Frame alignment requirement
    std::vector<std::string> param_registers; ///< Parameter passing registers in order
    std::vector<std::string> return_registers; ///< Return value registers
    bool stack_grows_down;                   ///< Stack growth direction (true = grows downward)
    
    CallingConvention() : stack_alignment(4), frame_alignment(4), stack_grows_down(true) {}
};

/**
 * @brief Comprehensive stack frame analysis information
 * 
 * Complete stack frame layout with all variables, calling convention details,
 * and embedded debugging information. Extends the basic FunctionInfo with
 * detailed stack frame analysis for professional embedded debugging tools.
 */
struct StackFrameInfo {
    std::string function_name;               ///< Function name
    std::string mangled_name;                ///< Mangled C++ name (if applicable)
    uint64_t function_start_address;         ///< Function start address
    uint64_t function_end_address;           ///< Function end address
    
    // Stack Frame Layout
    uint32_t total_frame_size;               ///< Total stack frame size in bytes
    uint32_t local_variables_size;           ///< Size allocated for local variables
    uint32_t parameter_area_size;            ///< Size of parameter area
    uint32_t saved_registers_size;           ///< Size for saved registers
    int64_t frame_pointer_offset;            ///< Offset of frame pointer from stack pointer
    
    // Frame Contents
    std::vector<StackFrameEntry> stack_variables;  ///< All stack variables (parameters + locals)
    std::vector<StackFrameEntry> parameters;       ///< Function parameters only
    std::vector<StackFrameEntry> local_variables;  ///< Local variables only
    
    // Architecture-Specific Information
    CallingConvention calling_convention;    ///< Calling convention details
    RegisterUsage register_usage;            ///< Register usage analysis
    
    // Debugging Support
    std::string prologue_instructions;       ///< Function prologue (for debugging)
    std::string epilogue_instructions;       ///< Function epilogue (for debugging)
    bool has_exception_handling;             ///< Whether function has exception handling
    bool is_leaf_function;                   ///< Whether function calls other functions
    
    StackFrameInfo() : function_start_address(0), function_end_address(0), 
                      total_frame_size(0), local_variables_size(0), parameter_area_size(0),
                      saved_registers_size(0), frame_pointer_offset(0),
                      has_exception_handling(false), is_leaf_function(false) {}
    
    /**
     * @brief Get maximum stack offset used by any variable
     */
    int64_t getMaxStackOffset() const {
        int64_t max_offset = 0;
        for (const auto& var : stack_variables) {
            if (var.stack_offset > max_offset) {
                max_offset = var.stack_offset;
            }
        }
        return max_offset;
    }
    
    /**
     * @brief Get minimum stack offset used by any variable
     */
    int64_t getMinStackOffset() const {
        int64_t min_offset = 0;
        for (const auto& var : stack_variables) {
            if (var.stack_offset < min_offset) {
                min_offset = var.stack_offset;
            }
        }
        return min_offset;
    }
    
    /**
     * @brief Find variable by name in the stack frame
     */
    const StackFrameEntry* findVariable(const std::string& var_name) const {
        for (const auto& var : stack_variables) {
            if (var.name == var_name) {
                return &var;
            }
        }
        return nullptr;
    }
    
    /**
     * @brief Get number of parameters
     */
    size_t getParameterCount() const {
        return parameters.size();
    }
    
    /**
     * @brief Get number of local variables
     */
    size_t getLocalVariableCount() const {
        return local_variables.size();
    }
    
    /**
     * @brief Check if function uses frame pointer for embedded debugging
     */
    bool usesFramePointer() const {
        return register_usage.uses_frame_pointer;
    }
    
    /**
     * @brief Get formatted summary for debugging output
     */
    std::string getSummary() const {
        return function_name + " (Frame: " + std::to_string(total_frame_size) + " bytes, " +
               std::to_string(getParameterCount()) + " params, " +
               std::to_string(getLocalVariableCount()) + " locals)";
    }
};

/**
 * @brief Stack frame analysis results container
 * 
 * Contains all stack frame analysis results for an ELF file, organized
 * by function for easy lookup and comprehensive embedded debugging support.
 */
struct StackFrameAnalysisResults {
    std::string target_architecture;                          ///< Target architecture (ARM, ARM64, RISC-V)
    std::string abi_name;                                     ///< ABI name (AAPCS, AAPCS64, RISC-V, etc.)
    std::map<std::string, StackFrameInfo> function_frames;   ///< Function name -> stack frame info
    std::map<uint64_t, std::string> address_to_function;     ///< Address -> function name mapping
    
    // Analysis Statistics
    uint32_t total_functions_analyzed;       ///< Number of functions with stack frame analysis
    uint32_t functions_with_frame_pointer;   ///< Functions using frame pointer
    uint32_t leaf_functions;                 ///< Functions that don't call others
    uint64_t largest_frame_size;             ///< Largest stack frame size found
    std::string largest_frame_function;      ///< Function with largest stack frame
    
    StackFrameAnalysisResults() : total_functions_analyzed(0), functions_with_frame_pointer(0),
                                 leaf_functions(0), largest_frame_size(0) {}
    
    /**
     * @brief Add stack frame information for a function
     */
    void addStackFrame(const StackFrameInfo& frame_info) {
        function_frames[frame_info.function_name] = frame_info;
        address_to_function[frame_info.function_start_address] = frame_info.function_name;
        
        total_functions_analyzed++;
        if (frame_info.usesFramePointer()) {
            functions_with_frame_pointer++;
        }
        if (frame_info.is_leaf_function) {
            leaf_functions++;
        }
        if (frame_info.total_frame_size > largest_frame_size) {
            largest_frame_size = frame_info.total_frame_size;
            largest_frame_function = frame_info.function_name;
        }
    }
    
    /**
     * @brief Find stack frame by function name
     */
    const StackFrameInfo* findStackFrame(const std::string& function_name) const {
        auto it = function_frames.find(function_name);
        return (it != function_frames.end()) ? &it->second : nullptr;
    }
    
    /**
     * @brief Find stack frame by function address
     */
    const StackFrameInfo* findStackFrameByAddress(uint64_t address) const {
        auto it = address_to_function.find(address);
        if (it != address_to_function.end()) {
            return findStackFrame(it->second);
        }
        return nullptr;
    }
    
    /**
     * @brief Get analysis statistics summary
     */
    std::string getStatisticsSummary() const {
        return "Stack Frame Analysis: " + std::to_string(total_functions_analyzed) + " functions, " +
               std::to_string(functions_with_frame_pointer) + " with FP, " +
               std::to_string(leaf_functions) + " leaf functions, " +
               "largest frame: " + std::to_string(largest_frame_size) + " bytes (" + 
               largest_frame_function + ")";
    }
};