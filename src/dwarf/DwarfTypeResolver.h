/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <string>
#include <cstdint>

// Forward declarations for libdwarf
typedef struct Dwarf_Debug_s* Dwarf_Debug;
typedef struct Dwarf_Die_s* Dwarf_Die;
typedef struct Dwarf_Error_s* Dwarf_Error;

/**
 * @class DwarfTypeResolver
 * @brief DWARF type resolution and size calculation utilities
 *
 * This module handles all DWARF type resolution logic, including:
 * - Type name resolution from DWARF DIEs
 * - Qualified type handling (const, volatile, restrict)
 * - Array type parsing with multi-dimensional support
 * - Type size estimation from type names
 * - Multiple fallback resolution strategies
 *
 * ## Design Pattern: All-Static Utility Class
 * DwarfTypeResolver is a stateless utility class with only static methods.
 * This design provides:
 * - **Zero coupling** to ElfReader internal state
 * - **No object lifecycle management** (no construction/destruction needed)
 * - **Pure functions** - same inputs always produce same outputs
 * - **Easy testing** - no setup required
 *
 * ## Resolution Strategies
 * The module uses multiple fallback strategies for robust type resolution:
 *
 * 1. **Direct Name**: DIE has DW_AT_name attribute → return name directly
 * 2. **Type Attribute**: Follow DW_AT_type → resolve recursively
 * 3. **Encoding-Based**: Use DW_AT_byte_size + DW_AT_encoding → infer type
 * 4. **Qualified Type**: Prepend const/volatile/restrict to base type
 * 5. **Hex Fallback**: Return "type_0xADDRESS" if all strategies fail
 *
 * ## Supported DWARF Tags
 * - `DW_TAG_base_type` - Primitive types (int, char, float)
 * - `DW_TAG_pointer_type` - Pointer types
 * - `DW_TAG_array_type` - Array types with dimensions
 * - `DW_TAG_typedef` - Type aliases
 * - `DW_TAG_const_type` - Const-qualified types
 * - `DW_TAG_volatile_type` - Volatile-qualified types
 * - `DW_TAG_restrict_type` - Restrict-qualified types
 * - `DW_TAG_structure_type` - Struct types
 * - `DW_TAG_union_type` - Union types
 * - `DW_TAG_enumeration_type` - Enum types
 *
 * ## Usage Example
 * ```cpp
 * // Resolve a variable's type
 * Dwarf_Attribute type_attr;
 * dwarf_attr(var_die, DW_AT_type, &type_attr, nullptr);
 * Dwarf_Off type_offset;
 * dwarf_global_formref(type_attr, &type_offset, nullptr);
 * Dwarf_Die type_die;
 * dwarf_offdie_b(dbg, type_offset, true, &type_die, nullptr);
 *
 * std::string type_name = DwarfTypeResolver::resolveDwarfType(dbg, type_die);
 * uint64_t size = DwarfTypeResolver::estimateTypeSize(type_name);
 * ```
 *
 * ## Extracted from ElfReader
 * This module was extracted from ElfReader.cpp (Phase 3, Task 3.1, October 2025)
 * to improve modularity and reduce coupling. See doc/TASK_3.1_COMPLETE.md for details.
 *
 * @author ELF Symbol Reader Project
 * @date October 2025
 * @see ElfReader
 * @see doc/DWARF_PARSING.md for detailed DWARF parsing guide
 */
class DwarfTypeResolver {
public:
    /**
     * @brief Type metadata structure for enhanced type information
     *
     * Provides comprehensive type information beyond simple type names.
     * Used for advanced analysis and future extensibility.
     */
    struct TypeMetadata {
        std::string type_name;           ///< Primary type name (e.g., "int", "MyStruct")
        std::string underlying_type;     ///< For typedefs, the underlying type (e.g., "uint32_t" → "unsigned int")
        std::string enum_values;         ///< For enums, comma-separated list of enumerator values
        uint64_t byte_size = 0;         ///< Size in bytes from DW_AT_byte_size
        bool is_typedef = false;        ///< Whether this is a typedef (DW_TAG_typedef)
        bool is_union = false;          ///< Whether this is a union type (DW_TAG_union_type)
    };

    /**
     * @brief Resolve DWARF type DIE to human-readable type name string
     *
     * Main entry point for type resolution. Applies multiple strategies to
     * resolve DWARF type DIEs to readable type names.
     *
     * @param dbg DWARF debug context from dwarf_init_path()
     * @param type_die Type DIE to resolve (from DW_AT_type attribute)
     * @return Type name string (e.g., "int", "const char*", "uint32_t[10]")
     *         Returns "type_0xADDRESS" fallback if resolution fails
     *
     * ## Resolution Strategies (in order):
     * 1. **Direct Name**: Check DW_AT_name attribute
     * 2. **Type Attribute**: Follow DW_AT_type → resolve recursively
     * 3. **Encoding-Based**: Infer from DW_AT_byte_size + DW_AT_encoding
     * 4. **Qualified Type**: Handle const/volatile/restrict prefixes
     * 5. **Array Type**: Parse dimensions with parseArrayType()
     * 6. **Hex Fallback**: Return "type_0xOFFSET" for unresolvable types
     *
     * ## Examples:
     * ```
     * DW_TAG_base_type with name="int"           → "int"
     * DW_TAG_const_type → DW_TAG_base_type       → "const int"
     * DW_TAG_pointer_type → DW_TAG_base_type     → "char*"
     * DW_TAG_array_type with bounds=10           → "int[10]"
     * DW_TAG_typedef with name="uint32_t"        → "uint32_t"
     * ```
     *
     * @see tryTypeAttributeResolution() for Strategy 2
     * @see tryEncodingBasedResolution() for Strategy 3
     * @see parseArrayType() for array handling
     * @see doc/DWARF_PARSING.md for detailed resolution algorithm
     */
    static std::string resolveDwarfType(Dwarf_Debug dbg, Dwarf_Die type_die);

    /**
     * @brief Get name from DWARF DIE with error handling
     *
     * Safely extracts the DW_AT_name attribute from a DIE.
     * Used internally by resolution methods.
     *
     * @param dbg DWARF debug context from dwarf_init_path()
     * @param die DIE to get name from (variable, type, function, etc.)
     * @return DIE name string, or empty string if DW_AT_name not available
     *
     * @note Returns empty string instead of throwing on missing name
     * @note Used by resolveDwarfType() as first resolution strategy
     */
    static std::string getDwarfDieName(Dwarf_Debug dbg, Dwarf_Die die);

    /**
     * @brief Parse array type with dimensions from DWARF subranges
     *
     * Extracts element type and array dimensions from DW_TAG_array_type DIE.
     * Handles both 1D and multi-dimensional arrays.
     *
     * @param dbg DWARF debug context from dwarf_init_path()
     * @param array_die Array type DIE (DW_TAG_array_type)
     * @return Array type string with dimensions (e.g., "int[10]", "uint8_t[3][4]")
     *         Returns "unknown_array" if element type cannot be resolved
     *
     * ## DWARF Array Structure:
     * ```
     * DW_TAG_array_type
     *   DW_AT_type: → element_type_die
     *   DW_TAG_subrange_type (dimension 1)
     *     DW_AT_upper_bound: 9  (for array[10])
     *   DW_TAG_subrange_type (dimension 2, optional)
     *     DW_AT_upper_bound: 3  (for [][4])
     * ```
     *
     * ## Examples:
     * ```
     * int array[10]           → "int[10]"
     * uint8_t matrix[3][4]    → "unsigned char[3][4]"
     * char* strings[5]        → "char*[5]"
     * int flexible[]          → "int[0]" (flexible array member)
     * ```
     *
     * @note Handles DW_AT_upper_bound (DWARF 2-4) and DW_AT_count (DWARF 4+)
     * @note Multi-dimensional arrays parsed recursively
     * @see resolveDwarfType() which calls this for DW_TAG_array_type
     */
    static std::string parseArrayType(Dwarf_Debug dbg, Dwarf_Die array_die);

    /**
     * @brief Extract comprehensive type metadata
     * @param dbg DWARF debug context
     * @param type_die Type DIE to analyze
     * @return TypeMetadata structure with detailed type information
     *
     * Extracts additional information beyond basic type names:
     * - Typedef underlying types
     * - Enum values
     * - Union detection
     * - Byte sizes
     */
    static TypeMetadata extractTypeMetadata(Dwarf_Debug dbg, Dwarf_Die type_die);

    /**
     * @brief Estimate type size from type name
     * @param type_name Type name string
     * @return Estimated size in bytes (0 if unknown)
     *
     * Handles:
     * - Basic C/C++ types (int, char, float, etc.)
     * - Verbose DWARF type names (signed char, short int, etc.)
     * - Array types with dimensions (type[N][M])
     * - stdint.h types (uint32_t, int8_t, etc.)
     *
     * Uses ARM EABI sizes (32-bit):
     * - char: 1 byte
     * - short: 2 bytes
     * - int/long/pointer: 4 bytes
     * - long long/double: 8 bytes
     */
    static uint64_t estimateTypeSize(const std::string& type_name);

private:
    /**
     * @brief Strategy 1: Try to follow DW_AT_type attribute for indirect resolution
     * @param dbg DWARF debug context
     * @param type_die Type DIE to resolve
     * @param error Error pointer for DWARF operations
     * @return Resolved type name or empty string on failure
     */
    static std::string tryTypeAttributeResolution(Dwarf_Debug dbg, Dwarf_Die type_die, Dwarf_Error* error);

    /**
     * @brief Strategy 2: Try to get byte size and encoding for basic type inference
     * @param dbg DWARF debug context
     * @param type_die Type DIE to resolve
     * @param error Error pointer for DWARF operations
     * @return Inferred type name or empty string on failure
     *
     * Uses DW_AT_encoding and DW_AT_byte_size to infer basic types:
     * - Size 1: char vs unsigned char
     * - Size 2: short vs unsigned short
     * - Size 4: int, unsigned int, float
     * - Size 8: long long, unsigned long long, double
     */
    static std::string tryEncodingBasedResolution(Dwarf_Debug dbg, Dwarf_Die type_die, Dwarf_Error* error);

    /**
     * @brief Resolve qualified types (const, volatile)
     * @param dbg DWARF debug context
     * @param type_die Qualified type DIE
     * @param error Error pointer for DWARF operations
     * @param fallback Fallback string if resolution fails
     * @return Underlying type name
     *
     * Follows DW_AT_type attribute to get the type being qualified.
     * Used for DW_TAG_const_type and DW_TAG_volatile_type.
     */
    static std::string resolveQualifiedType(Dwarf_Debug dbg, Dwarf_Die type_die, Dwarf_Error* error, const std::string& fallback);
};
