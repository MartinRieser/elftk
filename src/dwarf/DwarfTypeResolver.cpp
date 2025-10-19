/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @file DwarfTypeResolver.cpp
 * @brief Implementation of DWARF type resolution with multiple fallback strategies
 *
 * This file implements robust DWARF type resolution using libdwarf API.
 * Extracted from ElfReader.cpp during Phase 3 refactoring (October 2025).
 *
 * ## Key Features:
 * - Multi-strategy type resolution (name, attribute, encoding)
 * - Support for const/volatile/restrict qualifiers
 * - Multi-dimensional array parsing
 * - Type size estimation for ARM EABI
 * - Graceful handling of incomplete DWARF information
 *
 * ## Resolution Algorithm:
 * 1. Check for direct type name (DW_AT_name)
 * 2. Follow type attribute (DW_AT_type) recursively
 * 3. Infer from encoding and size (DW_AT_encoding + DW_AT_byte_size)
 * 4. Handle qualified types (const/volatile)
 * 5. Parse array dimensions from subranges
 * 6. Fall back to hex offset identifier if all strategies fail
 *
 * ## Design Pattern: All-Static Utility Class
 * All methods are static with no instance state, providing:
 * - Zero coupling to ElfReader internals
 * - Pure functions (testable, predictable)
 * - No object lifecycle management
 *
 * @see DwarfTypeResolver.h for class documentation
 * @see doc/DWARF_PARSING.md for detailed parsing guide
 * @see doc/TASK_3.1_COMPLETE.md for extraction details
 */

#include "DwarfTypeResolver.h"
#include <dwarf.h>
#include <libdwarf.h>
#include <sstream>
#include <vector>
#include "../DwarfRAII.h"
#include "../ElfReader.h"  // For TypeSizes constants

std::string DwarfTypeResolver::getDwarfDieName(Dwarf_Debug dbg, Dwarf_Die die) {
    Dwarf_Error error = nullptr;

    // First try to get the regular name (DW_AT_name)
    DwarfRAII::DwarfString name(dbg);
    int ret = dwarf_diename(die, name.ptr(), &error);
    if (ret == DW_DLV_OK && name) {
        return name.toString();
    }

    // If no regular name, try to get the linkage name (DW_AT_linkage_name)
    // This is important for unnamed structures with linkage names (like 6UnnamedStruct)
    DwarfRAII::DwarfAttribute linkage_attr(dbg);
    if (dwarf_attr(die, DW_AT_linkage_name, linkage_attr.ptr(), &error) == DW_DLV_OK) {
        DwarfRAII::DwarfString linkage_name(dbg);
        if (dwarf_formstring(linkage_attr.get(), linkage_name.ptr(), &error) == DW_DLV_OK && linkage_name) {
            return linkage_name.toString();
        }
    }

    return "";
}

std::string DwarfTypeResolver::tryTypeAttributeResolution(Dwarf_Debug dbg,
                                                          Dwarf_Die type_die,
                                                          Dwarf_Error* error) {
    // Strategy 1: Try to follow DW_AT_type attribute for indirect resolution
    DwarfRAII::DwarfAttribute attr(dbg);
    if (dwarf_attr(type_die, DW_AT_type, attr.ptr(), error) == DW_DLV_OK) {
        Dwarf_Off type_offset;
        if (dwarf_global_formref(attr.get(), &type_offset, error) == DW_DLV_OK) {
            DwarfRAII::DwarfDie indirect_type_die(dbg);
            if (dwarf_offdie_b(dbg, type_offset, 1, indirect_type_die.ptr(), error) == DW_DLV_OK) {
                std::string indirect_type = resolveDwarfType(dbg, indirect_type_die.get());
                if (indirect_type.find("type_0x") == std::string::npos) {
                    return indirect_type;
                }
            }
        }
    }
    return "";  // Empty string indicates resolution failed
}

std::string DwarfTypeResolver::tryEncodingBasedResolution(Dwarf_Debug dbg,
                                                          Dwarf_Die type_die,
                                                          Dwarf_Error* error) {
    // Strategy 2: Try to get byte size and encoding for basic type inference
    Dwarf_Unsigned byte_size = 0;
    Dwarf_Unsigned encoding = 0;
    bool has_size = (dwarf_bytesize(type_die, &byte_size, error) == DW_DLV_OK);

    DwarfRAII::DwarfAttribute encoding_attr(dbg);
    bool has_encoding =
        (dwarf_attr(type_die, DW_AT_encoding, encoding_attr.ptr(), error) == DW_DLV_OK);

    if (has_encoding) {
        dwarf_formudata(encoding_attr.get(), &encoding, error);
    }

    if (has_size) {
        // Use DWARF encoding to determine signed/unsigned/float
        switch (byte_size) {
            case 1:
                if (encoding == DW_ATE_unsigned || encoding == DW_ATE_unsigned_char)
                    return "unsigned char";
                return "char";
            case 2:
                if (encoding == DW_ATE_unsigned)
                    return "unsigned short";
                return "short";
            case 4:
                if (encoding == DW_ATE_float)
                    return "float";
                if (encoding == DW_ATE_unsigned)
                    return "unsigned int";
                return "int";
            case 8:
                if (encoding == DW_ATE_float)
                    return "double";
                if (encoding == DW_ATE_unsigned)
                    return "unsigned long long";
                return "long long";
            default:
                break;
        }
    }
    return "";  // Empty string indicates resolution failed
}

std::string DwarfTypeResolver::resolveQualifiedType(Dwarf_Debug dbg,
                                                    Dwarf_Die type_die,
                                                    Dwarf_Error* error,
                                                    const std::string& fallback) {
    // Follow the DW_AT_type attribute to get the underlying type
    // Used for both const and volatile qualifiers
    DwarfRAII::DwarfAttribute attr(dbg);
    if (dwarf_attr(type_die, DW_AT_type, attr.ptr(), error) == DW_DLV_OK) {
        Dwarf_Off type_offset;
        if (dwarf_global_formref(attr.get(), &type_offset, error) == DW_DLV_OK) {
            DwarfRAII::DwarfDie underlying_type_die(dbg);
            if (dwarf_offdie_b(dbg, type_offset, 1, underlying_type_die.ptr(), error) ==
                DW_DLV_OK) {
                return resolveDwarfType(dbg, underlying_type_die.get());
            }
        }
    }
    return fallback;
}

std::string DwarfTypeResolver::resolveDwarfType(Dwarf_Debug dbg, Dwarf_Die type_die) {
    if (type_die == nullptr) {
        return "void";
    }

    Dwarf_Half tag;
    Dwarf_Error error = nullptr;

    int ret = dwarf_tag(type_die, &tag, &error);
    if (ret != DW_DLV_OK) {
        // Enhanced DWARF-based fallback strategies

        // Strategy 1: Try to follow DW_AT_type attribute for indirect resolution
        std::string result = tryTypeAttributeResolution(dbg, type_die, &error);
        if (!result.empty()) {
            return result;
        }

        // Strategy 2: Try to get byte size and encoding for basic type inference
        result = tryEncodingBasedResolution(dbg, type_die, &error);
        if (!result.empty()) {
            return result;
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
        case DW_TAG_const_type:
            return resolveQualifiedType(dbg, type_die, &error, "const_type");
        case DW_TAG_volatile_type:
            return resolveQualifiedType(dbg, type_die, &error, "volatile_type");
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

DwarfTypeResolver::TypeMetadata DwarfTypeResolver::extractTypeMetadata(Dwarf_Debug dbg,
                                                                       Dwarf_Die type_die) {
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
                if (dwarf_tag(child_die, &child_tag, &error) == DW_DLV_OK &&
                    child_tag == DW_TAG_enumerator) {
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
                    if (i > 0)
                        metadata.enum_values += ", ";
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

uint64_t DwarfTypeResolver::estimateTypeSize(const std::string& type_name) {
    // Handle basic types first (including verbose DWARF names)
    if (type_name == "int" || type_name == "float" || type_name == "uint32_t" ||
        type_name == "unsigned int" || type_name == "long int" ||
        type_name == "long unsigned int") {
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
        if (base_type == "int" || base_type == "float" || base_type == "uint32_t" ||
            base_type == "long" || base_type == "long int" || base_type == "long unsigned int" ||
            base_type == "unsigned int") {
            base_size = TypeSizes::INT_SIZE;
        } else if (base_type == "char" || base_type == "uint8_t" || base_type == "int8_t" ||
                   base_type == "signed char" || base_type == "unsigned char") {
            base_size = TypeSizes::CHAR_SIZE;
        } else if (base_type == "double" || base_type == "uint64_t" || base_type == "long long") {
            base_size = TypeSizes::LONG_LONG_SIZE;
        } else if (base_type == "short" || base_type == "uint16_t" || base_type == "int16_t" ||
                   base_type == "short int" || base_type == "short unsigned int") {
            base_size = TypeSizes::SHORT_SIZE;
        } else {
            base_size = TypeSizes::DEFAULT_SIZE;
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

    return 0;  // Unknown size
}

std::string DwarfTypeResolver::parseArrayType(Dwarf_Debug dbg, Dwarf_Die array_die) {
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
                dimensions.push_back(0);  // 0 indicates unknown/flexible size
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
