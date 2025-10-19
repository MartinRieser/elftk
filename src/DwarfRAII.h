/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

/**
 * @file DwarfRAII.h
 * @brief RAII wrappers for libdwarf resources to prevent memory leaks
 *
 * This file provides RAII (Resource Acquisition Is Initialization) wrappers
 * for libdwarf resources. These wrappers automatically manage the lifetime
 * of DWARF resources, ensuring proper cleanup even when exceptions occur.
 *
 * ## Key Benefits:
 * - Automatic resource cleanup (no manual dwarf_dealloc needed)
 * - Exception safety (resources freed even on early returns/exceptions)
 * - Reduced code duplication (centralized cleanup logic)
 * - Prevents memory leaks from forgotten deallocation calls
 *
 * @see ElfReader.cpp for usage examples
 */

#include <libdwarf.h>
#include <utility>

namespace DwarfRAII {

/**
 * @brief RAII wrapper for Dwarf_Attribute
 *
 * Automatically deallocates DWARF attributes when the wrapper goes out of scope.
 *
 * ## Usage Example:
 * ```cpp
 * DwarfAttribute attr(dbg);
 * if (dwarf_attr(die, DW_AT_type, attr.ptr(), &error) == DW_DLV_OK) {
 *     // Use attr.get() to access the attribute
 *     Dwarf_Off offset;
 *     dwarf_global_formref(attr.get(), &offset, &error);
 *     // No need to manually deallocate - automatic on scope exit
 * }
 * ```
 */
class DwarfAttribute {
private:
    Dwarf_Debug dbg_;
    Dwarf_Attribute attr_;

public:
    /**
     * @brief Construct a new DWARF attribute wrapper
     * @param dbg DWARF debug context
     */
    explicit DwarfAttribute(Dwarf_Debug dbg) : dbg_(dbg), attr_(nullptr) {}

    /**
     * @brief Destructor - automatically deallocates the attribute
     */
    ~DwarfAttribute() {
        if (attr_ && dbg_) {
            dwarf_dealloc(dbg_, attr_, DW_DLA_ATTR);
        }
    }

    // Delete copy operations to prevent double-free
    DwarfAttribute(const DwarfAttribute&) = delete;
    DwarfAttribute& operator=(const DwarfAttribute&) = delete;

    // Move operations
    DwarfAttribute(DwarfAttribute&& other) noexcept
        : dbg_(other.dbg_), attr_(other.attr_) {
        other.attr_ = nullptr;
    }

    DwarfAttribute& operator=(DwarfAttribute&& other) noexcept {
        if (this != &other) {
            // Clean up current resource
            if (attr_ && dbg_) {
                dwarf_dealloc(dbg_, attr_, DW_DLA_ATTR);
            }
            // Transfer ownership
            dbg_ = other.dbg_;
            attr_ = other.attr_;
            other.attr_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Get pointer to the underlying attribute (for libdwarf API calls)
     * @return Pointer to Dwarf_Attribute for use with dwarf_attr() etc.
     */
    Dwarf_Attribute* ptr() { return &attr_; }

    /**
     * @brief Get the underlying attribute value
     * @return The managed Dwarf_Attribute
     */
    Dwarf_Attribute get() const { return attr_; }

    /**
     * @brief Check if the attribute is valid (non-null)
     * @return true if attribute is valid, false otherwise
     */
    explicit operator bool() const { return attr_ != nullptr; }

    /**
     * @brief Reset to manage a new attribute (deallocates current if any)
     * @param new_attr New attribute to manage
     */
    void reset(Dwarf_Attribute new_attr = nullptr) {
        if (attr_ && dbg_) {
            dwarf_dealloc(dbg_, attr_, DW_DLA_ATTR);
        }
        attr_ = new_attr;
    }
};

/**
 * @brief RAII wrapper for Dwarf_Die
 *
 * Automatically deallocates DWARF DIEs when the wrapper goes out of scope.
 *
 * ## Usage Example:
 * ```cpp
 * DwarfDie type_die(dbg);
 * if (dwarf_offdie_b(dbg, offset, 1, type_die.ptr(), &error) == DW_DLV_OK) {
 *     std::string type_name = resolveDwarfType(dbg, type_die.get());
 *     // No need to manually deallocate - automatic on scope exit
 * }
 * ```
 */
class DwarfDie {
private:
    Dwarf_Debug dbg_;
    Dwarf_Die die_;

public:
    /**
     * @brief Construct a new DWARF DIE wrapper
     * @param dbg DWARF debug context (can be nullptr for delayed initialization)
     */
    explicit DwarfDie(Dwarf_Debug dbg = nullptr) : dbg_(dbg), die_(nullptr) {}

    /**
     * @brief Destructor - automatically deallocates the DIE
     */
    ~DwarfDie() {
        if (die_) {
            dwarf_dealloc_die(die_);
        }
    }

    // Delete copy operations to prevent double-free
    DwarfDie(const DwarfDie&) = delete;
    DwarfDie& operator=(const DwarfDie&) = delete;

    // Move operations
    DwarfDie(DwarfDie&& other) noexcept
        : dbg_(other.dbg_), die_(other.die_) {
        other.die_ = nullptr;
    }

    DwarfDie& operator=(DwarfDie&& other) noexcept {
        if (this != &other) {
            // Clean up current resource
            if (die_) {
                dwarf_dealloc_die(die_);
            }
            // Transfer ownership
            dbg_ = other.dbg_;
            die_ = other.die_;
            other.die_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Get pointer to the underlying DIE (for libdwarf API calls)
     * @return Pointer to Dwarf_Die for use with dwarf_offdie_b() etc.
     */
    Dwarf_Die* ptr() { return &die_; }

    /**
     * @brief Get the underlying DIE value
     * @return The managed Dwarf_Die
     */
    Dwarf_Die get() const { return die_; }

    /**
     * @brief Check if the DIE is valid (non-null)
     * @return true if DIE is valid, false otherwise
     */
    explicit operator bool() const { return die_ != nullptr; }

    /**
     * @brief Reset to manage a new DIE (deallocates current if any)
     * @param new_die New DIE to manage
     */
    void reset(Dwarf_Die new_die = nullptr) {
        if (die_) {
            dwarf_dealloc_die(die_);
        }
        die_ = new_die;
    }

    /**
     * @brief Set the debug context (useful for delayed initialization)
     * @param dbg DWARF debug context
     */
    void setDebug(Dwarf_Debug dbg) {
        dbg_ = dbg;
    }
};

/**
 * @brief RAII wrapper for DWARF strings (DW_DLA_STRING)
 *
 * Automatically deallocates DWARF strings when the wrapper goes out of scope.
 *
 * ## Usage Example:
 * ```cpp
 * DwarfString name(dbg);
 * if (dwarf_diename(die, name.ptr(), &error) == DW_DLV_OK) {
 *     std::string result(name.get());
 *     // No need to manually deallocate - automatic on scope exit
 * }
 * ```
 */
class DwarfString {
private:
    Dwarf_Debug dbg_;
    char* str_;

public:
    /**
     * @brief Construct a new DWARF string wrapper
     * @param dbg DWARF debug context
     */
    explicit DwarfString(Dwarf_Debug dbg) : dbg_(dbg), str_(nullptr) {}

    /**
     * @brief Destructor - automatically deallocates the string
     */
    ~DwarfString() {
        if (str_ && dbg_) {
            dwarf_dealloc(dbg_, str_, DW_DLA_STRING);
        }
    }

    // Delete copy operations to prevent double-free
    DwarfString(const DwarfString&) = delete;
    DwarfString& operator=(const DwarfString&) = delete;

    // Move operations
    DwarfString(DwarfString&& other) noexcept
        : dbg_(other.dbg_), str_(other.str_) {
        other.str_ = nullptr;
    }

    DwarfString& operator=(DwarfString&& other) noexcept {
        if (this != &other) {
            // Clean up current resource
            if (str_ && dbg_) {
                dwarf_dealloc(dbg_, str_, DW_DLA_STRING);
            }
            // Transfer ownership
            dbg_ = other.dbg_;
            str_ = other.str_;
            other.str_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Get pointer to the underlying string (for libdwarf API calls)
     * @return Pointer to char* for use with dwarf_diename() etc.
     */
    char** ptr() { return &str_; }

    /**
     * @brief Get the underlying string value
     * @return The managed string (may be nullptr)
     */
    const char* get() const { return str_; }

    /**
     * @brief Check if the string is valid (non-null)
     * @return true if string is valid, false otherwise
     */
    explicit operator bool() const { return str_ != nullptr; }

    /**
     * @brief Convert to std::string
     * @return std::string copy of the managed string, or empty if nullptr
     */
    std::string toString() const {
        return str_ ? std::string(str_) : std::string();
    }

    /**
     * @brief Reset to manage a new string (deallocates current if any)
     * @param new_str New string to manage
     */
    void reset(char* new_str = nullptr) {
        if (str_ && dbg_) {
            dwarf_dealloc(dbg_, str_, DW_DLA_STRING);
        }
        str_ = new_str;
    }
};

/**
 * @brief RAII wrapper for Dwarf_Loc_Head_c (location expressions)
 *
 * Automatically deallocates DWARF location blocks when the wrapper goes out of scope.
 *
 * ## Usage Example:
 * ```cpp
 * DwarfLocBlock loc(dbg);
 * if (dwarf_get_loclist_c(attr, loc.ptr(), ...) == DW_DLV_OK) {
 *     // Process location information
 *     // No need to manually deallocate - automatic on scope exit
 * }
 * ```
 */
class DwarfLocBlock {
private:
    Dwarf_Debug dbg_;
    Dwarf_Loc_Head_c loc_head_;

public:
    /**
     * @brief Construct a new DWARF location block wrapper
     * @param dbg DWARF debug context
     */
    explicit DwarfLocBlock(Dwarf_Debug dbg) : dbg_(dbg), loc_head_(nullptr) {}

    /**
     * @brief Destructor - automatically deallocates the location block
     */
    ~DwarfLocBlock() {
        if (loc_head_ && dbg_) {
            dwarf_dealloc(dbg_, loc_head_, DW_DLA_LOC_BLOCK);
        }
    }

    // Delete copy operations to prevent double-free
    DwarfLocBlock(const DwarfLocBlock&) = delete;
    DwarfLocBlock& operator=(const DwarfLocBlock&) = delete;

    // Move operations
    DwarfLocBlock(DwarfLocBlock&& other) noexcept
        : dbg_(other.dbg_), loc_head_(other.loc_head_) {
        other.loc_head_ = nullptr;
    }

    DwarfLocBlock& operator=(DwarfLocBlock&& other) noexcept {
        if (this != &other) {
            // Clean up current resource
            if (loc_head_ && dbg_) {
                dwarf_dealloc(dbg_, loc_head_, DW_DLA_LOC_BLOCK);
            }
            // Transfer ownership
            dbg_ = other.dbg_;
            loc_head_ = other.loc_head_;
            other.loc_head_ = nullptr;
        }
        return *this;
    }

    /**
     * @brief Get pointer to the underlying location block (for libdwarf API calls)
     * @return Pointer to Dwarf_Loc_Head_c for use with dwarf_get_loclist_c()
     */
    Dwarf_Loc_Head_c* ptr() { return &loc_head_; }

    /**
     * @brief Get the underlying location block value
     * @return The managed Dwarf_Loc_Head_c
     */
    Dwarf_Loc_Head_c get() const { return loc_head_; }

    /**
     * @brief Check if the location block is valid (non-null)
     * @return true if location block is valid, false otherwise
     */
    explicit operator bool() const { return loc_head_ != nullptr; }

    /**
     * @brief Reset to manage a new location block (deallocates current if any)
     * @param new_loc New location block to manage
     */
    void reset(Dwarf_Loc_Head_c new_loc = nullptr) {
        if (loc_head_ && dbg_) {
            dwarf_dealloc(dbg_, loc_head_, DW_DLA_LOC_BLOCK);
        }
        loc_head_ = new_loc;
    }
};

} // namespace DwarfRAII
