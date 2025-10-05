/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <string>
#include <unordered_set>
#include <memory>

/**
 * @file StringInterner.h
 * @brief String interning system for memory optimization
 * 
 * This file defines the StringInterner class which provides string deduplication
 * to reduce memory usage in applications that work with many duplicate strings.
 * Common in ELF analysis where symbol names, type names, and member names
 * frequently repeat across large binaries.
 * 
 * @author ELF Symbol Reader Project
 * @date 2025
 */

/**
 * @class StringInterner
 * @brief High-performance string interning system for memory optimization
 * 
 * The StringInterner maintains a pool of unique strings and returns references
 * to the pooled strings instead of creating duplicates. This provides significant
 * memory savings when processing large ELF files with many repeated symbol names.
 * 
 * ## Memory Benefits:
 * - Eliminates duplicate string storage (15-30% memory reduction typical)
 * - Enables fast pointer-based string comparisons
 * - Reduces memory fragmentation from string allocations
 * - Particularly effective with symbol names that repeat frequently
 * 
 * ## Performance Characteristics:
 * - O(1) average case intern() performance using hash set
 * - O(1) string comparison using pointer equality for interned strings
 * - Memory overhead: ~24-32 bytes per unique string (hash set node)
 * - Thread safety: Not thread-safe, intended for single-threaded use
 * 
 * ## Usage Pattern:
 * ```cpp
 * StringInterner interner;
 * const std::string& name1 = interner.intern("main");
 * const std::string& name2 = interner.intern("main"); // Returns same reference
 * assert(&name1 == &name2); // Pointer equality
 * ```
 * 
 * ## Memory Analysis Example:
 * For a typical ARM firmware with 1000 symbols where 200 names repeat:
 * - Without interning: 1000 strings × 8 chars avg = 8000 bytes
 * - With interning: 200 unique strings × 8 chars = 1600 bytes (80% savings)
 */
class StringInterner {
public:
    /**
     * @brief Construct a new StringInterner
     */
    StringInterner() = default;

    /**
     * @brief Destructor - cleans up the string pool
     */
    ~StringInterner() = default;

    // Disable copy construction and assignment
    StringInterner(const StringInterner&) = delete;
    StringInterner& operator=(const StringInterner&) = delete;

    // Enable move construction and assignment
    StringInterner(StringInterner&&) = default;
    StringInterner& operator=(StringInterner&&) = default;

    /**
     * @brief Intern a string (copy version)
     * 
     * Takes a string, adds it to the intern pool if not already present,
     * and returns a const reference to the pooled string. Multiple calls
     * with the same string content will return references to the same object.
     * 
     * @param str The string to intern
     * @return const std::string& Reference to the interned string
     * 
     * ## Example:
     * ```cpp
     * StringInterner interner;
     * const std::string& symbol1 = interner.intern("printf");
     * const std::string& symbol2 = interner.intern("printf");
     * // symbol1 and symbol2 point to the same string object
     * ```
     * 
     * ## Performance:
     * - Time: O(1) average case, O(n) worst case (hash collision)
     * - Space: O(1) if string already exists, O(k) where k = string length
     */
    const std::string& intern(const std::string& str);

    /**
     * @brief Intern a string (move version)
     * 
     * More efficient version for rvalue strings. If the string doesn't exist
     * in the pool, it will be moved into the pool rather than copied.
     * 
     * @param str The string to intern (will be moved if not in pool)
     * @return const std::string& Reference to the interned string
     * 
     * ## Example:
     * ```cpp
     * StringInterner interner;
     * std::string temp = "temporary";
     * const std::string& interned = interner.intern(std::move(temp));
     * // temp is now empty, interned contains "temporary"
     * ```
     * 
     * ## Performance:
     * - Time: O(1) average case
     * - Space: O(1) if exists, O(k) with move semantics if new
     */
    const std::string& intern(std::string&& str);

    /**
     * @brief Intern a C-style string
     * 
     * Convenience method for interning C-style strings without explicit
     * std::string construction at the call site.
     * 
     * @param str The null-terminated C string to intern
     * @return const std::string& Reference to the interned string
     * 
     * ## Example:
     * ```cpp
     * StringInterner interner;
     * const std::string& symbol = interner.intern("main");
     * ```
     */
    const std::string& intern(const char* str);

    /**
     * @brief Get the number of unique strings in the pool
     * 
     * @return size_t Number of unique strings currently interned
     * 
     * ## Usage:
     * Useful for memory usage analysis and debugging. Can be used
     * with --debug output to show interning effectiveness.
     */
    size_t getPoolSize() const { return pool_.size(); }

    /**
     * @brief Get estimated memory usage of the string pool
     * 
     * Calculates the approximate memory usage including:
     * - Hash set overhead (nodes, buckets)
     * - String storage (character data)
     * - Internal std::string objects
     * 
     * @return size_t Estimated memory usage in bytes
     * 
     * ## Note:
     * This is an approximation as exact memory usage depends on:
     * - Hash set implementation details
     * - Memory allocator behavior
     * - String storage optimization (SSO - Small String Optimization)
     */
    size_t getEstimatedMemoryUsage() const;

    /**
     * @brief Reserve capacity for expected number of strings
     *
     * Pre-allocates hash table buckets for improved performance when
     * processing large numbers of strings. Reduces hash table rehashing.
     *
     * @param capacity Expected number of unique strings
     */
    void reserve(size_t capacity) { pool_.reserve(capacity); }

    /**
     * @brief Clear the string pool
     *
     * Removes all interned strings from the pool. Any existing references
     * to interned strings become invalid after this call.
     *
     * ## Warning:
     * This invalidates all previously returned references. Only call
     * when you're certain no code is holding references to interned strings.
     */
    void clear() { pool_.clear(); }

    /**
     * @brief Check if a string is already interned
     * 
     * @param str The string to check
     * @return true if the string is in the pool, false otherwise
     * 
     * ## Usage:
     * Useful for testing and debugging. Not typically needed in production
     * code since intern() handles both cases efficiently.
     */
    bool contains(const std::string& str) const;

    /**
     * @brief Get memory usage statistics
     * 
     * Returns detailed statistics about the string pool for analysis
     * and debugging purposes.
     * 
     * @return MemoryStats Statistics about pool usage
     */
    struct MemoryStats {
        size_t unique_strings;     ///< Number of unique strings
        size_t total_characters;   ///< Total character count across all strings
        size_t estimated_bytes;    ///< Estimated total memory usage
        double average_length;     ///< Average string length
        double load_factor;        ///< Hash set load factor
    };

    MemoryStats getStats() const;

private:
    /**
     * @brief Hash set storing unique strings
     * 
     * Uses std::unordered_set for O(1) average case lookup and insertion.
     * The set stores the actual string objects, and we return const references
     * to these objects, ensuring they remain valid for the lifetime of the
     * StringInterner instance.
     */
    std::unordered_set<std::string> pool_;
};