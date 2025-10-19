/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "ElfStructures.h"

/**
 * @file ThreadSafeContainers.h
 * @brief Thread-safe containers for Phase 2 multi-threading support
 *
 * This file provides thread-safe versions of key data structures used in
 * ELF analysis, enabling concurrent processing while maintaining data integrity.
 *
 * Key Features:
 * - Read-write locks for optimal read performance
 * - Lock-free operations where possible
 * - Minimal contention design
 * - Memory-efficient string handling
 *
 * @author ELF Symbol Reader Development Team
 * @date 2025 - Phase 2 Multi-threading Implementation
 */

/**
 * @brief Thread-safe registry for type information
 *
 * Provides concurrent access to type information with multiple readers
 * and single writers. Uses shared_mutex for optimal read performance
 * since type information is read much more frequently than written.
 *
 * Performance Characteristics:
 * - Concurrent reads: No contention (multiple threads can read simultaneously)
 * - Single write: Blocks all readers during write (minimal impact, writes are rare)
 * - Memory overhead: ~16 bytes for mutex + map overhead
 */
class ThreadSafeTypeRegistry {
private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, TypeInfo> types_;

    // Statistics for performance monitoring
    mutable std::atomic<uint64_t> read_count_{0};
    mutable std::atomic<uint64_t> write_count_{0};

public:
    /**
     * @brief Get type information by name (thread-safe read)
     *
     * @param name Type name to lookup
     * @return Optional TypeInfo if found, empty optional if not found
     */
    std::optional<TypeInfo> getType(const std::string& name) const {
        read_count_.fetch_add(1, std::memory_order_relaxed);

        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = types_.find(name);
        if (it != types_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * @brief Check if a type exists (thread-safe read)
     *
     * @param name Type name to check
     * @return true if type exists, false otherwise
     */
    bool hasType(const std::string& name) const {
        read_count_.fetch_add(1, std::memory_order_relaxed);

        std::shared_lock<std::shared_mutex> lock(mutex_);
        return types_.find(name) != types_.end();
    }

    /**
     * @brief Add or update type information (thread-safe write)
     *
     * @param name Type name
     * @param type_info Type information to store
     */
    void addType(const std::string& name, const TypeInfo& type_info) {
        write_count_.fetch_add(1, std::memory_order_relaxed);

        std::unique_lock<std::shared_mutex> lock(mutex_);
        types_[name] = type_info;
    }

    /**
     * @brief Get all type names (thread-safe read)
     *
     * @return Vector of all registered type names
     */
    std::vector<std::string> getAllTypeNames() const {
        read_count_.fetch_add(1, std::memory_order_relaxed);

        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> names;
        names.reserve(types_.size());

        for (const auto& pair : types_) {
            names.push_back(pair.first);
        }
        return names;
    }

    /**
     * @brief Get the number of registered types (thread-safe read)
     *
     * @return Number of types in the registry
     */
    size_t size() const {
        read_count_.fetch_add(1, std::memory_order_relaxed);

        std::shared_lock<std::shared_mutex> lock(mutex_);
        return types_.size();
    }

    /**
     * @brief Clear all types (thread-safe write)
     */
    void clear() {
        write_count_.fetch_add(1, std::memory_order_relaxed);

        std::unique_lock<std::shared_mutex> lock(mutex_);
        types_.clear();
    }

    /**
     * @brief Get performance statistics
     *
     * @return Pair of (read_count, write_count)
     */
    std::pair<uint64_t, uint64_t> getStats() const {
        return {read_count_.load(std::memory_order_relaxed),
                write_count_.load(std::memory_order_relaxed)};
    }

    /**
     * @brief Reset statistics counters
     */
    void resetStats() {
        read_count_.store(0, std::memory_order_relaxed);
        write_count_.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Thread-safe string interner for memory optimization
 *
 * Provides concurrent string interning to eliminate duplicate string storage.
 * Uses shared_mutex for optimal read performance with atomic reference counting.
 *
 * Performance Characteristics:
 * - Concurrent reads: No contention for existing strings
 * - Concurrent writes: Minimal contention when adding new strings
 * - Memory efficiency: Eliminates duplicate string storage
 */
class ThreadSafeStringInterner {
private:
    struct StringEntry {
        std::string string;
        std::atomic<uint32_t> ref_count{1};

        StringEntry(const std::string& s) : string(s) {}
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string_view, std::unique_ptr<StringEntry>> string_pool_;

    // Statistics
    mutable std::atomic<uint64_t> intern_count_{0};
    mutable std::atomic<uint64_t> lookup_count_{0};
    mutable std::atomic<uint64_t> cache_hits_{0};

public:
    /**
     * @brief Intern a string (thread-safe)
     *
     * Returns a string_view that points to an internal string storage.
     * The string is guaranteed to remain valid as long as this interner exists.
     *
     * @param str String to intern
     * @return string_view pointing to internal storage
     */
    std::string_view intern(const std::string& str) {
        intern_count_.fetch_add(1, std::memory_order_relaxed);

        // Fast path: try read-only lookup first
        {
            std::shared_lock<std::shared_mutex> lock(mutex_);
            auto it = string_pool_.find(str);
            if (it != string_pool_.end()) {
                it->second->ref_count.fetch_add(1, std::memory_order_relaxed);
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                return it->first;
            }
        }

        // Slow path: need to add new string
        {
            std::unique_lock<std::shared_mutex> lock(mutex_);

            // Double-check in case another thread added it while we waited
            auto it = string_pool_.find(str);
            if (it != string_pool_.end()) {
                it->second->ref_count.fetch_add(1, std::memory_order_relaxed);
                return it->first;
            }

            // Add new string
            auto entry = std::make_unique<StringEntry>(str);
            std::string_view view(entry->string);
            string_pool_[view] = std::move(entry);
            return view;
        }
    }

    /**
     * @brief Get the number of interned strings
     *
     * @return Number of unique strings in the pool
     */
    size_t size() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return string_pool_.size();
    }

    /**
     * @brief Get total memory usage in bytes
     *
     * @return Total bytes used for string storage
     */
    size_t getMemoryUsage() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        size_t total = 0;
        for (const auto& pair : string_pool_) {
            total += pair.second->string.size() + sizeof(StringEntry);
        }
        return total + string_pool_.size() * sizeof(std::string_view);
    }

    /**
     * @brief Get performance statistics
     *
     * @return Tuple of (intern_count, lookup_count, cache_hits)
     */
    std::tuple<uint64_t, uint64_t, uint64_t> getStats() const {
        return {intern_count_.load(std::memory_order_relaxed),
                lookup_count_.load(std::memory_order_relaxed),
                cache_hits_.load(std::memory_order_relaxed)};
    }

    /**
     * @brief Reset statistics counters
     */
    void resetStats() {
        intern_count_.store(0, std::memory_order_relaxed);
        lookup_count_.store(0, std::memory_order_relaxed);
        cache_hits_.store(0, std::memory_order_relaxed);
    }

    /**
     * @brief Get cache hit ratio
     *
     * @return Cache hit percentage (0-100)
     */
    double getCacheHitRatio() const {
        uint64_t total = intern_count_.load(std::memory_order_relaxed);
        if (total == 0)
            return 0.0;
        return (static_cast<double>(cache_hits_.load(std::memory_order_relaxed)) / total) * 100.0;
    }
};