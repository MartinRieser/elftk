/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "StringInterner.h"
#include <algorithm>
#include <numeric>

// ============================================================================
// StringInterner Implementation
// ============================================================================

const std::string& StringInterner::intern(const std::string& str) {
    // Try to insert the string into the set
    auto [iterator, inserted] = pool_.insert(str);
    
    // Return reference to the string in the set (either newly inserted or existing)
    return *iterator;
}

const std::string& StringInterner::intern(std::string&& str) {
    // Try to insert the string with move semantics
    auto [iterator, inserted] = pool_.insert(std::move(str));
    
    // Return reference to the string in the set
    return *iterator;
}

const std::string& StringInterner::intern(const char* str) {
    // Construct string and insert
    auto [iterator, inserted] = pool_.emplace(str);
    
    // Return reference to the string in the set
    return *iterator;
}

size_t StringInterner::getEstimatedMemoryUsage() const {
    size_t total_size = 0;
    
    // Calculate size of all strings (character data)
    for (const auto& str : pool_) {
        total_size += str.capacity(); // Use capacity to include potential over-allocation
    }
    
    // Add hash set overhead estimation
    // Typical overhead: 24-32 bytes per node + bucket array
    size_t hash_set_overhead = pool_.size() * 32; // Conservative estimate for node overhead
    
    // Add bucket array size (usually prime number close to size)
    size_t bucket_count = pool_.bucket_count();
    size_t bucket_array_size = bucket_count * sizeof(void*); // Pointer to first node in each bucket
    
    total_size += hash_set_overhead + bucket_array_size;
    
    return total_size;
}

bool StringInterner::contains(const std::string& str) const {
    return pool_.find(str) != pool_.end();
}

StringInterner::MemoryStats StringInterner::getStats() const {
    MemoryStats stats;
    
    stats.unique_strings = pool_.size();
    
    if (stats.unique_strings == 0) {
        stats.total_characters = 0;
        stats.estimated_bytes = 0;
        stats.average_length = 0.0;
        stats.load_factor = 0.0;
        return stats;
    }
    
    // Calculate total characters
    stats.total_characters = std::accumulate(
        pool_.begin(), 
        pool_.end(), 
        size_t(0),
        [](size_t total, const std::string& str) {
            return total + str.length();
        }
    );
    
    stats.estimated_bytes = getEstimatedMemoryUsage();
    stats.average_length = static_cast<double>(stats.total_characters) / stats.unique_strings;
    stats.load_factor = pool_.load_factor();
    
    return stats;
}