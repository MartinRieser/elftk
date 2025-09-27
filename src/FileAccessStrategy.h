/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

/**
 * @file FileAccessStrategy.h
 * @brief File access strategy interface for ELF binary file handling
 * 
 * This file defines the strategy pattern for accessing ELF binary files,
 * allowing for different file access methods (in-memory vs memory-mapped)
 * depending on file size and performance requirements.
 * 
 * @author ELF Symbol Reader Project
 * @date 2025
 * @version 2.2.0
 */

/**
 * @class FileAccessStrategy
 * @brief Abstract base class for different file access strategies
 * 
 * This interface allows ElfReader to transparently handle files using different
 * access methods. Small files can be loaded entirely into memory for optimal
 * performance, while large files can use memory mapping to reduce memory usage.
 * 
 * ## Strategy Pattern Benefits:
 * - Transparent file access regardless of size
 * - Automatic optimization based on file characteristics
 * - Easy testing and mocking capabilities
 * - Future extensibility for additional access methods
 * 
 * ## Usage Example:
 * ```cpp
 * auto strategy = FileAccessStrategy::create("firmware.elf", config);
 * const uint8_t* data = strategy->data();
 * size_t size = strategy->size();
 * ```
 */
class FileAccessStrategy {
public:
    /**
     * @brief Virtual destructor for proper cleanup
     */
    virtual ~FileAccessStrategy() = default;

    /**
     * @brief Get pointer to file data
     * @return Pointer to the beginning of file data
     * @note The returned pointer remains valid for the lifetime of this object
     */
    virtual const uint8_t* data() const = 0;

    /**
     * @brief Get file size in bytes
     * @return File size in bytes
     */
    virtual size_t size() const = 0;

    /**
     * @brief Check if this strategy uses memory mapping
     * @return true if memory-mapped, false if in-memory
     * @note Useful for debugging and performance analysis
     */
    virtual bool isMemoryMapped() const = 0;

    /**
     * @brief Get human-readable description of the strategy
     * @return String describing the access method (e.g., "Memory-mapped", "In-memory")
     */
    virtual std::string getStrategyName() const = 0;

    /**
     * @brief Get performance metrics if monitoring is enabled
     * @return String containing performance information, empty if monitoring disabled
     */
    virtual std::string getPerformanceMetrics() const = 0;

    /**
     * @brief Factory method to create appropriate strategy based on file size
     * @param filename Path to the ELF file
     * @param mmap_threshold Size threshold above which to use memory mapping (default: 100MB)
     * @param enable_performance_monitoring Enable performance metrics collection (default: false)
     * @return Unique pointer to the created strategy
     * @throws std::runtime_error if file cannot be accessed
     */
    static std::unique_ptr<FileAccessStrategy> create(
        const std::string& filename,
        size_t mmap_threshold = 100 * 1024 * 1024,  // 100MB default
        bool enable_performance_monitoring = false
    );

    /**
     * @brief Get file size without opening the file
     * @param filename Path to the file
     * @return File size in bytes
     * @throws std::runtime_error if file cannot be accessed
     */
    static size_t getFileSize(const std::string& filename);
};

/**
 * @class InMemoryFile
 * @brief Strategy that loads entire file into memory
 * 
 * This strategy loads the complete file content into a std::vector<uint8_t>.
 * It provides the fastest access for small to medium-sized files but uses
 * memory proportional to file size.
 * 
 * ## Best for:
 * - Files smaller than 100MB
 * - Frequent random access patterns
 * - When memory usage is not a primary concern
 * 
 * ## Memory usage: File size + overhead
 */
class InMemoryFile : public FileAccessStrategy {
public:
    /**
     * @brief Construct and load file into memory
     * @param filename Path to the ELF file to load
     * @param enable_performance_monitoring Enable performance metrics collection
     * @throws std::runtime_error if file cannot be read
     */
    explicit InMemoryFile(const std::string& filename, bool enable_performance_monitoring = false);

    const uint8_t* data() const override { return data_.data(); }
    size_t size() const override { return data_.size(); }
    bool isMemoryMapped() const override { return false; }
    std::string getStrategyName() const override { return "In-memory"; }
    std::string getPerformanceMetrics() const override;

private:
    std::vector<uint8_t> data_;
    bool performance_monitoring_enabled_;
    double load_time_ms_;
};

/**
 * @class MemoryMappedFile
 * @brief Strategy that uses memory mapping for file access
 * 
 * This strategy uses the operating system's memory mapping capabilities
 * to access file content without loading it entirely into memory. The OS
 * handles paging and caching automatically.
 * 
 * ## Best for:
 * - Large files (>100MB)
 * - Sequential or sparse access patterns
 * - Memory-constrained environments
 * 
 * ## Memory usage: Minimal (OS handles paging)
 * 
 * ## Platform support:
 * - Linux/macOS: Uses mmap() system call
 * - Windows: Uses CreateFileMapping()/MapViewOfFile()
 */
class MemoryMappedFile : public FileAccessStrategy {
public:
    /**
     * @brief Construct and memory-map the file
     * @param filename Path to the ELF file to map
     * @param enable_performance_monitoring Enable performance metrics collection
     * @throws std::runtime_error if file cannot be mapped
     */
    explicit MemoryMappedFile(const std::string& filename, bool enable_performance_monitoring = false);

    /**
     * @brief Destructor - unmaps the file
     */
    ~MemoryMappedFile() override;

    // Disable copy constructor and assignment operator
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;

    // Enable move constructor and assignment operator
    MemoryMappedFile(MemoryMappedFile&& other) noexcept;
    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept;

    const uint8_t* data() const override { return mapped_data_; }
    size_t size() const override { return file_size_; }
    bool isMemoryMapped() const override { return true; }
    std::string getStrategyName() const override { return "Memory-mapped"; }
    std::string getPerformanceMetrics() const override;

private:
    void cleanup();

    const uint8_t* mapped_data_;
    size_t file_size_;
    bool performance_monitoring_enabled_;
    double load_time_ms_;

#ifdef _WIN32
    void* file_handle_;
    void* mapping_handle_;
#else
    int file_descriptor_;
#endif
};