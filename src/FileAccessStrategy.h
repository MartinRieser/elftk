/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <chrono>
#include <limits>

/**
 * @file FileAccessStrategy.h
 * @brief File access strategy interface for ELF binary file handling
 *
 * This file defines the strategy pattern for accessing ELF binary files,
 * allowing for different file access methods (in-memory vs memory-mapped)
 * depending on file size and performance requirements.
 *
 * Key Features:
 * - Automatic strategy selection based on file size
 * - Cross-platform memory mapping support
 * - Performance metrics and validation
 * - Robust error handling with platform-specific details
 * - Thread-safe implementation
 *
 * @author ELF Symbol Reader Project
 * @date 2025
 */

// Forward declarations
class FileAccessStrategy;

/**
 * @brief Configuration for file access strategies
 */
struct FileAccessConfig {
    static constexpr size_t DEFAULT_MMAP_THRESHOLD = 100 * 1024 * 1024;           ///< 100MB default threshold
    static constexpr size_t DEFAULT_MAX_IN_MEMORY_SIZE = 2ULL * 1024 * 1024 * 1024; ///< 2GB max in-memory

    size_t mmap_threshold = DEFAULT_MMAP_THRESHOLD;  ///< Size threshold for memory mapping
    bool force_memory_mapping = false;              ///< Force memory mapping regardless of size
    bool force_in_memory = false;                   ///< Force in-memory loading regardless of size
    bool enable_fallback = true;                    ///< Enable fallback between strategies
    size_t max_in_memory_size = DEFAULT_MAX_IN_MEMORY_SIZE; ///< Maximum size for in-memory loading
};

/**
 * @brief Performance metrics for file access operations
 */
struct AccessMetrics {
    std::chrono::milliseconds load_time{0};         ///< Time taken to load/map the file
    size_t memory_usage_bytes = 0;                  ///< Actual memory usage
    bool fallback_used = false;                     ///< Whether fallback strategy was used
    std::string strategy_used;                      ///< Name of strategy actually used
};

/**
 * @brief Custom exception for file access errors
 */
class FileAccessException : public std::runtime_error {
public:
    explicit FileAccessException(const std::string& message) : std::runtime_error(message) {}
};

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
 * ## Usage Examples:
 * @code
 * // Basic usage with defaults
 * auto strategy = FileAccessStrategy::create("firmware.elf");
 * const uint8_t* data = strategy->data();
 * size_t size = strategy->size();
 *
 * // Advanced usage with configuration
 * FileAccessConfig config;
 * config.mmap_threshold = 50 * 1024 * 1024; // 50MB threshold
 * config.enable_fallback = true;
 * auto strategy = FileAccessStrategy::create("large_firmware.elf", config);
 *
 * // Get performance metrics
 * AccessMetrics metrics = strategy->getMetrics();
 * std::cout << "Load time: " << metrics.load_time.count() << "ms\n";
 * @endcode
 */
class FileAccessStrategy {
public:
    // Configuration constants
    static constexpr size_t BYTES_PER_MB = 1024 * 1024;                      ///< Bytes per megabyte
    static constexpr size_t BYTES_PER_GB = 1024ULL * 1024 * 1024;            ///< Bytes per gigabyte

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
     * @brief Check if the file access is valid and ready
     * @return true if file is accessible, false otherwise
     */
    virtual bool isValid() const = 0;

    /**
     * @brief Get the last error message if any
     * @return Error message string, empty if no error
     */
    virtual std::string getLastError() const = 0;

    /**
     * @brief Get performance metrics for this access strategy
     * @return AccessMetrics structure with timing and usage information
     */
    virtual AccessMetrics getMetrics() const = 0;

    /**
     * @brief Get performance metrics as formatted string (legacy)
     * @return String containing performance information for backward compatibility
     */
    virtual std::string getPerformanceMetrics() const = 0;

    /**
     * @brief Factory method to create appropriate strategy based on configuration
     * @param filename Path to the ELF file
     * @param config Configuration options for file access
     * @return Unique pointer to the created strategy
     * @throws FileAccessException if file cannot be accessed
     */
    static std::unique_ptr<FileAccessStrategy> create(
        const std::string& filename,
        const FileAccessConfig& config = {}
    );

    /**
     * @brief Legacy factory method with simple threshold
     * @param filename Path to the ELF file
     * @param mmap_threshold Size threshold above which to use memory mapping
     * @return Unique pointer to the created strategy
     * @throws FileAccessException if file cannot be accessed
     * @deprecated Use create(filename, FileAccessConfig) instead
     */
    static std::unique_ptr<FileAccessStrategy> create(
        const std::string& filename,
        size_t mmap_threshold
    );

    /**
     * @brief Legacy factory method with performance monitoring
     * @param filename Path to the ELF file
     * @param mmap_threshold Size threshold above which to use memory mapping
     * @param enable_performance_monitoring Enable performance metrics collection
     * @return Unique pointer to the created strategy
     * @throws FileAccessException if file cannot be accessed
     * @deprecated Use create(filename, FileAccessConfig) instead
     */
    static std::unique_ptr<FileAccessStrategy> create(
        const std::string& filename,
        size_t mmap_threshold,
        bool enable_performance_monitoring
    );

    /**
     * @brief Get file size without opening the file
     * @param filename Path to the file
     * @return File size in bytes
     * @throws FileAccessException if file cannot be accessed
     */
    static size_t getFileSize(const std::string& filename);

    /**
     * @brief Validate file path and accessibility
     * @param filename Path to validate
     * @throws FileAccessException if path is invalid or inaccessible
     */
    static void validateFilePath(const std::string& filename);

    /**
     * @brief Utility to get platform-specific error message
     * @return Platform-specific error description
     */
    static std::string getSystemErrorMessage();

    /**
     * @brief Check if file size exceeds platform limits
     * @param file_size Size to check
     * @param operation Description of operation for error message
     * @throws FileAccessException if size exceeds limits
     */
    static void validateFileSize(size_t file_size, const std::string& operation);

protected:
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
 * - Files smaller than DEFAULT_MMAP_THRESHOLD
 * - Frequent random access patterns
 * - When memory usage is not a primary concern
 * - Systems where memory mapping is unavailable
 *
 * ## Memory usage: File size + vector overhead (~25% typically)
 * ## Performance: O(1) access, O(n) load time
 */
class InMemoryFile : public FileAccessStrategy {
public:
    /**
     * @brief Construct and load file into memory
     * @param filename Path to the ELF file to load
     * @param config Configuration options
     * @throws FileAccessException if file cannot be read
     */
    explicit InMemoryFile(const std::string& filename, const FileAccessConfig& config = {});

    /**
     * @brief Legacy constructor with performance monitoring flag
     * @param filename Path to the ELF file to load
     * @param enable_performance_monitoring Enable performance metrics collection
     * @throws FileAccessException if file cannot be read
     * @deprecated Use InMemoryFile(filename, FileAccessConfig) instead
     */
    explicit InMemoryFile(const std::string& filename, bool enable_performance_monitoring);

    const uint8_t* data() const override { return data_.data(); }
    size_t size() const override { return data_.size(); }
    bool isMemoryMapped() const override { return false; }
    std::string getStrategyName() const override { return "In-memory"; }
    bool isValid() const override { return !data_.empty() && last_error_.empty(); }
    std::string getLastError() const override { return last_error_; }
    AccessMetrics getMetrics() const override { return metrics_; }
    std::string getPerformanceMetrics() const override;

private:
    std::vector<uint8_t> data_;
    std::string last_error_;
    AccessMetrics metrics_;

    /**
     * @brief Load file data with performance tracking
     * @param filename Path to the file
     * @param max_size Maximum allowed file size
     */
    void loadFile(const std::string& filename, size_t max_size);
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
 * - Large files (>DEFAULT_MMAP_THRESHOLD)
 * - Sequential or sparse access patterns
 * - Memory-constrained environments
 * - Read-only access patterns
 *
 * ## Memory usage: Virtual memory only (OS handles physical pages)
 * ## Performance: O(1) access after mapping, lazy loading
 *
 * ## Platform support:
 * - Linux/macOS: Uses mmap() system call with PROT_READ/MAP_PRIVATE
 * - Windows: Uses CreateFileMapping()/MapViewOfFile() with PAGE_READONLY
 *
 * ## Error handling:
 * - Provides detailed platform-specific error messages
 * - Automatic cleanup on destruction or move operations
 * - Validation of file size limits for platform compatibility
 */
class MemoryMappedFile : public FileAccessStrategy {
public:
    /**
     * @brief Construct and memory-map the file
     * @param filename Path to the ELF file to map
     * @param config Configuration options
     * @throws FileAccessException if file cannot be mapped
     */
    explicit MemoryMappedFile(const std::string& filename, const FileAccessConfig& config = {});

    /**
     * @brief Legacy constructor with performance monitoring flag
     * @param filename Path to the ELF file to map
     * @param enable_performance_monitoring Enable performance metrics collection
     * @throws FileAccessException if file cannot be mapped
     * @deprecated Use MemoryMappedFile(filename, FileAccessConfig) instead
     */
    explicit MemoryMappedFile(const std::string& filename, bool enable_performance_monitoring);

    /**
     * @brief Destructor - unmaps the file
     */
    ~MemoryMappedFile() override;

    // Disable copy constructor and assignment operator
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;

    // Enable move constructor and assignment operator
    MemoryMappedFile(MemoryMappedFile&& other) noexcept(false);
    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept(false);

    const uint8_t* data() const override { return mapped_data_; }
    size_t size() const override { return file_size_; }
    bool isMemoryMapped() const override { return true; }
    std::string getStrategyName() const override { return "Memory-mapped"; }
    bool isValid() const override { return mapped_data_ != nullptr && file_size_ > 0 && last_error_.empty(); }
    std::string getLastError() const override { return last_error_; }
    AccessMetrics getMetrics() const override { return metrics_; }
    std::string getPerformanceMetrics() const override;

private:
    void cleanup();
    void mapFile(const std::string& filename);

    const uint8_t* mapped_data_;
    size_t file_size_;
    std::string last_error_;
    AccessMetrics metrics_;

#ifdef _WIN32
    void* file_handle_;
    void* mapping_handle_;

    /**
     * @brief Get Windows-specific error message
     * @param error_code Windows error code
     * @return Formatted error message
     */
    static std::string getWindowsErrorString(unsigned long error_code);
#else
    int file_descriptor_;

    /**
     * @brief Get Unix-specific error message
     * @param errno_code Error number from errno
     * @return Formatted error message
     */
    static std::string getUnixErrorString(int errno_code);
#endif
};