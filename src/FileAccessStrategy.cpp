/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "FileAccessStrategy.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

// Platform-specific includes
#ifdef _WIN32
    #include <fcntl.h>
    #include <io.h>
    #include <windows.h>
#else
    #include <errno.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

/**
 * @brief Utility class for platform-specific error handling
 */
class FileAccessErrors {
public:
    static std::string cannotOpen(const std::string& filename, const std::string& reason = "") {
        return "Cannot open file '" + filename + "'" + (reason.empty() ? "" : ": " + reason);
    }

    static std::string cannotGetSize(const std::string& filename) {
        return "Cannot determine size of file '" + filename + "'";
    }

    static std::string cannotMap(const std::string& filename, const std::string& operation) {
        return "Cannot " + operation + " file '" + filename + "'";
    }

    static std::string fileTooLarge(const std::string& filename, size_t size, size_t limit) {
        return "File '" + filename + "' (" + std::to_string(size) + " bytes) exceeds limit of " +
               std::to_string(limit) + " bytes";
    }
};

// ============================================================================
// FileAccessStrategy Implementation
// ============================================================================

std::unique_ptr<FileAccessStrategy> FileAccessStrategy::create(const std::string& filename,
                                                               const FileAccessConfig& config) {
    try {
        validateFilePath(filename);

        size_t file_size = getFileSize(filename);
        validateFileSize(file_size, "access");

        // Validate non-zero file size
        if (file_size == 0) {
            throw FileAccessException("Cannot process zero-sized file: " + filename);
        }

        // Check forced strategies first
        if (config.force_memory_mapping) {
            return std::make_unique<MemoryMappedFile>(filename, config);
        }

        if (config.force_in_memory) {
            if (file_size > config.max_in_memory_size) {
                throw FileAccessException(
                    FileAccessErrors::fileTooLarge(filename, file_size, config.max_in_memory_size));
            }
            return std::make_unique<InMemoryFile>(filename, config);
        }

        // Automatic selection based on size
        if (file_size >= config.mmap_threshold) {
            try {
                // Try memory mapping for large files
                return std::make_unique<MemoryMappedFile>(filename, config);
            } catch (const FileAccessException& e) {
                if (!config.enable_fallback) {
                    throw;  // Re-throw if fallback is disabled
                }

                // Check if file is too large for in-memory loading
                if (file_size > config.max_in_memory_size) {
                    throw FileAccessException(
                        "Memory mapping failed and file too large for in-memory loading: " +
                        std::string(e.what()));
                }

                std::cerr << "Warning: Memory mapping failed (" << e.what()
                          << "), falling back to in-memory loading\n";
                return std::make_unique<InMemoryFile>(filename, config);
            }
        } else {
            // Use in-memory for smaller files
            return std::make_unique<InMemoryFile>(filename, config);
        }
    } catch (const FileAccessException&) {
        throw;  // Re-throw FileAccessException
    } catch (const std::exception& e) {
        throw FileAccessException("Failed to create file access strategy: " +
                                  std::string(e.what()));
    }
}

// Legacy overload for backward compatibility
std::unique_ptr<FileAccessStrategy> FileAccessStrategy::create(const std::string& filename,
                                                               size_t mmap_threshold) {
    FileAccessConfig config;
    config.mmap_threshold = mmap_threshold;
    return create(filename, config);
}

// Legacy overload with performance monitoring
std::unique_ptr<FileAccessStrategy> FileAccessStrategy::create(const std::string& filename,
                                                               size_t mmap_threshold,
                                                               bool enable_performance_monitoring) {
    FileAccessConfig config;
    config.mmap_threshold = mmap_threshold;
    // Performance monitoring is now always enabled via AccessMetrics
    (void)enable_performance_monitoring;  // Suppress unused parameter warning
    return create(filename, config);
}

size_t FileAccessStrategy::getFileSize(const std::string& filename) {
    try {
        std::error_code ec;
        auto file_size = std::filesystem::file_size(filename, ec);
        if (ec) {
            throw FileAccessException(FileAccessErrors::cannotGetSize(filename) + ": " +
                                      ec.message());
        }

        // Check for potential overflow
        if (file_size > std::numeric_limits<size_t>::max()) {
            throw FileAccessException("File too large for platform: " + filename + " (" +
                                      std::to_string(file_size) + " bytes)");
        }

        return static_cast<size_t>(file_size);
    } catch (const std::filesystem::filesystem_error& e) {
        throw FileAccessException(FileAccessErrors::cannotGetSize(filename) + ": " + e.what());
    }
}

void FileAccessStrategy::validateFilePath(const std::string& filename) {
    if (filename.empty()) {
        throw FileAccessException("Filename cannot be empty");
    }

    try {
        std::error_code ec;
        if (!std::filesystem::exists(filename, ec)) {
            if (ec) {
                throw FileAccessException("Cannot check file existence '" + filename +
                                          "': " + ec.message());
            }
            throw FileAccessException("File does not exist: " + filename);
        }

        if (!std::filesystem::is_regular_file(filename, ec)) {
            if (ec) {
                throw FileAccessException("Cannot check file type '" + filename +
                                          "': " + ec.message());
            }
            throw FileAccessException("Path is not a regular file: " + filename);
        }
    } catch (const std::filesystem::filesystem_error& e) {
        throw FileAccessException("File validation failed for '" + filename + "': " + e.what());
    }
}

std::string FileAccessStrategy::getSystemErrorMessage() {
#ifdef _WIN32
    DWORD error = GetLastError();
    if (error == 0) {
        return "No error";
    }

    LPSTR messageBuffer = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   nullptr,
                   error,
                   0,
                   (LPSTR)&messageBuffer,
                   0,
                   nullptr);

    std::string message(messageBuffer);
    LocalFree(messageBuffer);

    // Remove trailing newline if present
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
        if (!message.empty() && message.back() == '\r') {
            message.pop_back();
        }
    }

    return message;
#else
    // Use thread-safe strerror_r on POSIX systems
    char buffer[256];
    return strerror_r(errno, buffer, sizeof(buffer)) == 0 ? std::string(buffer) : "Unknown error";
#endif
}

void FileAccessStrategy::validateFileSize(size_t file_size, const std::string& operation) {
    // Check against platform size_t limits
    constexpr size_t MAX_SAFE_SIZE = std::numeric_limits<size_t>::max() / 2;  // Conservative limit

    if (file_size > MAX_SAFE_SIZE) {
        throw FileAccessException(
            "File too large for " + operation + ": " + std::to_string(file_size) +
            " bytes (platform limit: " + std::to_string(MAX_SAFE_SIZE) + " bytes)");
    }
}

// ============================================================================
// InMemoryFile Implementation
// ============================================================================

InMemoryFile::InMemoryFile(const std::string& filename, const FileAccessConfig& config) {
    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        loadFile(filename, config.max_in_memory_size);

        auto end_time = std::chrono::high_resolution_clock::now();
        metrics_.load_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_.memory_usage_bytes = data_.capacity() * sizeof(uint8_t);
        metrics_.strategy_used = "In-memory";
        metrics_.fallback_used = false;

    } catch (const std::exception& e) {
        last_error_ = e.what();
        throw FileAccessException("Failed to load file into memory: " + std::string(e.what()));
    }
}

// Legacy constructor for backward compatibility
InMemoryFile::InMemoryFile(const std::string& filename, bool enable_performance_monitoring) {
    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        FileAccessConfig config;
        loadFile(filename, config.max_in_memory_size);

        auto end_time = std::chrono::high_resolution_clock::now();
        metrics_.load_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_.memory_usage_bytes = data_.capacity() * sizeof(uint8_t);
        metrics_.strategy_used = "In-memory";
        metrics_.fallback_used = false;

        // Suppress unused parameter warning
        (void)enable_performance_monitoring;

    } catch (const std::exception& e) {
        last_error_ = e.what();
        throw FileAccessException("Failed to load file into memory: " + std::string(e.what()));
    }
}

void InMemoryFile::loadFile(const std::string& filename, size_t max_size) {
    size_t file_size = FileAccessStrategy::getFileSize(filename);

    if (file_size > max_size) {
        throw FileAccessException(FileAccessErrors::fileTooLarge(filename, file_size, max_size));
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw FileAccessException(
            FileAccessErrors::cannotOpen(filename, FileAccessStrategy::getSystemErrorMessage()));
    }

    // Pre-allocate memory efficiently
    data_.reserve(file_size);
    data_.resize(file_size);

    // Read file in chunks for better error handling
    constexpr size_t CHUNK_SIZE = static_cast<size_t>(1024) * 1024;  // 1MB chunks
    size_t bytes_read = 0;

    while (bytes_read < file_size) {
        size_t chunk_size = std::min(CHUNK_SIZE, file_size - bytes_read);
        file.read(reinterpret_cast<char*>(data_.data() + bytes_read),
                  static_cast<std::streamsize>(chunk_size));

        if (file.fail() && !file.eof()) {
            throw FileAccessException("Failed to read file '" + filename + "' at offset " +
                                      std::to_string(bytes_read));
        }

        bytes_read += file.gcount();

        if (file.eof()) {
            break;
        }
    }

    // Verify we read the expected amount
    if (bytes_read != file_size) {
        throw FileAccessException("File size mismatch for '" + filename + "': expected " +
                                  std::to_string(file_size) + " bytes, read " +
                                  std::to_string(bytes_read) + " bytes");
    }

    data_.shrink_to_fit();  // Optimize memory usage
}

std::string InMemoryFile::getPerformanceMetrics() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "In-memory strategy: " << (static_cast<double>(data_.size()) / 1024.0 / 1024.0)
        << " MB loaded in " << metrics_.load_time.count() << " ms";
    return oss.str();
}

// ============================================================================
// MemoryMappedFile Implementation
// ============================================================================

MemoryMappedFile::MemoryMappedFile(const std::string& filename, const FileAccessConfig& config)
    : mapped_data_(nullptr),
      file_size_(0)
#ifdef _WIN32
      ,
      file_handle_(INVALID_HANDLE_VALUE),
      mapping_handle_(nullptr)
#else
      ,
      file_descriptor_(-1)
#endif
{
    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        mapFile(filename);

        auto end_time = std::chrono::high_resolution_clock::now();
        metrics_.load_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_.memory_usage_bytes = 0;  // Virtual memory only
        metrics_.strategy_used = "Memory-mapped";
        metrics_.fallback_used = false;

        // Unused parameter warning suppression
        (void)config;

    } catch (const std::exception& e) {
        last_error_ = e.what();
        cleanup();  // Ensure cleanup on failure
        throw FileAccessException("Failed to memory-map file: " + std::string(e.what()));
    }
}

// Legacy constructor for backward compatibility
MemoryMappedFile::MemoryMappedFile(const std::string& filename, bool enable_performance_monitoring)
    : mapped_data_(nullptr),
      file_size_(0)
#ifdef _WIN32
      ,
      file_handle_(INVALID_HANDLE_VALUE),
      mapping_handle_(nullptr)
#else
      ,
      file_descriptor_(-1)
#endif
{
    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        mapFile(filename);

        auto end_time = std::chrono::high_resolution_clock::now();
        metrics_.load_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        metrics_.memory_usage_bytes = 0;  // Virtual memory only
        metrics_.strategy_used = "Memory-mapped";
        metrics_.fallback_used = false;

        // Unused parameter warning suppression
        (void)enable_performance_monitoring;

    } catch (const std::exception& e) {
        last_error_ = e.what();
        cleanup();  // Ensure cleanup on failure
        throw FileAccessException("Failed to memory-map file: " + std::string(e.what()));
    }
}

void MemoryMappedFile::mapFile(const std::string& filename) {
#ifdef _WIN32
    // Windows implementation using CreateFileMapping
    file_handle_ = CreateFileA(filename.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);

    if (file_handle_ == INVALID_HANDLE_VALUE) {
        throw FileAccessException(
            FileAccessErrors::cannotOpen(filename, getWindowsErrorString(GetLastError())));
    }

    // Get file size
    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(file_handle_, &file_size_li)) {
        DWORD error = GetLastError();
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        throw FileAccessException(FileAccessErrors::cannotGetSize(filename) + ": " +
                                  getWindowsErrorString(error));
    }

    // Check for files larger than size_t can handle
    if (static_cast<uint64_t>(file_size_li.QuadPart) > std::numeric_limits<size_t>::max()) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        throw FileAccessException("File too large for current platform: " + filename + " (" +
                                  std::to_string(file_size_li.QuadPart) + " bytes)");
    }

    file_size_ = static_cast<size_t>(file_size_li.QuadPart);

    // Create file mapping
    mapping_handle_ = CreateFileMappingA(file_handle_,
                                         nullptr,
                                         PAGE_READONLY,
                                         0,
                                         0,  // Map entire file
                                         nullptr);

    if (!mapping_handle_) {
        DWORD error = GetLastError();
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        throw FileAccessException(FileAccessErrors::cannotMap(filename, "create mapping for") +
                                  ": " + getWindowsErrorString(error));
    }

    // Map view of file
    mapped_data_ = static_cast<const uint8_t*>(MapViewOfFile(mapping_handle_,
                                                             FILE_MAP_READ,
                                                             0,
                                                             0,  // Map from beginning
                                                             0   // Map entire file
                                                             ));

    if (!mapped_data_) {
        DWORD error = GetLastError();
        CloseHandle(mapping_handle_);
        mapping_handle_ = nullptr;
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        throw FileAccessException(FileAccessErrors::cannotMap(filename, "map view of") + ": " +
                                  getWindowsErrorString(error));
    }

#else
    // Unix/Linux implementation using mmap
    file_descriptor_ = open(filename.c_str(), O_RDONLY);
    if (file_descriptor_ == -1) {
        int error_code = errno;
        throw FileAccessException(
            FileAccessErrors::cannotOpen(filename, getUnixErrorString(error_code)));
    }

    // Get file size
    struct stat file_stat;
    if (fstat(file_descriptor_, &file_stat) == -1) {
        int error_code = errno;
        close(file_descriptor_);
        file_descriptor_ = -1;
        throw FileAccessException(FileAccessErrors::cannotGetSize(filename) + ": " +
                                  getUnixErrorString(error_code));
    }

    // Check for files larger than size_t can handle
    if (file_stat.st_size < 0 ||
        static_cast<uint64_t>(file_stat.st_size) > std::numeric_limits<size_t>::max()) {
        close(file_descriptor_);
        file_descriptor_ = -1;
        throw FileAccessException("File too large for current platform: " + filename + " (" +
                                  std::to_string(file_stat.st_size) + " bytes)");
    }

    file_size_ = static_cast<size_t>(file_stat.st_size);

    // Memory map the file
    void* mapped = mmap(nullptr,           // Let system choose address
                        file_size_,        // Map entire file
                        PROT_READ,         // Read-only access
                        MAP_PRIVATE,       // Private mapping
                        file_descriptor_,  // File descriptor
                        0                  // Offset from beginning
    );

    if (mapped == MAP_FAILED) {
        int error_code = errno;
        close(file_descriptor_);
        file_descriptor_ = -1;
        throw FileAccessException(FileAccessErrors::cannotMap(filename, "memory map") + ": " +
                                  getUnixErrorString(error_code));
    }

    mapped_data_ = static_cast<const uint8_t*>(mapped);
#endif
}

MemoryMappedFile::~MemoryMappedFile() {
    cleanup();
}

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept(false)
    : mapped_data_(other.mapped_data_),
      file_size_(other.file_size_),
      last_error_(std::move(other.last_error_)),
      metrics_(std::move(other.metrics_))
#ifdef _WIN32
      ,
      file_handle_(other.file_handle_),
      mapping_handle_(other.mapping_handle_)
#else
      ,
      file_descriptor_(other.file_descriptor_)
#endif
{
    // Transfer ownership
    other.mapped_data_ = nullptr;
    other.file_size_ = 0;
    other.last_error_.clear();
    other.metrics_ = {};
#ifdef _WIN32
    other.file_handle_ = INVALID_HANDLE_VALUE;
    other.mapping_handle_ = nullptr;
#else
    other.file_descriptor_ = -1;
#endif
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept(false) {
    if (this != &other) {
        cleanup();

        // Transfer ownership
        mapped_data_ = other.mapped_data_;
        file_size_ = other.file_size_;
        last_error_ = std::move(other.last_error_);
        metrics_ = std::move(other.metrics_);
#ifdef _WIN32
        file_handle_ = other.file_handle_;
        mapping_handle_ = other.mapping_handle_;
#else
        file_descriptor_ = other.file_descriptor_;
#endif

        // Reset other object
        other.mapped_data_ = nullptr;
        other.file_size_ = 0;
        other.last_error_.clear();
        other.metrics_ = {};
#ifdef _WIN32
        other.file_handle_ = INVALID_HANDLE_VALUE;
        other.mapping_handle_ = nullptr;
#else
        other.file_descriptor_ = -1;
#endif
    }
    return *this;
}

void MemoryMappedFile::cleanup() {
#ifdef _WIN32
    if (mapped_data_) {
        UnmapViewOfFile(mapped_data_);
        mapped_data_ = nullptr;
    }
    if (mapping_handle_) {
        CloseHandle(mapping_handle_);
        mapping_handle_ = nullptr;
    }
    if (file_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (mapped_data_) {
        munmap(const_cast<uint8_t*>(mapped_data_), file_size_);
        mapped_data_ = nullptr;
    }
    if (file_descriptor_ != -1) {
        close(file_descriptor_);
        file_descriptor_ = -1;
    }
#endif
    file_size_ = 0;
}

std::string MemoryMappedFile::getPerformanceMetrics() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "Memory-mapped strategy: " << (static_cast<double>(file_size_) / 1024.0 / 1024.0)
        << " MB mapped in " << metrics_.load_time.count() << " ms";
    return oss.str();
}

#ifdef _WIN32
std::string MemoryMappedFile::getWindowsErrorString(unsigned long error_code) {
    if (error_code == 0) {
        return "No error";
    }

    LPSTR messageBuffer = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   nullptr,
                   error_code,
                   0,
                   (LPSTR)&messageBuffer,
                   0,
                   nullptr);

    std::string message(messageBuffer);
    LocalFree(messageBuffer);

    // Remove trailing newline if present
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
        if (!message.empty() && message.back() == '\r') {
            message.pop_back();
        }
    }

    return message;
}
#else
std::string MemoryMappedFile::getUnixErrorString(int errno_code) {
    // Use thread-safe strerror_r on POSIX systems
    char buffer[256];
    return strerror_r(errno_code, buffer, sizeof(buffer)) == 0 ? std::string(buffer)
                                                               : "Unknown error";
}
#endif