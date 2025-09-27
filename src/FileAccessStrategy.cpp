/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "FileAccessStrategy.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #include <fcntl.h>
#else
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

// ============================================================================
// Helper Functions
// ============================================================================

#ifdef _WIN32
std::string getLastErrorString() {
    DWORD error = GetLastError();
    if (error == 0) return "No error";

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer, 0, nullptr);

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);

    // Remove trailing newline if present
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
        if (!message.empty() && message.back() == '\r') {
            message.pop_back();
        }
    }

    return "Error " + std::to_string(error) + ": " + message;
}
#endif

// ============================================================================
// FileAccessStrategy Implementation
// ============================================================================

std::unique_ptr<FileAccessStrategy> FileAccessStrategy::create(
    const std::string& filename,
    size_t mmap_threshold,
    bool enable_performance_monitoring
) {
    size_t file_size = getFileSize(filename);

    // Validate non-zero file size
    if (file_size == 0) {
        throw std::runtime_error("Cannot process zero-sized file: " + filename);
    }

    if (file_size >= mmap_threshold) {
        try {
            // Try memory mapping for large files
            return std::make_unique<MemoryMappedFile>(filename, enable_performance_monitoring);
        } catch (const std::exception& e) {
            // Fall back to in-memory if memory mapping fails
            std::cerr << "Warning: Memory mapping failed (" << e.what()
                      << "), falling back to in-memory loading\n";
            return std::make_unique<InMemoryFile>(filename, enable_performance_monitoring);
        }
    } else {
        // Use in-memory for smaller files
        return std::make_unique<InMemoryFile>(filename, enable_performance_monitoring);
    }
}

size_t FileAccessStrategy::getFileSize(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    auto size = file.tellg();
    if (size < 0) {
        throw std::runtime_error("Cannot determine file size: " + filename);
    }
    
    return static_cast<size_t>(size);
}

// ============================================================================
// InMemoryFile Implementation
// ============================================================================

InMemoryFile::InMemoryFile(const std::string& filename, bool enable_performance_monitoring)
    : performance_monitoring_enabled_(enable_performance_monitoring), load_time_ms_(0.0) {

    auto start_time = std::chrono::high_resolution_clock::now();

    // Use centralized file size detection
    size_t file_size = FileAccessStrategy::getFileSize(filename);

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }

    // Reserve memory and read file
    data_.resize(file_size);
    file.read(reinterpret_cast<char*>(data_.data()), file_size);

    if (!file) {
        throw std::runtime_error("Failed to read file: " + filename);
    }

    if (performance_monitoring_enabled_) {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        load_time_ms_ = duration.count() / 1000.0;
    }
}

std::string InMemoryFile::getPerformanceMetrics() const {
    if (!performance_monitoring_enabled_) {
        return "";
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "In-memory strategy: " << (data_.size() / 1024.0 / 1024.0) << " MB loaded in "
        << load_time_ms_ << " ms";
    return oss.str();
}

// ============================================================================
// MemoryMappedFile Implementation
// ============================================================================

MemoryMappedFile::MemoryMappedFile(const std::string& filename, bool enable_performance_monitoring)
    : mapped_data_(nullptr), file_size_(0), performance_monitoring_enabled_(enable_performance_monitoring), load_time_ms_(0.0)
#ifdef _WIN32
    , file_handle_(INVALID_HANDLE_VALUE), mapping_handle_(nullptr)
#else
    , file_descriptor_(-1)
#endif
{
    auto start_time = std::chrono::high_resolution_clock::now();
#ifdef _WIN32
    // Windows implementation using CreateFileMapping
    file_handle_ = CreateFileA(
        filename.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Cannot open file for mapping: " + filename + " (" + getLastErrorString() + ")");
    }
    
    // Get file size
    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(file_handle_, &file_size_li)) {
        CloseHandle(file_handle_);
        throw std::runtime_error("Cannot get file size: " + filename + " (" + getLastErrorString() + ")");
    }
    file_size_ = static_cast<size_t>(file_size_li.QuadPart);
    
    // Create file mapping
    mapping_handle_ = CreateFileMappingA(
        file_handle_,
        nullptr,
        PAGE_READONLY,
        0, 0,  // Map entire file
        nullptr
    );
    
    if (!mapping_handle_) {
        CloseHandle(file_handle_);
        throw std::runtime_error("Cannot create file mapping: " + filename + " (" + getLastErrorString() + ")");
    }
    
    // Map view of file
    mapped_data_ = static_cast<const uint8_t*>(MapViewOfFile(
        mapping_handle_,
        FILE_MAP_READ,
        0, 0,  // Map from beginning
        0      // Map entire file
    ));
    
    if (!mapped_data_) {
        CloseHandle(mapping_handle_);
        CloseHandle(file_handle_);
        throw std::runtime_error("Cannot map view of file: " + filename + " (" + getLastErrorString() + ")");
    }

#else
    // Unix/Linux implementation using mmap
    file_descriptor_ = open(filename.c_str(), O_RDONLY);
    if (file_descriptor_ == -1) {
        throw std::runtime_error("Cannot open file for mapping: " + filename);
    }
    
    // Get file size
    struct stat file_stat;
    if (fstat(file_descriptor_, &file_stat) == -1) {
        close(file_descriptor_);
        throw std::runtime_error("Cannot get file size: " + filename);
    }
    file_size_ = static_cast<size_t>(file_stat.st_size);
    
    // Memory map the file
    void* mapped = mmap(
        nullptr,              // Let system choose address
        file_size_,           // Map entire file
        PROT_READ,            // Read-only access
        MAP_PRIVATE,          // Private mapping
        file_descriptor_,     // File descriptor
        0                     // Offset from beginning
    );
    
    if (mapped == MAP_FAILED) {
        close(file_descriptor_);
        throw std::runtime_error("Cannot memory map file: " + filename);
    }
    
    mapped_data_ = static_cast<const uint8_t*>(mapped);
#endif

    if (performance_monitoring_enabled_) {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        load_time_ms_ = duration.count() / 1000.0;
    }
}

MemoryMappedFile::~MemoryMappedFile() {
    cleanup();
}

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept
    : mapped_data_(other.mapped_data_), file_size_(other.file_size_),
      performance_monitoring_enabled_(other.performance_monitoring_enabled_), load_time_ms_(other.load_time_ms_)
#ifdef _WIN32
    , file_handle_(other.file_handle_), mapping_handle_(other.mapping_handle_)
#else
    , file_descriptor_(other.file_descriptor_)
#endif
{
    // Transfer ownership
    other.mapped_data_ = nullptr;
    other.file_size_ = 0;
    other.performance_monitoring_enabled_ = false;
    other.load_time_ms_ = 0.0;
#ifdef _WIN32
    other.file_handle_ = INVALID_HANDLE_VALUE;
    other.mapping_handle_ = nullptr;
#else
    other.file_descriptor_ = -1;
#endif
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
    if (this != &other) {
        cleanup();
        
        // Transfer ownership
        mapped_data_ = other.mapped_data_;
        file_size_ = other.file_size_;
        performance_monitoring_enabled_ = other.performance_monitoring_enabled_;
        load_time_ms_ = other.load_time_ms_;
#ifdef _WIN32
        file_handle_ = other.file_handle_;
        mapping_handle_ = other.mapping_handle_;
#else
        file_descriptor_ = other.file_descriptor_;
#endif

        // Reset other object
        other.mapped_data_ = nullptr;
        other.file_size_ = 0;
        other.performance_monitoring_enabled_ = false;
        other.load_time_ms_ = 0.0;
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
    if (mapped_data_ && file_size_ > 0) {
        munmap(const_cast<void*>(static_cast<const void*>(mapped_data_)), file_size_);
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
    if (!performance_monitoring_enabled_) {
        return "";
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    oss << "Memory-mapped strategy: " << (file_size_ / 1024.0 / 1024.0) << " MB mapped in "
        << load_time_ms_ << " ms";
    return oss.str();
}