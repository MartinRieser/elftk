/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <thread>

// Forward declarations for C libraries
struct ihex_state;
struct srec_state;

/**
 * @file ExportFormats.h
 * @brief Binary export format implementations for ELF analysis results
 *
 * This file provides C++ wrappers around arkku/ihex and arkku/srec libraries
 * for exporting ELF memory regions to various binary formats used in embedded
 * development.
 *
 * Key Features:
 * - Thread-safe implementation with RAII-based resource management
 * - Consistent exception-based error handling
 * - Optimized S-Record generation using arkku library
 * - Cross-platform file I/O with proper validation
 *
 * Usage Example:
 * @code
 * std::vector<ExportMemoryRegion> regions;
 * regions.emplace_back(0x08000000, 1024, data_vector, ".text");
 *
 * auto exporter = createExporter("hex");
 * bool success = exporter->exportToFile("firmware.hex", regions, 0x1000);
 * @endcode
 *
 * @author ELF Symbol Reader Development Team
 * @date 2025
 */

// Forward declarations for arkku library types
extern "C" {
    #include "kk_ihex.h"
    // Note: kk_srec.h has C99 'restrict' keyword that conflicts with C++
    // We'll include it only in the .cpp file and forward declare the struct here
    struct srec_state;
}

/**
 * @brief Exportable memory region data
 * 
 * Represents a contiguous memory region extracted from ELF sections
 * with address, size, and binary data for export to various formats.
 * 
 * @note This is different from the ExportMemoryRegion struct in ElfStructures.h
 *       which is used for ELF program header analysis.
 */
struct ExportMemoryRegion {
    uint64_t address;           ///< Start address of the region
    uint64_t size;              ///< Size of the region in bytes
    std::vector<uint8_t> data;  ///< Binary data content
    std::string section_name;   ///< Source ELF section name (e.g., ".text", ".data")
    
    ExportMemoryRegion(uint64_t addr, uint64_t sz, const std::vector<uint8_t>& d, const std::string& name = "")
        : address(addr), size(sz), data(d), section_name(name) {}
};

/**
 * @brief Base class for binary format exporters
 *
 * Abstract base class defining the interface for exporting memory regions
 * to different binary formats. Provides common functionality and virtual
 * methods for format-specific implementations.
 *
 * Thread Safety: All derived classes must be thread-safe for concurrent exports.
 * Error Handling: Uses exception-based error reporting for consistent error handling.
 */
class BinaryExporter {
public:
    // Export configuration constants
    static constexpr size_t DEFAULT_GAP_BRIDGE_SIZE = 256;  ///< Default gap bridging threshold
    static constexpr size_t SREC_GAP_BRIDGE_SIZE = 64;      ///< S-Record gap bridging threshold
    static constexpr size_t MAX_SREC_DATA_BYTES = 32;       ///< Maximum data bytes per S-Record
    static constexpr uint8_t DEFAULT_HEX_BYTES_PER_RECORD = 16; ///< Default Intel HEX bytes per record

    virtual ~BinaryExporter() = default;

    /**
     * @brief Export memory regions to a file
     *
     * @param filename Output file path
     * @param regions Vector of memory regions to export
     * @param base_offset Address offset to apply to all regions
     * @throws ExportException on file I/O errors or invalid data
     * @return true if export succeeded
     */
    virtual bool exportToFile(const std::string& filename,
                             const std::vector<ExportMemoryRegion>& regions,
                             uint64_t base_offset = 0) = 0;

    /**
     * @brief Get the file extension for this format
     * @return File extension including the dot (e.g., ".hex", ".s19")
     */
    virtual std::string getFileExtension() const = 0;

    /**
     * @brief Get human-readable format name
     * @return Format name string (e.g., "Intel HEX", "Motorola S-Record")
     */
    virtual std::string getFormatName() const = 0;

protected:
    /**
     * @brief Filter regions to remove gaps and optimize for format
     *
     * @param regions Input regions
     * @param max_gap Maximum gap size to bridge
     * @return Filtered and optimized regions
     */
    std::vector<ExportMemoryRegion> filterRegions(const std::vector<ExportMemoryRegion>& regions,
                                                  size_t max_gap = SREC_GAP_BRIDGE_SIZE) const;

    /**
     * @brief Validate input parameters before export
     *
     * @param filename Output file path to validate
     * @param regions Memory regions to validate
     * @throws ExportException if validation fails
     */
    void validateInputs(const std::string& filename,
                       const std::vector<ExportMemoryRegion>& regions) const;
};

/**
 * @brief Export exception for consistent error handling
 */
class ExportException : public std::runtime_error {
public:
    explicit ExportException(const std::string& message) : std::runtime_error(message) {}
};

/**
 * @brief Intel HEX format exporter
 *
 * Thread-safe C++ wrapper around arkku/ihex library for exporting memory regions
 * to Intel HEX format. Uses RAII-based callback management instead of global state.
 *
 * Features:
 * - Thread-safe implementation without global state
 * - RAII-based resource management
 * - Configurable bytes per record
 * - Exception-based error handling
 */
class IntelHexExporter : public BinaryExporter {
public:
    /**
     * @brief Constructor with optional configuration
     * @param bytes_per_record Number of data bytes per HEX record (1-255, default: 16)
     */
    explicit IntelHexExporter(uint8_t bytes_per_record = DEFAULT_HEX_BYTES_PER_RECORD);

    bool exportToFile(const std::string& filename,
                     const std::vector<ExportMemoryRegion>& regions,
                     uint64_t base_offset = 0) override;

    std::string getFileExtension() const override { return ".hex"; }
    std::string getFormatName() const override { return "Intel HEX"; }

public:
    // Thread-local storage for current output stream (public for C callback access)
    static thread_local std::ofstream* current_output_stream_;

private:
    uint8_t bytes_per_record_;

    /**
     * @brief Write a single memory region to Intel HEX using existing state
     * @param ihex Initialized ihex state to use
     * @param region Memory region to write
     * @param offset Address offset to apply
     */
    bool writeRegionData(struct ihex_state* ihex, const ExportMemoryRegion& region, uint64_t offset);
};

/**
 * @brief Motorola S-Record format exporter
 *
 * Optimized C++ wrapper using arkku/srec library for exporting memory regions
 * to Motorola S-Record format (S19/S28/S37). Automatically selects
 * appropriate S-record type based on address width.
 *
 * Features:
 * - Leverages arkku library for efficient S-Record generation
 * - Automatic format selection based on address range
 * - Thread-safe implementation
 * - Exception-based error handling
 */
class SRecordExporter : public BinaryExporter {
public:
    /**
     * @brief S-Record format variants
     */
    enum class SRecordType {
        AUTO,   ///< Automatically select based on address width
        S19,    ///< 16-bit addresses (S1/S9 records)
        S28,    ///< 24-bit addresses (S2/S8 records)
        S37     ///< 32-bit addresses (S3/S7 records)
    };

    /**
     * @brief Constructor with format selection
     * @param type S-Record type (AUTO for automatic selection)
     */
    explicit SRecordExporter(SRecordType type = SRecordType::AUTO);

    bool exportToFile(const std::string& filename,
                     const std::vector<ExportMemoryRegion>& regions,
                     uint64_t base_offset = 0) override;

    std::string getFileExtension() const override;
    std::string getFormatName() const override;

    /**
     * @brief Set S-Record type explicitly
     * @param type Desired S-Record format
     */
    void setRecordType(SRecordType type) { record_type_ = type; }

private:
    SRecordType record_type_;

    /**
     * @brief Determine optimal S-Record type for address range
     * @param max_address Highest address in the data
     * @return Recommended S-Record type
     */
    SRecordType determineRecordType(uint64_t max_address) const;

    /**
     * @brief Write memory region using arkku library efficiently
     * @param output Output stream for writing
     * @param region Memory region to write
     * @param offset Address offset to apply
     * @param type S-Record type to use
     */
    bool writeRegionWithLibrary(std::ofstream& output, const ExportMemoryRegion& region,
                               uint64_t offset, SRecordType type);

    /**
     * @brief Convert S-Record type enum to string
     * @param type S-Record type
     * @return String representation
     */
    std::string recordTypeToString(SRecordType type) const;

    /**
     * @brief Get address width for S-Record type
     * @param type S-Record type
     * @return Address width in bytes
     */
    static constexpr uint8_t getAddressWidth(SRecordType type) {
        switch (type) {
            case SRecordType::S19: return 2;
            case SRecordType::S28: return 3;
            case SRecordType::S37: return 4;
            default: return 2;
        }
    }
};

/**
 * @brief Raw binary format exporter
 *
 * Exports memory regions as raw binary files. Handles memory gaps
 * by either creating separate files or filling with padding bytes.
 *
 * Features:
 * - Multiple gap handling strategies
 * - Cross-platform file path handling
 * - Large file optimization
 * - Exception-based error handling
 */
class RawBinaryExporter : public BinaryExporter {
public:
    /**
     * @brief Gap handling strategies
     */
    enum class GapHandling {
        SEPARATE_FILES, ///< Create separate files for each region
        FILL_ZEROS,     ///< Fill gaps with zero bytes
        FILL_PATTERN    ///< Fill gaps with specified pattern
    };

    // Default values as constants
    static constexpr uint8_t DEFAULT_FILL_PATTERN = 0xFF;

    /**
     * @brief Constructor with gap handling configuration
     * @param gap_handling How to handle memory gaps
     * @param fill_pattern Pattern byte for FILL_PATTERN mode (default: 0xFF)
     */
    explicit RawBinaryExporter(GapHandling gap_handling = GapHandling::SEPARATE_FILES,
                              uint8_t fill_pattern = DEFAULT_FILL_PATTERN);

    bool exportToFile(const std::string& filename,
                     const std::vector<ExportMemoryRegion>& regions,
                     uint64_t base_offset = 0) override;

    std::string getFileExtension() const override { return ".bin"; }
    std::string getFormatName() const override { return "Raw Binary"; }

private:
    GapHandling gap_handling_;
    uint8_t fill_pattern_;

    /**
     * @brief Generate cross-platform safe filename with region information
     * @param base_filename Base filename
     * @param region Memory region
     * @param base_offset Address offset
     * @return Generated filename
     */
    std::string generateRegionFilename(const std::string& base_filename,
                                     const ExportMemoryRegion& region,
                                     uint64_t base_offset) const;

    /**
     * @brief Export regions as separate binary files
     * @param base_filename Base filename (will append region info)
     * @param regions Memory regions to export
     * @param base_offset Address offset
     */
    bool exportSeparateFiles(const std::string& base_filename,
                           const std::vector<ExportMemoryRegion>& regions,
                           uint64_t base_offset);

    /**
     * @brief Export regions as single binary file with gap filling
     * @param filename Output filename
     * @param regions Memory regions to export
     * @param base_offset Address offset
     */
    bool exportSingleFile(const std::string& filename,
                         const std::vector<ExportMemoryRegion>& regions,
                         uint64_t base_offset);
};

/**
 * @brief Factory function for creating exporters
 *
 * Creates appropriate exporter instances based on format string.
 * Thread-safe and exception-safe implementation.
 *
 * @param format Format string ("hex", "s19", "s28", "s37", "srec", "bin")
 * @return Unique pointer to appropriate exporter
 * @throws ExportException if format is unsupported
 *
 * Supported formats:
 * - "hex": Intel HEX format
 * - "s19": Motorola S-Record with 16-bit addresses
 * - "s28": Motorola S-Record with 24-bit addresses
 * - "s37": Motorola S-Record with 32-bit addresses
 * - "srec": Motorola S-Record with automatic type selection
 * - "bin": Raw binary format
 */
std::unique_ptr<BinaryExporter> createExporter(const std::string& format);