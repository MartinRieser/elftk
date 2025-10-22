/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ExportFormats.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>

extern "C" {
#include "kk_ihex_read.h"
#include "kk_ihex_write.h"
// Define restrict as empty for C++ compatibility
#define restrict
#include "kk_srec.h"
#undef restrict

/**
 * @brief Required callback for arkku IHEX library (reading - not used in export)
 */
// External library signature, cannot change
ihex_bool_t ihex_data_read(struct ihex_state* ihex,
                           ihex_record_type_t type,  // NOLINT(bugprone-easily-swappable-parameters)
                           ihex_bool_t checksum_mismatch) {
    (void)ihex;
    (void)type;
    (void)checksum_mismatch;
    return 1;  // Continue processing
}

/**
 * @brief Thread-local callback for arkku IHEX library buffer flushing
 * Uses thread-local storage instead of global state for thread safety
 */
void ihex_flush_buffer(struct ihex_state* /* ihex */, char* buffer, char* eptr) {
    if (IntelHexExporter::current_output_stream_ &&
        IntelHexExporter::current_output_stream_->is_open()) {
        size_t length = static_cast<size_t>(eptr - buffer);
        IntelHexExporter::current_output_stream_->write(buffer,
                                                        static_cast<std::streamsize>(length));
    }
}

/**
 * @brief Required callback for arkku SREC library (reading - not used in export)
 */
// NOLINTBEGIN(bugprone-easily-swappable-parameters) - External library signature, cannot change
void srec_data_read(struct srec_state* srec,
                    srec_record_number_t record_type,
                    srec_address_t address,
                    uint8_t* data,
                    srec_count_t length,
                    srec_bool_t checksum_error) {
    (void)srec;
    (void)record_type;
    (void)address;
    (void)data;
    (void)length;
    (void)checksum_error;
}
// NOLINTEND(bugprone-easily-swappable-parameters)
}

// ============================================================================
// Base BinaryExporter Implementation
// ============================================================================

void BinaryExporter::validateInputs(const std::string& filename,
                                    const std::vector<ExportMemoryRegion>& regions) const {
    if (filename.empty()) {
        throw ExportException("Output filename cannot be empty");
    }

    // Validate file path for cross-platform compatibility
    std::filesystem::path file_path(filename);
    if (!file_path.has_filename()) {
        throw ExportException("Invalid output filename: " + filename);
    }

    // Check if parent directory exists and is writable
    auto parent_dir = file_path.parent_path();
    if (!parent_dir.empty() && !std::filesystem::exists(parent_dir)) {
        std::error_code ec;
        std::filesystem::create_directories(parent_dir, ec);
        if (ec) {
            throw ExportException("Cannot create output directory: " + parent_dir.string());
        }
    }

    // Validate regions
    for (const auto& region : regions) {
        if (region.data.size() != region.size) {
            throw ExportException("Memory region data size mismatch");
        }
        if (region.data.size() > 0 && region.data.empty()) {
            throw ExportException("Memory region has invalid data");
        }
    }
}

std::vector<ExportMemoryRegion>
BinaryExporter::filterRegions(const std::vector<ExportMemoryRegion>& regions,
                              size_t max_gap) const {
    std::vector<ExportMemoryRegion> filtered;

    if (regions.empty()) {
        return filtered;
    }

    // Sort regions by address
    auto sorted_regions = regions;
    std::sort(sorted_regions.begin(),
              sorted_regions.end(),
              [](const ExportMemoryRegion& a, const ExportMemoryRegion& b) {
                  return a.address < b.address;
              });

    // Merge regions that are close together
    filtered.reserve(sorted_regions.size());
    filtered.push_back(sorted_regions[0]);

    for (size_t i = 1; i < sorted_regions.size(); ++i) {
        const auto& current = sorted_regions[i];
        auto& last = filtered.back();

        uint64_t gap = current.address - (last.address + last.size);

        if (gap <= max_gap) {
            // Merge regions by extending the last one
            size_t old_size = last.data.size();
            last.data.resize(old_size + gap + current.data.size());

            // Fill gap with zeros
            std::fill(last.data.begin() + static_cast<long>(old_size),
                      last.data.begin() + static_cast<long>(old_size + gap),
                      0);

            // Copy new data
            std::copy(current.data.begin(),
                      current.data.end(),
                      last.data.begin() + static_cast<long>(old_size + gap));

            last.size = last.data.size();
            last.section_name += "+" + current.section_name;
        } else {
            filtered.push_back(current);
        }
    }

    return filtered;
}

// ============================================================================
// Intel HEX Exporter Implementation
// ============================================================================

// Thread-local storage for output stream
thread_local std::unique_ptr<std::ofstream> IntelHexExporter::current_output_stream_ = nullptr;

IntelHexExporter::IntelHexExporter(uint8_t bytes_per_record) : bytes_per_record_(bytes_per_record) {
    if (bytes_per_record == 0) {
        throw ExportException("Invalid bytes_per_record: must be 1-255");
    }
}

bool IntelHexExporter::exportToFile(const std::string& filename,
                                    const std::vector<ExportMemoryRegion>& regions,
                                    uint64_t base_offset) {
    try {
        // Validate inputs first
        validateInputs(filename, regions);

        // Open output file
        std::ofstream output_file(filename, std::ios::out | std::ios::trunc);
        if (!output_file.is_open()) {
            throw ExportException("Cannot open file for writing: " + filename);
        }

        // Set thread-local output stream
        current_output_stream_ = std::make_unique<std::ofstream>(std::move(output_file));

        // Filter and optimize regions
        auto filtered_regions = filterRegions(regions, DEFAULT_GAP_BRIDGE_SIZE);

        // Initialize ihex state
        struct ihex_state ihex;
        ihex_init(&ihex);

        // Write all regions using the same state
        for (const auto& region : filtered_regions) {
            if (!writeRegionData(&ihex, region, base_offset)) {
                throw ExportException("Failed to write memory region at address 0x" +
                                      std::to_string(region.address));
            }
        }

        // Write end-of-file record
        ihex_end_write(&ihex);

        // Clean up thread-local storage (this will also close the file)
        current_output_stream_.reset();

        // Note: output_file was moved into current_output_stream_, so it's no longer valid
        // The file will be properly closed when current_output_stream_ is reset

        return true;

    } catch (const ExportException&) {
        current_output_stream_.reset();  // Clean up on exception
        throw;                           // Re-throw export exceptions
    } catch (const std::exception& e) {
        current_output_stream_.reset();  // Clean up on exception
        throw ExportException("Intel HEX export failed: " + std::string(e.what()));
    }
}

bool IntelHexExporter::writeRegionData(struct ihex_state* ihex,
                                       const ExportMemoryRegion& region,
                                       uint64_t offset) {
    if (!ihex || region.data.empty()) {
        return true;  // Nothing to write
    }

    uint64_t base_address = region.address + offset;

    // Write data in chunks
    size_t bytes_written = 0;
    const uint8_t* data_ptr = region.data.data();

    while (bytes_written < region.data.size()) {
        size_t chunk_size =
            std::min(static_cast<size_t>(bytes_per_record_), region.data.size() - bytes_written);

        // Calculate current address for this chunk
        uint64_t current_address = base_address + bytes_written;

        // Validate address range for Intel HEX format
        if (current_address > 0xFFFFFFFF) {
            throw ExportException("Address too large for Intel HEX format: 0x" +
                                  std::to_string(current_address));
        }

        // Set the address and write the data chunk
        ihex_write_at_address(ihex, static_cast<uint32_t>(current_address));
        ihex_write_bytes(ihex, data_ptr + bytes_written, static_cast<ihex_count_t>(chunk_size));

        bytes_written += chunk_size;
    }

    return true;
}

// ============================================================================
// S-Record Exporter Implementation
// ============================================================================

SRecordExporter::SRecordExporter(SRecordType type) : record_type_(type) {}

std::string SRecordExporter::getFileExtension() const {
    switch (record_type_) {
        case SRecordType::S19:
            return ".s19";
        case SRecordType::S28:
            return ".s28";
        case SRecordType::S37:
            return ".s37";
        default:
            return ".srec";
    }
}

std::string SRecordExporter::getFormatName() const {
    return "Motorola S-Record (" + recordTypeToString(record_type_) + ")";
}

bool SRecordExporter::exportToFile(const std::string& filename,
                                   const std::vector<ExportMemoryRegion>& regions,
                                   uint64_t base_offset) {
    try {
        // Validate inputs first
        validateInputs(filename, regions);

        // Open output file
        std::ofstream output_file(filename, std::ios::out | std::ios::trunc);
        if (!output_file.is_open()) {
            throw ExportException("Cannot open file for writing: " + filename);
        }

        // Filter regions
        auto filtered_regions = filterRegions(regions, SREC_GAP_BRIDGE_SIZE);

        if (filtered_regions.empty()) {
            output_file.close();
            return true;
        }

        // Determine record type if AUTO
        SRecordType actual_type = record_type_;
        if (actual_type == SRecordType::AUTO) {
            uint64_t max_address = 0;
            for (const auto& region : filtered_regions) {
                max_address = std::max(max_address, region.address + region.size + base_offset);
            }
            actual_type = determineRecordType(max_address);
        }

        // Write header record (S0) with standard "hello" message
        output_file << "S00F000068656C6C6F202020202000003C" << std::endl;

        // Write all regions using arkku library
        for (const auto& region : filtered_regions) {
            if (!writeRegionWithLibrary(output_file, region, base_offset, actual_type)) {
                throw ExportException("Failed to write S-Record for region at address 0x" +
                                      std::to_string(region.address));
            }
        }

        // Write termination record
        switch (actual_type) {
            case SRecordType::S19:
                output_file << "S9030000FC" << std::endl;
                break;
            case SRecordType::S28:
                output_file << "S804000000FB" << std::endl;
                break;
            case SRecordType::S37:
                output_file << "S70500000000FA" << std::endl;
                break;
            default:
                throw ExportException("Invalid S-Record type for termination");
        }

        output_file.close();
        if (output_file.fail()) {
            throw ExportException("Error closing S-Record output file: " + filename);
        }

        return true;

    } catch (const ExportException&) {
        throw;  // Re-throw export exceptions
    } catch (const std::exception& e) {
        throw ExportException("S-Record export failed: " + std::string(e.what()));
    }
}

SRecordExporter::SRecordType SRecordExporter::determineRecordType(uint64_t max_address) const {
    if (max_address <= 0xFFFF) {
        return SRecordType::S19;
    } else if (max_address <= 0xFFFFFF) {
        return SRecordType::S28;
    } else {
        return SRecordType::S37;
    }
}

bool SRecordExporter::writeRegionWithLibrary(std::ofstream& output,
                                             const ExportMemoryRegion& region,
                                             uint64_t offset,
                                             SRecordType type) {
    if (region.data.empty()) {
        return true;  // Nothing to write
    }

    uint64_t address = region.address + offset;
    const uint8_t* data = region.data.data();
    size_t remaining = region.data.size();
    uint8_t addr_bytes = getAddressWidth(type);

    // Validate address range for the selected S-Record type
    uint64_t max_address_for_type = (1ULL << (addr_bytes * 8)) - 1;
    if (address + remaining > max_address_for_type) {
        throw ExportException("Address range exceeds " + recordTypeToString(type) +
                              " format capacity");
    }

    while (remaining > 0) {
        size_t chunk_size = std::min(remaining, static_cast<size_t>(MAX_SREC_DATA_BYTES));

        // Calculate record length (address + data + checksum)
        uint8_t record_length = addr_bytes + static_cast<uint8_t>(chunk_size) + 1;

        // Write record type and length
        char record_type_char = static_cast<char>('1' + (addr_bytes - 2));
        output << 'S' << record_type_char;

        // Use stringstream for better formatting control
        std::ostringstream record_stream;
        record_stream << std::hex << std::uppercase << std::setfill('0');
        record_stream << std::setw(2) << static_cast<int>(record_length);

        // Write address
        for (int i = addr_bytes - 1; i >= 0; --i) {
            uint8_t addr_byte = static_cast<uint8_t>((address >> (i * 8)) & 0xFF);
            record_stream << std::setw(2) << static_cast<int>(addr_byte);
        }

        // Write data and calculate checksum
        uint8_t checksum = record_length;
        for (int i = addr_bytes - 1; i >= 0; --i) {
            checksum += static_cast<uint8_t>((address >> (i * 8)) & 0xFF);
        }

        for (size_t i = 0; i < chunk_size; ++i) {
            record_stream << std::setw(2) << static_cast<int>(data[i]);
            checksum += data[i];
        }

        // Write checksum (one's complement)
        checksum = ~checksum;
        record_stream << std::setw(2) << static_cast<int>(checksum);

        output << record_stream.str() << std::endl;

        data += chunk_size;
        address += chunk_size;
        remaining -= chunk_size;
    }

    return true;
}

std::string SRecordExporter::recordTypeToString(SRecordType type) const {
    switch (type) {
        case SRecordType::S19:
            return "S19";
        case SRecordType::S28:
            return "S28";
        case SRecordType::S37:
            return "S37";
        case SRecordType::AUTO:
            return "AUTO";
        default:
            return "Unknown";
    }
}

// ============================================================================
// Raw Binary Exporter Implementation
// ============================================================================

RawBinaryExporter::RawBinaryExporter(GapHandling gap_handling, uint8_t fill_pattern)
    : gap_handling_(gap_handling), fill_pattern_(fill_pattern) {}

std::string RawBinaryExporter::generateRegionFilename(const std::string& base_filename,
                                                      const ExportMemoryRegion& region,
                                                      uint64_t base_offset) const {
    // Remove extension from base filename
    std::filesystem::path base_path(base_filename);
    std::string base = base_path.stem().string();
    std::string extension = base_path.extension().string();
    if (extension.empty()) {
        extension = ".bin";
    }

    // Create cross-platform safe filename with region info
    std::ostringstream filename_stream;
    filename_stream << base << "_0x" << std::hex << std::uppercase << std::setfill('0')
                    << std::setw(8) << (region.address + base_offset) << "_"
                    << (region.section_name.empty() ? "region" : region.section_name) << extension;

    // Ensure the filename is in the same directory as the base filename
    std::filesystem::path result_path = base_path.parent_path() / filename_stream.str();
    return result_path.string();
}

bool RawBinaryExporter::exportToFile(const std::string& filename,
                                     const std::vector<ExportMemoryRegion>& regions,
                                     uint64_t base_offset) {
    try {
        // Validate inputs first
        validateInputs(filename, regions);

        if (regions.empty()) {
            // Create empty file for consistency
            std::ofstream empty_file(filename, std::ios::binary | std::ios::out | std::ios::trunc);
            if (!empty_file.is_open()) {
                throw ExportException("Cannot create empty output file: " + filename);
            }
            return true;
        }

        switch (gap_handling_) {
            case GapHandling::SEPARATE_FILES:
                return exportSeparateFiles(filename, regions, base_offset);
            case GapHandling::FILL_ZEROS:
            case GapHandling::FILL_PATTERN:
                return exportSingleFile(filename, regions, base_offset);
            default:
                throw ExportException("Invalid gap handling mode");
        }

    } catch (const ExportException&) {
        throw;  // Re-throw export exceptions
    } catch (const std::exception& e) {
        throw ExportException("Binary export failed: " + std::string(e.what()));
    }
}

bool RawBinaryExporter::exportSeparateFiles(const std::string& base_filename,
                                            const std::vector<ExportMemoryRegion>& regions,
                                            uint64_t base_offset) {
    for (const auto& region : regions) {
        // Generate cross-platform safe filename
        std::string filename = generateRegionFilename(base_filename, region, base_offset);

        std::ofstream output(filename, std::ios::binary | std::ios::out | std::ios::trunc);
        if (!output.is_open()) {
            throw ExportException("Cannot open file for writing: " + filename);
        }

        if (!region.data.empty()) {
            output.write(reinterpret_cast<const char*>(region.data.data()),
                         static_cast<std::streamsize>(region.data.size()));
        }

        output.close();
        if (output.fail()) {
            throw ExportException("Error writing to file: " + filename);
        }
    }

    return true;
}

bool RawBinaryExporter::exportSingleFile(const std::string& filename,
                                         const std::vector<ExportMemoryRegion>& regions,
                                         uint64_t base_offset) {
    // Sort regions by address
    auto sorted_regions = regions;
    std::sort(sorted_regions.begin(),
              sorted_regions.end(),
              [base_offset](const ExportMemoryRegion& a, const ExportMemoryRegion& b) {
                  return (a.address + base_offset) < (b.address + base_offset);
              });

    std::ofstream output(filename, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!output.is_open()) {
        throw ExportException("Cannot open file for writing: " + filename);
    }

    if (sorted_regions.empty()) {
        output.close();
        return true;
    }

    uint64_t current_pos = sorted_regions[0].address + base_offset;
    uint8_t fill_byte = (gap_handling_ == GapHandling::FILL_ZEROS) ? 0 : fill_pattern_;

    for (const auto& region : sorted_regions) {
        uint64_t region_start = region.address + base_offset;

        // Fill gap if needed
        if (region_start > current_pos) {
            uint64_t gap_size = region_start - current_pos;
            // Validate gap size to prevent memory issues
            if (gap_size > static_cast<uint64_t>(1024) * 1024 * 1024) {  // 1GB limit
                throw ExportException("Gap size too large: " + std::to_string(gap_size) + " bytes");
            }
            std::vector<uint8_t> fill_data(static_cast<size_t>(gap_size), fill_byte);
            output.write(reinterpret_cast<const char*>(fill_data.data()),
                         static_cast<std::streamsize>(gap_size));
        }

        // Write region data
        if (!region.data.empty()) {
            output.write(reinterpret_cast<const char*>(region.data.data()),
                         static_cast<std::streamsize>(region.data.size()));
        }
        current_pos = region_start + region.data.size();
    }

    output.close();
    if (output.fail()) {
        throw ExportException("Error writing to file: " + filename);
    }

    return true;
}

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<BinaryExporter> createExporter(const std::string& format) {
    if (format == "hex") {
        return std::make_unique<IntelHexExporter>();
    } else if (format == "s19") {
        return std::make_unique<SRecordExporter>(SRecordExporter::SRecordType::S19);
    } else if (format == "s28") {
        return std::make_unique<SRecordExporter>(SRecordExporter::SRecordType::S28);
    } else if (format == "s37") {
        return std::make_unique<SRecordExporter>(SRecordExporter::SRecordType::S37);
    } else if (format == "srec") {
        return std::make_unique<SRecordExporter>(SRecordExporter::SRecordType::AUTO);
    } else if (format == "bin") {
        return std::make_unique<RawBinaryExporter>(RawBinaryExporter::GapHandling::FILL_ZEROS);
    } else {
        throw ExportException("Unsupported export format: " + format +
                              ". Supported formats: hex, s19, s28, s37, srec, bin");
    }
}