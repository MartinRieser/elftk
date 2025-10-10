/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * @file ElfMemoryValidator.h
 * @brief Safe memory operations and bounds checking for ELF file processing
 *
 * This file provides utilities for safe memory access when processing ELF files,
 * including bounds checking, input validation, and protection against malformed
 * or malicious input files.
 *
 * Key Features:
 * - Comprehensive bounds checking for all memory operations
 * - Protection against integer overflow in size calculations
 * - Validation of ELF structure consistency
 * - Safe string operations with length limits
 *
 * @author ELF Symbol Reader Project
 * @date 2025
 */

#ifndef ELF_MEMORY_VALIDATOR_H
#define ELF_MEMORY_VALIDATOR_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include "ElfExceptions.h"

namespace ElfReaderUtils {

/**
 * @brief Constants for safe memory operations
 */
namespace MemoryConstants {
constexpr size_t MAX_FILE_SIZE = 1ULL * 1024 * 1024 * 1024;  // 1GB maximum file size
constexpr size_t MAX_STRING_LENGTH = 4096;                   // Maximum string length
constexpr size_t MAX_SECTION_COUNT = 65536;                  // Maximum number of sections
constexpr size_t MAX_SYMBOL_COUNT = 1048576;                 // Maximum number of symbols
constexpr size_t MAX_PROGRAM_HEADERS = 65536;                // Maximum program headers
constexpr size_t MAX_SECTION_NAME_LENGTH = 255;              // Maximum section name length
constexpr size_t MAX_SYMBOL_NAME_LENGTH = 255;               // Maximum symbol name length
}  // namespace MemoryConstants

/**
 * @brief Safe arithmetic operations with overflow checking
 */
class SafeArithmetic {
public:
    /**
     * @brief Safe addition with overflow checking
     * @param a First operand
     * @param b Second operand
     * @param context Description for error messages
     * @return Sum of a and b
     * @throws MemoryAccessError if overflow would occur
     */
    static size_t safeAdd(size_t a, size_t b, const std::string& context = "") {
        if (a > std::numeric_limits<size_t>::max() - b) {
            throw ElfReaderExceptions::MemoryAccessError("Integer overflow in " + context + " (" +
                                                         std::to_string(a) + " + " +
                                                         std::to_string(b) + ")");
        }
        return a + b;
    }

    /**
     * @brief Safe multiplication with overflow checking
     * @param a First operand
     * @param b Second operand
     * @param context Description for error messages
     * @return Product of a and b
     * @throws MemoryAccessError if overflow would occur
     */
    static size_t safeMultiply(size_t a, size_t b, const std::string& context = "") {
        if (a != 0 && b > std::numeric_limits<size_t>::max() / a) {
            throw ElfReaderExceptions::MemoryAccessError("Integer overflow in " + context + " (" +
                                                         std::to_string(a) + " * " +
                                                         std::to_string(b) + ")");
        }
        return a * b;
    }

    /**
     * @brief Safe array size calculation
     * @param element_size Size of each element
     * @param count Number of elements
     * @param context Description for error messages
     * @return Total size needed for array
     * @throws MemoryAccessError if calculation would overflow
     */
    static size_t
    safeArraySize(size_t element_size, size_t count, const std::string& context = "") {
        return safeMultiply(element_size, count, context);
    }
};

/**
 * @brief Memory bounds validator for ELF file processing
 */
class ElfMemoryValidator {
private:
    const uint8_t* data_;
    size_t size_;
    std::string filename_;

public:
    /**
     * @brief Construct validator for memory buffer
     * @param data Pointer to memory buffer
     * @param size Size of memory buffer
     * @param filename Filename for error reporting
     */
    ElfMemoryValidator(const uint8_t* data, size_t size, const std::string& filename)
        : data_(data), size_(size), filename_(filename) {
        validateBasicConstraints();
    }

    /**
     * @brief Validate that a memory range is within bounds
     * @param offset Starting offset
     * @param length Length of range
     * @param context Description for error messages
     * @throws MemoryAccessError if range is out of bounds
     */
    void validateRange(size_t offset, size_t length, const std::string& context = "") const {
        if (offset > size_) {
            throw ElfReaderExceptions::MemoryAccessError(
                "Offset beyond end of file: " + std::to_string(offset) +
                    " (file size: " + std::to_string(size_) + ")",
                offset);
        }

        size_t end_offset = SafeArithmetic::safeAdd(offset, length, context);
        if (end_offset > size_) {
            throw ElfReaderExceptions::MemoryAccessError(
                "Range exceeds file bounds: " + context + " (offset: " + std::to_string(offset) +
                    ", length: " + std::to_string(length) +
                    ", file size: " + std::to_string(size_) + ")",
                offset);
        }
    }

    /**
     * @brief Validate that an offset is within bounds
     * @param offset Offset to check
     * @param context Description for error messages
     * @throws MemoryAccessError if offset is out of bounds
     */
    void validateOffset(size_t offset, const std::string& context = "") const {
        validateRange(offset, 1, context);
    }

    /**
     * @brief Safe read of a value from memory
     * @tparam T Type of value to read
     * @param offset Offset to read from
     * @param context Description for error messages
     * @return Value read from memory
     * @throws MemoryAccessError if read would be out of bounds
     */
    template<typename T>
    T readValue(size_t offset, const std::string& context = "") const {
        validateRange(offset, sizeof(T), context);

        T value;
        std::memcpy(&value, &data_[offset], sizeof(T));
        return value;
    }

    /**
     * @brief Safe read of a string from memory
     * @param offset Offset to read from
     * @param max_length Maximum allowed string length
     * @param context Description for error messages
     * @return String read from memory
     * @throws MemoryAccessError if read would be out of bounds or string too long
     */
    std::string readString(size_t offset,
                           size_t max_length = MemoryConstants::MAX_STRING_LENGTH,
                           const std::string& context = "") const {
        validateOffset(offset, context);

        // Find null terminator within bounds
        size_t length = 0;
        size_t max_search_length = std::min(max_length, size_ - offset);

        while (length < max_search_length && data_[offset + length] != '\0') {
            length++;
        }

        if (length >= max_length) {
            throw ElfReaderExceptions::MemoryAccessError(
                "String too long at offset " + std::to_string(offset) +
                    " (max: " + std::to_string(max_length) + ")",
                offset);
        }

        validateRange(offset, length + 1, context);  // +1 for null terminator

        return std::string(reinterpret_cast<const char*>(&data_[offset]), length);
    }

    /**
     * @brief Validate ELF header structure
     * @throws ElfFileError if header is invalid
     */
    void validateElfHeader() const {
        if (size_ < 16) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::FileTooSmall,
                "File too small to be a valid ELF file (minimum 16 bytes)",
                filename_);
        }

        // Check ELF magic number
        if (data_[0] != 0x7f || data_[1] != 'E' || data_[2] != 'L' || data_[3] != 'F') {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid ELF magic number",
                filename_);
        }

        // Validate ELF class
        uint8_t elf_class = data_[4];
        if (elf_class != 1 && elf_class != 2) {  // ELFCLASS32 or ELFCLASS64
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid ELF class (must be 32-bit or 64-bit)",
                filename_);
        }

        // Validate ELF data encoding
        uint8_t elf_data = data_[5];
        if (elf_data != 1 && elf_data != 2) {  // ELFDATA2LSB or ELFDATA2MSB
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid ELF data encoding (must be little or big endian)",
                filename_);
        }

        // Validate ELF version
        uint8_t elf_version = data_[6];
        if (elf_version != 1) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid ELF version (must be 1)",
                filename_);
        }
    }

    /**
     * @brief Validate section header count
     * @param section_count Number of sections
     * @throws ElfFileError if section count is invalid
     */
    void validateSectionCount(uint16_t section_count) const {
        if (section_count == 0) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::InvalidFormat,
                "Invalid section count (0)",
                filename_);
        }

        // Note: uint16_t is already limited to 0-65535, no additional check needed
        // MAX_SECTION_COUNT is 65536, which is >= uint16_t max, so no validation required
    }

    /**
     * @brief Validate program header count
     * @param program_count Number of program headers
     * @throws ElfFileError if program header count is invalid
     */
    void validateProgramCount(uint16_t /* program_count */) const {
        // Note: uint16_t is already limited to 0-65535, no additional check needed
        // MAX_PROGRAM_HEADERS is 65536, which is >= uint16_t max, so no validation required
        // Program count of 0 is valid (not all ELF files have program headers)
    }

    /**
     * @brief Validate section name
     * @param name Section name to validate
     * @param offset Offset where name is located
     * @throws ElfFileError if section name is invalid
     */
    void validateSectionName(const std::string& name, size_t offset) const {
        if (name.length() > MemoryConstants::MAX_SECTION_NAME_LENGTH) {
            throw ElfReaderExceptions::MemoryAccessError(
                "Section name too long: " + std::to_string(name.length()) +
                    " (max: " + std::to_string(MemoryConstants::MAX_SECTION_NAME_LENGTH) + ")",
                offset);
        }

        // Check for invalid characters in section name
        for (char c : name) {
            if (c < 32 || c > 126) {  // Non-printable ASCII
                throw ElfReaderExceptions::MemoryAccessError(
                    "Invalid character in section name at offset " + std::to_string(offset),
                    offset);
            }
        }
    }

    /**
     * @brief Get the total file size
     * @return File size in bytes
     */
    size_t getSize() const {
        return size_;
    }

    /**
     * @brief Get pointer to data
     * @return Pointer to memory data
     */
    const uint8_t* getData() const {
        return data_;
    }

private:
    /**
     * @brief Validate basic file constraints
     * @throws ElfFileError if constraints are violated
     */
    void validateBasicConstraints() const {
        if (size_ == 0) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::FileTooSmall,
                "Empty file",
                filename_);
        }

        if (size_ > MemoryConstants::MAX_FILE_SIZE) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::FileTooSmall,
                "File too large: " + std::to_string(size_) + " bytes " +
                    "(max: " + std::to_string(MemoryConstants::MAX_FILE_SIZE) + " bytes)",
                filename_);
        }

        if (!data_) {
            throw ElfReaderExceptions::ElfFileError(
                ElfReaderExceptions::ElfFileError::ErrorType::ReadError,
                "Null data pointer",
                filename_);
        }
    }
};

}  // namespace ElfReaderUtils

#endif  // ELF_MEMORY_VALIDATOR_H