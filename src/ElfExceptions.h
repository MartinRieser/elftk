/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
 
/**
 * @file ElfExceptions.h
 * @brief Custom exception hierarchy for ELF parsing errors
 * 
 * This file provides a hierarchical exception system for better error handling
 * and debugging in the ELF Symbol Reader. Each exception type provides specific
 * context and suggestions for resolving common issues.
 * 
 * Exception Hierarchy:
 * - ElfParsingError (base)
 *   - ElfFileError (file access and validation)
 *   - DwarfParsingError (DWARF debug information)
 *   - SymbolResolutionError (symbol table processing)
 *   - MemoryAccessError (bounds checking and memory)
 *
 * Usage Examples:
 * @code
 * try {
 *     ElfReader reader(filename);
 *     reader.analyzeMemberParameters();
 * } catch (const ElfFileError& e) {
 *     std::cerr << "File error: " << e.getDetailedMessage() << std::endl;
 *     if (e.getErrorType() == ElfFileError::ErrorType::FileNotFound) {
 *         // Handle file not found specifically
 *     }
 * } catch (const DwarfParsingError& e) {
 *     std::cerr << "DWARF error: " << e.getDetailedMessage() << std::endl;
 * } catch (const ElfParsingError& e) {
 *     std::cerr << "General ELF error: " << e.getDetailedMessage() << std::endl;
 * }
 * @endcode
 * 
 * @author ELF Symbol Reader Team
 * @date 2025
 */

#ifndef ELF_EXCEPTIONS_H
#define ELF_EXCEPTIONS_H

#include <stdexcept>
#include <string>
#include <sstream>
#include <iomanip>

namespace ElfReaderExceptions {

/**
 * @brief Base exception class for all ELF parsing related errors
 * 
 * This is the root of the exception hierarchy. All ELF-related errors
 * inherit from this class, allowing for catch-all exception handling
 * while maintaining specific error type information.
 */
class ElfParsingError : public std::runtime_error {
public:
    /**
     * @brief Construct exception with error message
     * @param message Descriptive error message
     */
    explicit ElfParsingError(const std::string& message)
        : std::runtime_error(message), context_("") {}

    /**
     * @brief Construct exception with error message and context
     * @param message Descriptive error message
     * @param context Additional context information (filename, section, etc.)
     */
    ElfParsingError(const std::string& message, const std::string& context)
        : std::runtime_error(message), context_(context) {}

    /**
     * @brief Copy constructor
     */
    ElfParsingError(const ElfParsingError&) = default;

    /**
     * @brief Copy assignment operator
     */
    ElfParsingError& operator=(const ElfParsingError&) = default;

    /**
     * @brief Move constructor
     */
    ElfParsingError(ElfParsingError&&) noexcept = default;

    /**
     * @brief Move assignment operator
     */
    ElfParsingError& operator=(ElfParsingError&&) noexcept = default;
    
    /**
     * @brief Get additional context information
     * @return Context string (may be empty)
     */
    const std::string& getContext() const noexcept { return context_; }
    
    /**
     * @brief Get formatted error message with context
     * @return Complete error description including context
     */
    virtual std::string getDetailedMessage() const {
        if (context_.empty()) {
            return what();
        }
        return std::string(what()) + " (Context: " + context_ + ")";
    }

protected:
    std::string context_;  ///< Additional context information
};

/**
 * @brief File access and validation errors
 * 
 * Thrown when there are issues opening, reading, or validating ELF files.
 * Common causes include file permissions, corrupted files, or non-ELF binaries.
 */
class ElfFileError : public ElfParsingError {
public:
    enum class ErrorType {
        FileNotFound,    ///< File does not exist
        PermissionDenied,///< Cannot read file due to permissions
        FileTooSmall,    ///< File smaller than minimum ELF size
        InvalidFormat,   ///< File is not a valid ELF format
        ReadError       ///< I/O error during file reading
    };
    
    /**
     * @brief Construct file error with type and message
     * @param type Specific type of file error
     * @param message Error description
     * @param filename File path that caused the error
     */
    ElfFileError(ErrorType type, const std::string& message, const std::string& filename = "")
        : ElfParsingError(message, filename), errorType_(type) {}
    
    /**
     * @brief Get the specific file error type
     * @return Error type enumeration
     */
    ErrorType getErrorType() const noexcept { return errorType_; }
    
    /**
     * @brief Get user-friendly suggestion for resolving the error
     * @return Suggestion string for fixing the issue
     */
    std::string getSuggestion() const noexcept {
        switch (errorType_) {
            case ErrorType::FileNotFound:
                return "Check that the file path is correct and the file exists";
            case ErrorType::PermissionDenied:
                return "Verify that you have read permissions for the file";
            case ErrorType::FileTooSmall:
                return "Ensure the file is a complete ELF binary and not truncated";
            case ErrorType::InvalidFormat:
                return "Verify that the file is an ELF binary (try 'file' command)";
            case ErrorType::ReadError:
                return "Check for disk errors or file system issues";
            default:
                return "Contact support with the error details";
        }
    }
    
    std::string getDetailedMessage() const override {
        std::string msg = ElfParsingError::getDetailedMessage();
        return msg + "\nSuggestion: " + getSuggestion();
    }

    /**
     * @brief Factory method for file not found errors
     * @param filename Path to the missing file
     * @return ElfFileError configured for file not found
     */
    static ElfFileError fileNotFound(const std::string& filename) {
        return ElfFileError(ErrorType::FileNotFound,
                           "File not found: " + filename, filename);
    }

    /**
     * @brief Factory method for permission denied errors
     * @param filename Path to the inaccessible file
     * @return ElfFileError configured for permission denied
     */
    static ElfFileError permissionDenied(const std::string& filename) {
        return ElfFileError(ErrorType::PermissionDenied,
                           "Permission denied: " + filename, filename);
    }

    /**
     * @brief Factory method for invalid format errors
     * @param filename Path to the invalid file
     * @return ElfFileError configured for invalid format
     */
    static ElfFileError invalidFormat(const std::string& filename) {
        return ElfFileError(ErrorType::InvalidFormat,
                           "Invalid ELF format: " + filename, filename);
    }

private:
    ErrorType errorType_;
};

/**
 * @brief DWARF debug information parsing errors
 * 
 * Thrown when there are issues processing DWARF debug information.
 * This includes libdwarf API errors, malformed DWARF data, or missing debug sections.
 */
class DwarfParsingError : public ElfParsingError {
public:
    /**
     * @brief Construct DWARF parsing error
     * @param message Error description
     * @param dwarfSection DWARF section name (optional)
     */
    explicit DwarfParsingError(const std::string& message, const std::string& dwarfSection = "")
        : ElfParsingError(message, dwarfSection) {}
    
    std::string getDetailedMessage() const override {
        std::string msg = ElfParsingError::getDetailedMessage();
        if (context_.empty()) {
            return msg + "\nSuggestion: Ensure the binary was compiled with debug information (-g flag)";
        }
        return msg + "\nSuggestion: Check DWARF section '" + context_ + "' for corruption";
    }
};

/**
 * @brief Symbol table processing errors
 * 
 * Thrown when there are issues processing symbol tables, resolving symbols,
 * or handling symbol name lookups.
 */
class SymbolResolutionError : public ElfParsingError {
public:
    /**
     * @brief Construct symbol resolution error
     * @param message Error description
     * @param symbolName Symbol name that caused the error (optional)
     */
    explicit SymbolResolutionError(const std::string& message, const std::string& symbolName = "")
        : ElfParsingError(message, symbolName) {}
    
    std::string getDetailedMessage() const override {
        std::string msg = ElfParsingError::getDetailedMessage();
        if (!context_.empty()) {
            return msg + "\nFailed while processing symbol: " + context_ + 
                   "\nSuggestion: Check symbol table integrity and string table references";
        }
        return msg + "\nSuggestion: Check symbol table integrity and string table references";
    }
};

/**
 * @brief Memory access and bounds checking errors
 * 
 * Thrown when there are memory access violations, attempts to read beyond
 * file boundaries, or other memory-related issues during ELF parsing.
 */
class MemoryAccessError : public ElfParsingError {
public:
    /**
     * @brief Construct memory access error
     * @param message Error description
     * @param offset Problematic memory offset (optional)
     */
    explicit MemoryAccessError(const std::string& message, size_t offset = 0)
        : ElfParsingError(message), offset_(offset) {}
    
    /**
     * @brief Get the problematic memory offset
     * @return Offset where the error occurred (0 if not specified)
     */
    size_t getOffset() const noexcept { return offset_; }
    
    std::string getDetailedMessage() const override {
        std::string msg = what();
        if (offset_ > 0) {
            std::ostringstream oss;
            oss << " at offset 0x" << std::hex << std::uppercase << offset_;
            msg += oss.str();
        }
        return msg + "\nSuggestion: File may be corrupted or truncated";
    }

private:
    size_t offset_;  ///< Memory offset where error occurred
};

} // namespace ElfReaderExceptions

#endif // ELF_EXCEPTIONS_H