/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "../ElfReader.h"
#include <string>
#include <vector>

/**
 * @file ConfigValidator.h
 * @brief Configuration validation and conflict detection
 *
 * This file provides comprehensive validation of command-line configuration
 * options, detecting conflicts and invalid combinations before analysis begins.
 * Provides clear error messages to guide users.
 *
 * @author ELF Symbol Reader Project
 * @date 2025
 */

/**
 * @class ConfigValidator
 * @brief Validates configuration options and detects conflicts
 *
 * Provides comprehensive validation of Config objects to ensure:
 * - No conflicting options are specified
 * - Export formats are valid
 * - File paths are accessible
 * - Option combinations make sense
 *
 * ## Validation Categories:
 * - **Mutual Exclusion**: Options that cannot be used together
 * - **Format Validation**: Export formats, output formats
 * - **File Access**: Input file existence and readability
 * - **Logical Consistency**: Option combinations that make sense
 *
 * ## Usage:
 * ```cpp
 * Config config;
 * // ... populate config from command line ...
 *
 * std::string error;
 * if (!ConfigValidator::validate(config, error)) {
 *     std::cerr << "Configuration error: " << error << std::endl;
 *     return 1;
 * }
 * ```
 */
class ConfigValidator {
public:
    /**
     * @brief Validation result structure
     */
    struct ValidationResult {
        bool is_valid = true;           ///< Whether configuration is valid
        std::string error_message;      ///< Detailed error message if invalid
        std::vector<std::string> warnings; ///< Non-fatal warnings
    };

    /**
     * @brief Validate complete configuration
     *
     * Performs comprehensive validation of all configuration options,
     * checking for conflicts, invalid values, and logical inconsistencies.
     *
     * @param config Configuration to validate
     * @return ValidationResult with validation status and messages
     *
     * ## Validation Checks:
     * - Mutual exclusion of --functions, --variables, --constants
     * - Valid export format specifications
     * - Input file existence and readability
     * - Logical option combinations
     * - Format compatibility with requested features
     */
    static ValidationResult validate(const Config& config);

    /**
     * @brief Simple validation with error string (backward compatibility)
     *
     * @param config Configuration to validate
     * @param error Output parameter for error message
     * @return true if valid, false if errors found
     */
    static bool validate(const Config& config, std::string& error);

    /**
     * @brief Check for mutually exclusive options
     *
     * @param config Configuration to check
     * @param error Output parameter for error message
     * @return true if no conflicts, false if mutually exclusive options found
     */
    static bool validateMutualExclusion(const Config& config, std::string& error);

    /**
     * @brief Validate export format specification
     *
     * @param format Export format to validate
     * @param error Output parameter for error message
     * @return true if format is valid, false otherwise
     */
    static bool validateExportFormat(const std::string& format, std::string& error);

    /**
     * @brief Validate input file accessibility
     *
     * @param filepath Path to input file
     * @param error Output parameter for error message
     * @return true if file is accessible, false otherwise
     */
    static bool validateInputFile(const std::string& filepath, std::string& error);

    /**
     * @brief Check logical consistency of option combinations
     *
     * @param config Configuration to check
     * @param warnings Output parameter for warning messages
     * @return true always (generates warnings, not errors)
     */
    static bool checkLogicalConsistency(const Config& config, std::vector<std::string>& warnings);

    /**
     * @brief Get list of valid export formats
     * @return Vector of supported export format strings
     */
    static std::vector<std::string> getValidExportFormats();

private:
    /// @brief Valid export formats
    static const std::vector<std::string> VALID_EXPORT_FORMATS;
};