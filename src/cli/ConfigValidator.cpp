/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ConfigValidator.h"
#include <algorithm>
#include <fstream>
#include <sstream>

const std::vector<std::string> ConfigValidator::VALID_EXPORT_FORMATS = {
    "hex", "s19", "s28", "s37", "bin"
};

ConfigValidator::ValidationResult ConfigValidator::validate(const Config& config) {
    ValidationResult result;
    std::string error;

    // Check mutual exclusion
    if (!validateMutualExclusion(config, error)) {
        result.is_valid = false;
        result.error_message = error;
        return result;
    }

    // Validate export format
    if (!config.exportFormat.empty()) {
        if (!validateExportFormat(config.exportFormat, error)) {
            result.is_valid = false;
            result.error_message = error;
            return result;
        }
    }

    // Validate input file
    if (!config.inputFile.empty()) {
        if (!validateInputFile(config.inputFile, error)) {
            result.is_valid = false;
            result.error_message = error;
            return result;
        }
    }

    // Check logical consistency (warnings only)
    checkLogicalConsistency(config, result.warnings);

    return result;
}

bool ConfigValidator::validate(const Config& config, std::string& error) {
    ValidationResult result = validate(config);
    if (!result.is_valid) {
        error = result.error_message;
        return false;
    }
    return true;
}

bool ConfigValidator::validateMutualExclusion(const Config& config, std::string& error) {
    // Count exclusive "what to show" options
    int exclusive_count = 0;
    std::vector<std::string> active_options;

    if (config.functionsOnly) {
        exclusive_count++;
        active_options.push_back("--functions");
    }
    if (config.variablesOnly) {
        exclusive_count++;
        active_options.push_back("--variables");
    }
    if (config.constantsOnly) {
        exclusive_count++;
        active_options.push_back("--constants");
    }

    if (exclusive_count > 1) {
        std::ostringstream oss;
        oss << "Cannot specify multiple exclusive options: ";
        for (size_t i = 0; i < active_options.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << active_options[i];
        }
        oss << ". Choose only one of --functions, --variables, or --constants.";
        error = oss.str();
        return false;
    }

    // Check for other logical conflicts
    if (!config.exportFormat.empty() && (config.functionsOnly || config.variablesOnly || config.constantsOnly)) {
        error = "Binary export (--export) cannot be combined with specific analysis options (--functions, --variables, --constants). Use basic analysis for export.";
        return false;
    }

    return true;
}

bool ConfigValidator::validateExportFormat(const std::string& format, std::string& error) {
    if (std::find(VALID_EXPORT_FORMATS.begin(), VALID_EXPORT_FORMATS.end(), format) == VALID_EXPORT_FORMATS.end()) {
        std::ostringstream oss;
        oss << "Invalid export format '" << format << "'. Valid options are: ";
        for (size_t i = 0; i < VALID_EXPORT_FORMATS.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << VALID_EXPORT_FORMATS[i];
        }
        error = oss.str();
        return false;
    }
    return true;
}

bool ConfigValidator::validateInputFile(const std::string& filepath, std::string& error) {
    if (filepath.empty()) {
        error = "Input file path is empty";
        return false;
    }

    // Check if file exists and is readable
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        error = "Cannot open input file '" + filepath + "'. Please check that the file exists and is readable.";
        return false;
    }

    // Check file size (should not be empty)
    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    if (file_size <= 0) {
        error = "Input file '" + filepath + "' is empty or cannot determine file size.";
        return false;
    }

    return true;
}

bool ConfigValidator::checkLogicalConsistency(const Config& config, std::vector<std::string>& warnings) {
    // Check for potentially inefficient combinations
    if (config.extractMemoryRegions && config.extractInterruptVectors) {
        warnings.push_back("Both --memory-regions and --interrupt-vectors specified. Output may be verbose.");
    }

    if (!config.exportFormat.empty() && config.verbosity > 0) {
        warnings.push_back("--verbose has no effect with binary export (--export). Export produces binary data only.");
    }

    return true;
}

std::vector<std::string> ConfigValidator::getValidExportFormats() {
    return VALID_EXPORT_FORMATS;
}