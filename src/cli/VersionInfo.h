/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

/**
 * @file VersionInfo.h
 * @brief Centralized version and help information management
 *
 * This file provides a single source of truth for application version,
 * copyright, and help text formatting. Eliminates duplicate version
 * strings and provides consistent formatting across the application.
 *
 * @author elftk Project
 * @date 2025
 */

/**
 * @class VersionInfo
 * @brief Centralized version information and help text management
 *
 * Provides static methods for displaying version information and help text.
 * Ensures consistent formatting and eliminates duplicate version strings
 * throughout the codebase.
 *
 * ## Design Benefits:
 * - Single source of truth for version information
 * - Consistent formatting across all output
 * - Easy to update version information in one place
 * - Testable help text generation
 *
 * ## Usage:
 * ```cpp
 * VersionInfo::showVersion();
 * VersionInfo::showHelp("./elftk");
 * std::string version = VersionInfo::getVersionString();
 * ```
 */
class VersionInfo {
public:
    /// @brief Application version string
    static constexpr const char* VERSION = "2.2.0";

    /// @brief Copyright notice
    static constexpr const char* COPYRIGHT = "Copyright (c) 2025 - Licensed under Mozilla Public License 2.0";

    /// @brief License URL
    static constexpr const char* LICENSE_URL = "https://mozilla.org/MPL/2.0/";

    /// @brief Application name
    static constexpr const char* APP_NAME = "elftk";

    /**
     * @brief Get formatted version string
     * @return Complete version string with application name
     */
    static const char* getVersionString();

    /**
     * @brief Display application version and build information
     *
     * Outputs comprehensive version information including:
     * - Application name and version
     * - Copyright notice
     * - Build timestamp (if available)
     * - License information
     */
    static void showVersion();

    /**
     * @brief Display comprehensive help information
     *
     * Shows complete usage documentation including:
     * - Version information (via showVersion())
     * - Command-line syntax
     * - All available options organized by category
     * - Usage examples
     *
     * @param program_name Name of the executable (from argv[0])
     */
    static void showHelp(const char* program_name);

private:
    /**
     * @brief Format and display the options help section
     * @param program_name Name of the executable for examples
     */
    static void showOptionsHelp(const char* program_name);

    /**
     * @brief Display usage examples section
     * @param program_name Name of the executable for examples
     */
    static void showExamples(const char* program_name);
};