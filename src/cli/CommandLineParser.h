/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "../ElfReader.h"
#include <string>
#include <functional>
#include <unordered_map>

/**
 * @file CommandLineParser.h
 * @brief Modern command-line argument parsing for ELF Symbol Reader
 *
 * This file provides a robust, maintainable command-line parser that replaces
 * the fragile string-based option handling in main.cpp. Uses type-safe option
 * handlers and comprehensive validation.
 *
 * @author ELF Symbol Reader Project
 * @date 2025
 */

/**
 * @class CommandLineParser
 * @brief Type-safe command-line argument parser
 *
 * Provides modern C++ command-line parsing with:
 * - Type-safe option handlers using std::function
 * - Comprehensive error handling and validation
 * - Clear separation of parsing logic from main()
 * - Testable design with isolated components
 *
 * ## Design Benefits:
 * - **Maintainable**: No string comparisons, clear option mapping
 * - **Extensible**: Easy to add new options without code duplication
 * - **Testable**: Isolated parsing logic can be unit tested
 * - **Type Safe**: Compile-time checking of option handlers
 *
 * ## Usage:
 * ```cpp
 * auto result = CommandLineParser::parse(argc, argv);
 * if (result.should_exit) {
 *     return result.exit_code;
 * }
 * if (!result.error_message.empty()) {
 *     std::cerr << result.error_message << std::endl;
 *     return 1;
 * }
 * // Use result.config for analysis
 * ```
 */
class CommandLineParser {
public:
    /**
     * @brief Command-line parsing result
     */
    struct ParseResult {
        Config config;                  ///< Parsed configuration
        bool should_exit = false;       ///< Whether application should exit immediately
        int exit_code = 0;             ///< Exit code if should_exit is true
        std::string error_message;      ///< Error message if parsing failed
        bool help_requested = false;    ///< Whether help was requested
        bool version_requested = false; ///< Whether version was requested
    };

    /**
     * @brief Parse command-line arguments into configuration
     *
     * Processes argc/argv and returns a ParseResult containing either:
     * - Valid configuration for analysis
     * - Request to show help/version and exit
     * - Error message and appropriate exit code
     *
     * @param argc Number of command-line arguments
     * @param argv Array of command-line argument strings
     * @return ParseResult containing configuration or exit instructions
     *
     * ## Error Handling:
     * - Invalid options: Returns error with usage suggestion
     * - Missing arguments: Returns error with specific guidance
     * - Conflicting options: Returns error from ConfigValidator
     * - Help/version requests: Returns with should_exit=true, exit_code=0
     */
    static ParseResult parse(int argc, char* argv[]);

private:
    /// @brief Option handler function type
    using OptionHandler = std::function<void(Config&, const char*)>;

    /**
     * @brief Map of long option names to handler functions
     *
     * Uses std::function for type-safe option handling, eliminating
     * the fragile string comparison chains from the original code.
     */
    static const std::unordered_map<std::string, OptionHandler> OPTION_HANDLERS;

    /**
     * @brief Handle a long option with its argument
     *
     * @param option_name Name of the long option (without --)
     * @param optarg Option argument (may be nullptr)
     * @param config Configuration to modify
     * @return true if option was handled successfully
     */
    static bool handleLongOption(const char* option_name, const char* optarg, Config& config);

    /**
     * @brief Validate parsed configuration
     *
     * @param config Configuration to validate
     * @param error Output parameter for error message
     * @return true if configuration is valid
     */
    static bool validateParsedConfig(const Config& config, std::string& error);

    /**
     * @brief Initialize option handlers map
     * @return Map of option names to handler functions
     */
    static std::unordered_map<std::string, OptionHandler> initializeOptionHandlers();
};