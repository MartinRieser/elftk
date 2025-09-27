/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "CommandLineParser.h"
#include "ConfigValidator.h"
#include <getopt.h>
#include <cstring>
#include <iostream>

const std::unordered_map<std::string, CommandLineParser::OptionHandler>
CommandLineParser::OPTION_HANDLERS = CommandLineParser::initializeOptionHandlers();

CommandLineParser::ParseResult CommandLineParser::parse(int argc, char* argv[]) {
    ParseResult result;
    int opt;
    int option_index = 0;

    // Define long options structure
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"json", no_argument, 0, 0},
        {"verbose", no_argument, 0, 0},
        {"functions", no_argument, 0, 0},
        {"variables", no_argument, 0, 0},
        {"constants", no_argument, 0, 0},
        {"local-vars", no_argument, 0, 0},
        {"show-sections", no_argument, 0, 0},
        {"stack-layout", no_argument, 0, 0},
        {"memory-regions", no_argument, 0, 0},
        {"interrupt-vectors", no_argument, 0, 0},
        {"export", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    // Parse options
    while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0: {
                // Long option
                const char* option_name = long_options[option_index].name;
                if (!handleLongOption(option_name, optarg, result.config)) {
                    result.error_message = std::string("Unknown option: --") + option_name;
                    return result;
                }
                break;
            }
            case 'h':
                result.help_requested = true;
                result.should_exit = true;
                result.exit_code = 0;
                return result;
            case 'v':
                result.version_requested = true;
                result.should_exit = true;
                result.exit_code = 0;
                return result;
            case '?':
            default:
                result.error_message = "Invalid option. Use --help for usage information.";
                result.exit_code = 1;
                return result;
        }
    }

    // Get input file
    if (optind < argc) {
        result.config.inputFile = argv[optind];
    } else {
        result.error_message = "Error: Input file not specified.";
        result.exit_code = 1;
        return result;
    }

    // Check for extra arguments
    if (optind + 1 < argc) {
        result.error_message = "Error: Too many arguments. Only one input file is supported.";
        result.exit_code = 1;
        return result;
    }

    // Validate configuration
    std::string validation_error;
    if (!validateParsedConfig(result.config, validation_error)) {
        result.error_message = "Configuration error: " + validation_error;
        result.exit_code = 1;
        return result;
    }

    return result;
}

bool CommandLineParser::handleLongOption(const char* option_name, const char* optarg, Config& config) {
    auto it = OPTION_HANDLERS.find(option_name);
    if (it != OPTION_HANDLERS.end()) {
        it->second(config, optarg);
        return true;
    }
    return false;
}

bool CommandLineParser::validateParsedConfig(const Config& config, std::string& error) {
    return ConfigValidator::validate(config, error);
}

std::unordered_map<std::string, CommandLineParser::OptionHandler>
CommandLineParser::initializeOptionHandlers() {
    return {
        {"json", [](Config& cfg, const char*) {
            cfg.format = "json";
        }},
        {"verbose", [](Config& cfg, const char*) {
            cfg.verbosity = 1;
        }},
        {"functions", [](Config& cfg, const char*) {
            cfg.functionsOnly = true;
        }},
        {"variables", [](Config& cfg, const char*) {
            cfg.variablesOnly = true;
        }},
        {"constants", [](Config& cfg, const char*) {
            cfg.constantsOnly = true;
        }},
        {"local-vars", [](Config& cfg, const char*) {
            cfg.showLocalVariables = true;
        }},
        {"show-sections", [](Config& cfg, const char*) {
            cfg.showSections = true;
        }},
        {"stack-layout", [](Config& cfg, const char*) {
            cfg.showStackLayout = true;
        }},
        {"memory-regions", [](Config& cfg, const char*) {
            cfg.extractMemoryRegions = true;
        }},
        {"interrupt-vectors", [](Config& cfg, const char*) {
            cfg.extractInterruptVectors = true;
        }},
        {"export", [](Config& cfg, const char* arg) {
            if (arg) {
                cfg.exportFormat = arg;
            }
        }}
    };
}