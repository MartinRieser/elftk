/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include "../ElfReader.h"
#include <CLI11.hpp>
#include <optional>

/**
 * @file CLI11Parser.h
 * @brief Modern CLI parsing using CLI11 library
 *
 * This replaces the custom CommandLineParser with the robust CLI11 library,
 * providing better error handling, automatic help generation, and standard
 * CLI behavior.
 */

/**
 * @brief Compact formatter that removes positionals section and reduces blank lines
 */
class CompactFormatter : public CLI::Formatter {
public:
    std::string make_help(const CLI::App *app, std::string name, CLI::AppFormatMode mode) const override;
};

class CLI11Parser {
public:
    /**
     * @brief Parse command line arguments using CLI11
     * @param argc Number of arguments
     * @param argv Array of argument strings
     * @return std::optional<Config> with parsed options, or std::nullopt if parsing fails
     */
    static std::optional<Config> parse(int argc, char* argv[]);

private:
    static void setupApp(CLI::App& app, Config& config);
};