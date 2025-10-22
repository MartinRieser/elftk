/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "CLI11Parser.h"
#include <regex>
#include "VersionInfo.h"

std::string
CompactFormatter::make_help(const CLI::App* app, std::string name, CLI::AppFormatMode mode) const {
    std::string help = CLI::Formatter::make_help(app, name, mode);

    // Remove the positionals section entirely
    size_t pos = help.find("\nPOSITIONALS:");
    if (pos != std::string::npos) {
        size_t end = help.find("\nOPTIONS:", pos);
        if (end != std::string::npos) {
            help.erase(pos, end - pos);
        }
    }

    // Reduce multiple blank lines to single blank line
    help = std::regex_replace(help, std::regex("\n\n\n+"), "\n\n");

    return help;
}

std::optional<Config> CLI11Parser::parse(int argc, char* argv[]) {
    Config config;

    CLI::App app{"elftk - ELF file tool kit for embedded software development", "elftk"};
    setupApp(app, config);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // CLI11 automatically handles help, version, and error messages
        // Return the exit code instead of calling std::exit for thread safety
        app.exit(e);  // This will print error message and exit status
        return std::nullopt;
    }

    return config;
}

void CLI11Parser::setupApp(CLI::App& app, Config& config) {
    // Configure formatter for clean output
    auto formatter = std::make_shared<CompactFormatter>();
    formatter->column_width(40);
    formatter->label("REQUIRED", "");
    app.formatter(formatter);

    // Strict argument parsing
    app.allow_extras(false);
    app.allow_config_extras(false);

    // Version and help flags
    app.set_version_flag("--version,-v", []() {
        VersionInfo::showVersion();
        return std::string{};
    });
    app.set_help_flag("--help,-h", "Show this help");

    // Required positional argument
    app.add_option("file", config.inputFile, "ELF file to analyze")
        ->required()
        ->check(CLI::ExistingFile);

    // Analysis mode options
    app.add_flag("--functions", config.functionsOnly, "Show functions only");
    app.add_flag("--variables", config.variablesOnly, "Show variables only");
    app.add_flag("--constants", config.constantsOnly, "Show constants only");
    app.add_flag("--memory-regions", config.extractMemoryRegions, "Show memory region mapping");
    app.add_flag(
        "--interrupt-vectors", config.extractInterruptVectors, "Show interrupt vector table");
    app.add_option("--export", config.exportFormat, "Export firmware (hex, s19, s28, s37, bin)")
        ->check(CLI::IsMember({"hex", "s19", "s28", "s37", "bin"}));

    // Output format options
    app.add_flag(
        "--json",
        [&config](bool flag) { config.format = flag ? "json" : "csv"; },
        "Output in JSON format (default: CSV)");
    app.add_flag(
           "--verbose",
           [&config](int64_t count) { config.verbosity = static_cast<int>(count); },
           "Show detailed information (use twice for more detail)")
        ->multi_option_policy(CLI::MultiOptionPolicy::Sum);
    app.add_flag("--show-sections", config.showSections, "Include section names in output");

    // Array expansion control
    app.add_option("--array-limit",
                   config.maxArrayExpansion,
                   "Maximum array elements to expand (default: 10)")
        ->check(CLI::PositiveNumber)
        ->default_val(10);
}