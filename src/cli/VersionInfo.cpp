/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "VersionInfo.h"
#include <iostream>

/// @brief Build date macro (set by build system)
#ifndef BUILD_DATE
#define BUILD_DATE "unknown"
#endif

/// @brief Build time macro (set by build system)
#ifndef BUILD_TIME
#define BUILD_TIME "unknown"
#endif

const char* VersionInfo::getVersionString() {
    static std::string version_string = std::string(APP_NAME) + " v" + VERSION;
    return version_string.c_str();
}

void VersionInfo::showVersion() {
    std::cout << getVersionString() << std::endl;
    std::cout << COPYRIGHT << std::endl;
    std::cout << "Build Date: " << BUILD_DATE << std::endl;
    std::cout << "Build Time: " << BUILD_TIME << std::endl;
    std::cout << std::endl;
    std::cout << "License: " << LICENSE_URL << std::endl;
    std::cout << "Source:  Available under MPL-2.0 license terms" << std::endl;
    std::cout << std::endl;
}

void VersionInfo::showHelp(const char* program_name) {
    showVersion();
    std::cout << "Usage: " << program_name << " [OPTIONS] <elf_file>" << std::endl;
    std::cout << std::endl;

    showOptionsHelp(program_name);
    showExamples(program_name);
}

void VersionInfo::showOptionsHelp(const char* /* program_name */) {
    std::cout << "Basic Options:" << std::endl;
    std::cout << "  -h, --help           Show this help" << std::endl;
    std::cout << "  -v, --version        Show version" << std::endl;
    std::cout << "      --json           Output in JSON format (default: CSV)" << std::endl;
    std::cout << "      --verbose        Show detailed information" << std::endl;
    std::cout << std::endl;

    std::cout << "What to Show:" << std::endl;
    std::cout << "      --functions      Show functions only" << std::endl;
    std::cout << "      --variables      Show variables only" << std::endl;
    std::cout << "      --constants      Show constants only" << std::endl;
    std::cout << "      --local-vars     Show local variables within functions" << std::endl;
    std::cout << "      --show-sections  Include section names in output" << std::endl;
    std::cout << std::endl;

    std::cout << "Memory Layout:" << std::endl;
    std::cout << "      --stack-layout     Show function stack layouts" << std::endl;
    std::cout << "      --memory-regions   Show memory region mapping" << std::endl;
    std::cout << "      --interrupt-vectors Show interrupt vector table" << std::endl;
    std::cout << std::endl;

    std::cout << "Binary Export:" << std::endl;
    std::cout << "      --export=FORMAT  Export format: hex, s19, s28, s37, bin" << std::endl;
    std::cout << std::endl;
}

void VersionInfo::showExamples(const char* program_name) {
    std::cout << "Examples:" << std::endl;
    std::cout << "  Basic analysis:" << std::endl;
    std::cout << "    " << program_name << " firmware.elf" << std::endl;
    std::cout << std::endl;

    std::cout << "  Show specific information:" << std::endl;
    std::cout << "    " << program_name << " --json --constants firmware.elf" << std::endl;
    std::cout << "    " << program_name << " --functions --verbose firmware.elf" << std::endl;
    std::cout << "    " << program_name << " --local-vars --show-sections firmware.elf" << std::endl;
    std::cout << std::endl;

    std::cout << "  Memory analysis:" << std::endl;
    std::cout << "    " << program_name << " --memory-regions firmware.elf" << std::endl;
    std::cout << "    " << program_name << " --interrupt-vectors firmware.elf" << std::endl;
    std::cout << "    " << program_name << " --stack-layout --verbose firmware.elf" << std::endl;
    std::cout << std::endl;

    std::cout << "  Binary export:" << std::endl;
    std::cout << "    " << program_name << " --export=hex firmware.elf" << std::endl;
    std::cout << "    " << program_name << " --export=s28 --verbose firmware.elf" << std::endl;
    std::cout << std::endl;
}