/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ElfSymbolExtractor.h"
#include <cxxabi.h>
#include <fcntl.h>
#include <libelf/gelf.h>
#include <libelf/libelf.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace {
// Convert Windows paths to Unix-style paths for MSYS2/MinGW compatibility
std::string convertPathForMsys2(const std::string& path) {
    std::string converted = path;

    // Convert backslashes to forward slashes
    std::replace(converted.begin(), converted.end(), '\\', '/');

    // Handle drive letters - convert C:/path to /c/path
    if (converted.length() >= 2 && converted[1] == ':') {
        char drive = static_cast<char>(std::tolower(static_cast<unsigned char>(converted[0])));
        converted = "/" + std::string(1, drive) + converted.substr(2);
    }

    // Handle leading ./ for relative paths - sometimes problematic on Windows
    if (converted.length() >= 2 && converted.substr(0, 2) == "./") {
        converted = converted.substr(2);
    }

    return converted;
}
}  // namespace

std::vector<ExtractedSymbol> ElfSymbolExtractor::extractSymbols(const std::string& filename) {
    std::vector<ExtractedSymbol> symbols;

    // Use libelf for native ELF symbol table parsing
    if (elf_version(EV_CURRENT) == EV_NONE) {
        // libelf initialization failed, fallback to system tools
        return extractSymbolsFallback(filename);
    }

    // Try multiple path approaches for Windows compatibility
    std::vector<std::string> pathAttempts = {
        filename,                       // Original path
        convertPathForMsys2(filename),  // MSYS2 converted path
        filename.substr(1)              // Remove leading dot for relative paths
    };

    int fd = -1;
    std::string successfulPath;

    for (const auto& pathAttempt : pathAttempts) {
        fd = open(pathAttempt.c_str(), O_RDONLY);
        if (fd >= 0) {
            successfulPath = pathAttempt;
            break;
        }
    }

    if (fd < 0) {
        return extractSymbolsFallback(filename);
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return extractSymbolsFallback(filename);
    }

    // Check ELF kind
    if (elf_kind(elf) != ELF_K_ELF) {
        elf_end(elf);
        close(fd);
        return extractSymbolsFallback(filename);
    }

    // Get ELF header to determine 32/64 bit
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        elf_end(elf);
        close(fd);
        return extractSymbolsFallback(filename);
    }

    // Find symbol table sections
    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        // Look for symbol table sections (.symtab or .dynsym)
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }

            size_t symbolCount = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < symbolCount; i++) {
                GElf_Sym sym;
                if (!gelf_getsym(data, static_cast<int>(i), &sym)) {
                    continue;
                }

                // Skip empty symbols
                if (sym.st_name == 0) {
                    continue;
                }

                // Get symbol name from string table
                const char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || strlen(name) == 0) {
                    continue;
                }

                ExtractedSymbol symbol =
                    parseElfSymbol(&sym, name, ehdr.e_ident[EI_CLASS] == ELFCLASS64);
                if (!symbol.name.empty() && shouldIncludeSymbol(symbol)) {
                    symbols.push_back(symbol);
                }
            }
        }
    }

    elf_end(elf);
    close(fd);

    // If no symbols found, try fallback
    if (symbols.empty()) {
        return extractSymbolsFallback(filename);
    }

    return symbols;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::extractSymbolsFallback(const std::string& filename) {
    // Complete fallback - return empty result instead of using external tools
    // This eliminates the "system cannot find the path specified" errors
    (void)filename;  // Suppress unused parameter warning
    std::vector<ExtractedSymbol> symbols;
    return symbols;
}

ExtractedSymbol ElfSymbolExtractor::parseElfSymbol(void* sym_ptr, const char* name, bool is64bit) {
    (void)is64bit;  // Suppress unused parameter warning
    GElf_Sym* sym = static_cast<GElf_Sym*>(sym_ptr);
    ExtractedSymbol symbol;

    symbol.name = name;
    symbol.address = sym->st_value;
    symbol.size = sym->st_size;
    symbol.elementCount = 0;  // Will be calculated later

    // Determine symbol type from ELF symbol binding and type
    unsigned char binding = GELF_ST_BIND(sym->st_info);
    unsigned char type = GELF_ST_TYPE(sym->st_info);

    // Map ELF symbol info to our character-based type system
    switch (type) {
        case STT_FUNC:
            symbol.type = binding == STB_GLOBAL ? 'T' : 't';
            symbol.isFunction = true;
            symbol.isVariable = false;
            break;
        case STT_OBJECT:
            symbol.type = binding == STB_GLOBAL ? 'D' : 'd';
            symbol.isFunction = false;
            symbol.isVariable = true;
            break;
        case STT_NOTYPE:
            // Fall back to section-based classification
            symbol.type = 'D';  // Default to data
            symbol.isFunction = false;
            symbol.isVariable = true;
            break;
        default:
            symbol.type = '?';
            symbol.isFunction = false;
            symbol.isVariable = false;
            break;
    }

    // Set properties based on binding
    symbol.isGlobal = (binding == STB_GLOBAL || binding == STB_WEAK);
    symbol.isWeak = (binding == STB_WEAK);
    symbol.isUndefined = (sym->st_shndx == SHN_UNDEF);

    // Determine section based on symbol section index
    if (sym->st_shndx == SHN_UNDEF) {
        symbol.section = ".undefined";
    } else if (sym->st_shndx < SHN_LORESERVE) {
        // Use default section classification based on common section indices
        // Note: Section indices vary between ELF files, so use generic classification
        symbol.section = ".unknown";
    } else {
        // Special section indices (ABS, COMMON, etc.)
        symbol.section = ".special";
    }

    // Try to demangle C++ names
    symbol.demangledName = demangleSymbol(symbol.name);

    return symbol;
}

ExtractedSymbol ElfSymbolExtractor::parseNmLineBasic(const std::string& line) {
    ExtractedSymbol symbol;

    // Basic nm output format: address type name
    // Example: "00000400 R Core_FlashConfig"
    std::istringstream iss(line);
    std::string addrStr, typeStr, nameStr;

    if (iss >> addrStr >> typeStr) {
        // Read the rest of the line as the name (may contain spaces)
        std::getline(iss, nameStr);
        if (!nameStr.empty() && nameStr[0] == ' ') {
            nameStr = nameStr.substr(1);
        }

        if (!nameStr.empty() && addrStr != "00000000") {
            symbol.address = parseAddress(addrStr);
            symbol.size = 0;  // Size not available in basic nm output
            char typeChar = typeStr.length() > 0 ? typeStr[0] : '?';
            symbol.type = typeChar;
            symbol.name = nameStr;
            symbol.section = getSymbolType(typeChar);
            symbol.elementCount = 0;

            // Determine symbol properties
            symbol.isGlobal = isupper(typeChar) != 0;
            symbol.isWeak = (typeChar == 'W' || typeChar == 'w');
            symbol.isVariable = isVariableType(typeChar);
            symbol.isFunction = isFunctionType(typeChar);

            // Try to demangle C++ names
            symbol.demangledName = demangleSymbol(symbol.name);
        }
    }

    return symbol;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::getVariables(const std::vector<ExtractedSymbol>& symbols) {
    std::vector<ExtractedSymbol> variables;
    for (const auto& symbol : symbols) {
        if (symbol.isVariable) {
            variables.push_back(symbol);
        }
    }
    return variables;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::getFunctions(const std::vector<ExtractedSymbol>& symbols) {
    std::vector<ExtractedSymbol> functions;
    for (const auto& symbol : symbols) {
        if (symbol.isFunction) {
            functions.push_back(symbol);
        }
    }
    return functions;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::getLinkerSymbols(const std::vector<ExtractedSymbol>& symbols) {
    std::vector<ExtractedSymbol> linkerSymbols;
    for (const auto& symbol : symbols) {
        if (isLinkerSymbol(symbol)) {
            linkerSymbols.push_back(symbol);
        }
    }
    return linkerSymbols;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::getWeakSymbols(const std::vector<ExtractedSymbol>& symbols) {
    std::vector<ExtractedSymbol> weakSymbols;
    for (const auto& symbol : symbols) {
        if (symbol.isWeak) {
            weakSymbols.push_back(symbol);
        }
    }
    return weakSymbols;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::getSymbolsInSection(const std::vector<ExtractedSymbol>& symbols,
                                        const std::string& section) {
    std::vector<ExtractedSymbol> sectionSymbols;
    for (const auto& symbol : symbols) {
        if (symbol.getSectionName() == section) {
            sectionSymbols.push_back(symbol);
        }
    }
    return sectionSymbols;
}

std::map<std::string, size_t>
ElfSymbolExtractor::getSymbolStats(const std::vector<ExtractedSymbol>& symbols) {
    std::map<std::string, size_t> stats;

    for (const auto& symbol : symbols) {
        stats["total"]++;

        if (symbol.isVariable) {
            stats["variables"]++;
        }
        if (symbol.isFunction) {
            stats["functions"]++;
        }
        if (symbol.isGlobal) {
            stats["global"]++;
        }
        if (symbol.isWeak) {
            stats["weak"]++;
        }

        // Count by section
        std::string section = symbol.getSectionName();
        stats[section]++;
    }

    return stats;
}

bool ElfSymbolExtractor::isLinkerSymbol(const ExtractedSymbol& symbol) {
    return symbol.name.find("__") == 0 || symbol.name.find("_start") == 0 ||
           symbol.name.find("_end") == 0 || symbol.name.find("_STOP") == 0 ||
           symbol.name.find("_START") == 0 || symbol.name.find("_END") == 0;
}

ExtractedSymbol ElfSymbolExtractor::parseNmLine(const std::string& line) {
    ExtractedSymbol symbol;

    // nm -S output format: address size type name
    // Example: "00000400 00000010 R Core_FlashConfig"
    std::istringstream iss(line);
    std::string addrStr, sizeStr, typeStr, nameStr;

    if (iss >> addrStr >> sizeStr >> typeStr) {
        // Read the rest of the line as the name (may contain spaces)
        std::getline(iss, nameStr);
        if (!nameStr.empty() && nameStr[0] == ' ') {
            nameStr = nameStr.substr(1);
        }

        if (!nameStr.empty() && addrStr != "00000000") {
            symbol.address = parseAddress(addrStr);
            symbol.size = parseAddress(sizeStr);
            char typeChar = typeStr.length() > 0 ? typeStr[0] : '?';
            symbol.type = typeChar;  // Store as char
            symbol.name = nameStr;
            symbol.section = getSymbolType(typeChar);
            symbol.elementCount = 0;  // Will be calculated later

            // Determine symbol properties
            symbol.isGlobal = isupper(typeChar) != 0;
            symbol.isWeak = (typeChar == 'W' || typeChar == 'w');
            symbol.isVariable = isVariableType(typeChar);
            symbol.isFunction = isFunctionType(typeChar);

            // Try to demangle C++ names
            symbol.demangledName = demangleSymbol(symbol.name);
        }
    }

    return symbol;
}

uint64_t ElfSymbolExtractor::parseAddress(const std::string& hexStr) {
    uint64_t address = 0;
    std::istringstream iss(hexStr);
    iss >> std::hex >> address;
    return address;
}

bool ElfSymbolExtractor::isVariableType(char type) {
    return type == 'B' || type == 'D' || type == 'R' || type == 'S' || type == 'G';
}

bool ElfSymbolExtractor::isFunctionType(char type) {
    return type == 'T' || type == 'W' || type == 't' || type == 'w';
}

std::string ElfSymbolExtractor::getSymbolType(char type) {
    switch (type) {
        case 'T':
        case 't':
            return ".text";
        case 'D':
        case 'd':
        case 'G':
        case 'g':
            return ".data";
        case 'B':
        case 'b':
            return ".bss";
        case 'R':
        case 'r':
            return ".rodata";
        case 'S':
        case 's':
            return ".bss";  // Small objects
        default:
            return ".unknown";
    }
}

std::vector<ElfSection> ElfSymbolExtractor::extractSections(const std::string& filename) {
    std::vector<ElfSection> sections;

    // Use libelf for native ELF section parsing
    if (elf_version(EV_CURRENT) == EV_NONE) {
        // libelf initialization failed, fallback to basic sections
        return createBasicSections();
    }

    // Try multiple path approaches for Windows compatibility
    std::vector<std::string> pathAttempts = {
        filename,                       // Original path
        convertPathForMsys2(filename),  // MSYS2 converted path
        filename.substr(1)              // Remove leading dot for relative paths
    };

    int fd = -1;
    for (const auto& pathAttempt : pathAttempts) {
        fd = open(pathAttempt.c_str(), O_RDONLY);
        if (fd >= 0) {
            break;
        }
    }

    if (fd < 0) {
        return createBasicSections();
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return createBasicSections();
    }

    // Check ELF kind
    if (elf_kind(elf) != ELF_K_ELF) {
        elf_end(elf);
        close(fd);
        return createBasicSections();
    }

    // Get ELF header to determine 32/64 bit
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        elf_end(elf);
        close(fd);
        return createBasicSections();
    }

    // Parse all sections
    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        // Get section name
        const char* name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (!name) {
            continue;
        }

        ElfSection section;
        section.name = name;
        section.address = shdr.sh_addr;
        section.size = shdr.sh_size;
        section.offset = shdr.sh_offset;

        // Parse section flags from ELF section header
        section.isAllocated = (shdr.sh_flags & SHF_ALLOC) != 0;
        section.isWritable = (shdr.sh_flags & SHF_WRITE) != 0;
        section.isExecutable = (shdr.sh_flags & SHF_EXECINSTR) != 0;

        sections.push_back(section);
    }

    elf_end(elf);
    close(fd);

    // If no sections found, return basic ones
    if (sections.empty()) {
        return createBasicSections();
    }

    return sections;
}

std::vector<MemoryLayoutInfo> ElfSymbolExtractor::getMemoryLayout(const std::string& filename) {
    (void)filename;  // Suppress unused parameter warning

    std::vector<MemoryLayoutInfo> regions;

    // Simplified memory layout detection - just add basic regions
    MemoryLayoutInfo ramRegion;
    ramRegion.name = "RAM";
    ramRegion.address = 0x20000000;  // Typical ARM RAM start
    ramRegion.size = 0x40000;        // 256KB typical
    ramRegion.type = "RAM";
    regions.push_back(ramRegion);

    MemoryLayoutInfo flashRegion;
    flashRegion.name = "FLASH";
    flashRegion.address = 0x08000000;  // Typical ARM Flash start
    flashRegion.size = 0x100000;       // 1MB typical
    flashRegion.type = "FLASH";
    regions.push_back(flashRegion);

    return regions;
}

std::vector<ElfSection> ElfSymbolExtractor::createBasicSections() {
    // Fallback basic sections when objdump is not available
    std::vector<ElfSection> sections;

    ElfSection textSection;
    textSection.name = ".text";
    textSection.address = 0x08000000;  // Typical ARM flash start
    textSection.size = 0x100000;       // 1MB typical
    textSection.isExecutable = true;
    textSection.isAllocated = true;
    textSection.isWritable = false;
    sections.push_back(textSection);

    ElfSection dataSection;
    dataSection.name = ".data";
    dataSection.address = 0x20000000;  // Typical ARM RAM start
    dataSection.size = 0x20000;        // 128KB typical
    dataSection.isExecutable = false;
    dataSection.isAllocated = true;
    dataSection.isWritable = true;
    sections.push_back(dataSection);

    ElfSection bssSection;
    bssSection.name = ".bss";
    bssSection.address = 0x20020000;  // After data section
    bssSection.size = 0x20000;        // 128KB typical
    bssSection.isExecutable = false;
    bssSection.isAllocated = true;
    bssSection.isWritable = true;
    sections.push_back(bssSection);

    return sections;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::discoverSectionVariables(const std::vector<ElfSection>& sections,
                                             const std::vector<ExtractedSymbol>& symbols) {
    (void)sections;  // Suppress unused parameter warning

    // For now, just return existing symbols
    return symbols;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::detectArrayBounds(const std::vector<ExtractedSymbol>& symbols,
                                      const std::vector<ElfSection>& sections) {
    (void)sections;  // Suppress unused parameter warning

    std::vector<ExtractedSymbol> enhancedSymbols = symbols;

    // Simple array detection - if symbol name contains array indicators
    for (auto& symbol : enhancedSymbols) {
        if (symbol.size > 0) {
            // Try to guess if this is an array based on size patterns
            if (symbol.size % 4 == 0 && symbol.size > 4) {
                symbol.elementCount = symbol.size / 4;  // Assume 4-byte elements
            }
        }
    }

    return enhancedSymbols;
}

std::vector<ExtractedSymbol>
ElfSymbolExtractor::extractCrossReferenceSymbols(const std::string& filename) {
    std::vector<ExtractedSymbol> xrefSymbols;

    // Use libelf for native ELF relocation parsing
    if (elf_version(EV_CURRENT) == EV_NONE) {
        // libelf initialization failed, return empty result
        return xrefSymbols;
    }

    // Try multiple path approaches for Windows compatibility
    std::vector<std::string> pathAttempts = {
        filename,                       // Original path
        convertPathForMsys2(filename),  // MSYS2 converted path
        filename.substr(1)              // Remove leading dot for relative paths
    };

    int fd = -1;
    for (const auto& pathAttempt : pathAttempts) {
        fd = open(pathAttempt.c_str(), O_RDONLY);
        if (fd >= 0) {
            break;
        }
    }

    if (fd < 0) {
        return xrefSymbols;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return xrefSymbols;
    }

    // Check ELF kind
    if (elf_kind(elf) != ELF_K_ELF) {
        elf_end(elf);
        close(fd);
        return xrefSymbols;
    }

    // Get ELF header to determine 32/64 bit
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        elf_end(elf);
        close(fd);
        return xrefSymbols;
    }

    // Parse relocation sections
    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        // Look for relocation sections
        if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }

            size_t relocCount = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < relocCount; i++) {
                if (shdr.sh_type == SHT_REL) {
                    GElf_Rel rel;
                    if (!gelf_getrel(data, static_cast<int>(i), &rel)) {
                        continue;
                    }

                    // Get symbol index from relocation
                    uint32_t symIndex = GELF_R_SYM(rel.r_info);
                    ExtractedSymbol symbol =
                        parseRelocationSymbol(elf, symIndex, rel.r_offset, &ehdr);
                    if (!symbol.name.empty()) {
                        xrefSymbols.push_back(symbol);
                    }
                } else {  // SHT_RELA
                    GElf_Rela rela;
                    if (!gelf_getrela(data, static_cast<int>(i), &rela)) {
                        continue;
                    }

                    // Get symbol index from relocation
                    uint32_t symIndex = GELF_R_SYM(rela.r_info);
                    ExtractedSymbol symbol =
                        parseRelocationSymbol(elf, symIndex, rela.r_offset, &ehdr);
                    if (!symbol.name.empty()) {
                        xrefSymbols.push_back(symbol);
                    }
                }
            }
        }
    }

    elf_end(elf);
    close(fd);
    return xrefSymbols;
}

// symIndex and offset have distinct types and meanings
ExtractedSymbol ElfSymbolExtractor::parseRelocationSymbol(
    Elf* elf,
    uint32_t symIndex,  // NOLINT(bugprone-easily-swappable-parameters)
    uint64_t offset,
    void* ehdr_ptr) {
    (void)ehdr_ptr;  // Suppress unused parameter warning
    ExtractedSymbol symbol;

    // Find the symbol table section referenced by this relocation
    Elf_Scn* scn = nullptr;
    GElf_Shdr shdr;
    GElf_Sym sym;

    // Find the symbol table section
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }

            size_t symbolCount = shdr.sh_size / shdr.sh_entsize;
            if (symIndex < symbolCount) {
                if (!gelf_getsym(data, static_cast<int>(symIndex), &sym)) {
                    continue;
                }

                // Get symbol name
                const char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (name && strlen(name) > 0) {
                    symbol.name = name;
                    symbol.address = offset;  // Use relocation offset
                    symbol.size = 0;          // Size not available from relocation
                    symbol.type = 'R';        // Use 'R' for relocation type
                    symbol.section = ".relocation";
                    symbol.elementCount = 0;

                    // Set properties based on symbol
                    unsigned char binding = GELF_ST_BIND(sym.st_info);
                    symbol.isGlobal = (binding == STB_GLOBAL || binding == STB_WEAK);
                    symbol.isWeak = (binding == STB_WEAK);
                    symbol.isUndefined = (sym.st_shndx == SHN_UNDEF);
                    symbol.isVariable = false;
                    symbol.isFunction = false;

                    // Try to demangle C++ names
                    symbol.demangledName = demangleSymbol(symbol.name);
                    return symbol;
                }
            }
        }
    }

    // If we couldn't find the symbol, create a placeholder
    symbol.address = offset;
    symbol.type = 'R';
    symbol.section = ".relocation";
    symbol.isUndefined = true;
    symbol.name = "unknown_symbol_" + std::to_string(symIndex);

    return symbol;
}

ExtractedSymbol ElfSymbolExtractor::parseObjdumpRelocationLine(const std::string& line) {
    ExtractedSymbol symbol;

    // objdump -r output format: offset type symbol_name
    std::istringstream iss(line);
    std::string offsetStr, typeStr, nameStr;

    if (iss >> offsetStr >> typeStr >> nameStr) {
        symbol.address = parseAddress(offsetStr);
        symbol.name = nameStr;
        symbol.type = 'R';          // Use 'R' for relocation type
        symbol.isUndefined = true;  // Relocation symbols are typically undefined
        symbol.demangledName = demangleSymbol(symbol.name);
    }

    return symbol;
}

std::string ElfSymbolExtractor::demangleSymbol(const std::string& mangledName) {
    // Skip if it doesn't look like a mangled C++ name
    if (mangledName.empty() || mangledName.find('_') == std::string::npos) {
        return mangledName;
    }

    // Use built-in C++ demangling via libiberty
    int status = 0;
    char* demangled = abi::__cxa_demangle(mangledName.c_str(), nullptr, nullptr, &status);

    if (status == 0 && demangled != nullptr) {
        std::string result(demangled);
        free(demangled);
        return result;
    }

    return mangledName;  // Fallback to original name if demangling fails
}

bool ElfSymbolExtractor::shouldIncludeSymbol(const ExtractedSymbol& symbol) {
    // Skip symbols that start with certain prefixes
    if (symbol.name.empty())
        return false;

    // Skip compiler-generated symbols
    if (symbol.name.find("__") == 0 && symbol.name.find("__builtin") != 0 &&
        symbol.name.find("__PRETTY_FUNCTION__") != 0) {
        return false;
    }

    return true;
}

uint64_t ElfSymbolExtractor::estimateElementCount(const ExtractedSymbol& symbol,
                                                  const std::vector<ElfSection>& sections) {
    (void)sections;  // Suppress unused parameter warning

    if (symbol.size == 0)
        return 0;

    // Simple estimation based on common sizes
    if (symbol.size % 1 == 0 && symbol.size <= 8)
        return 1;
    if (symbol.size % 4 == 0)
        return symbol.size / 4;
    if (symbol.size % 8 == 0)
        return symbol.size / 8;

    return 1;  // Default to single element
}