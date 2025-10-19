/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

// Forward declarations for libelf types (avoiding conflicts)
typedef struct Elf Elf;
typedef struct Elf_Scn Elf_Scn;

/**
 * @file ElfSymbolExtractor.h
 * @brief Simple ELF symbol extractor using system tools
 *
 * This class provides a simple way to extract ELF symbols using system tools
 * like nm and objdump, complementing the existing DWARF-based extraction.
 */

/**
 * @brief ELF section information
 */
struct ElfSection {
    std::string name;   ///< Section name (.data, .bss, .rodata, etc.)
    uint64_t address;   ///< Section load address
    uint64_t size;      ///< Section size in bytes
    uint64_t offset;    ///< Section offset in file
    std::string flags;  ///< Section flags (ALLOC, WRITE, EXEC, etc.)
    bool isAllocated;   ///< True if section occupies memory
    bool isWritable;    ///< True if section is writable
    bool isExecutable;  ///< True if section contains code

    /**
     * @brief Check if section contains data variables
     */
    bool isDataSection() const {
        return name == ".data" || name == ".bss" || name == ".rodata" || name.find(".data.") == 0 ||
               name.find(".bss.") == 0;
    }

    /**
     * @brief Check if section is in RAM
     */
    bool isInRAM() const {
        return isAllocated && isWritable;
    }

    /**
     * @brief Check if section is in Flash/ROM
     */
    bool isInFlash() const {
        return isAllocated && !isWritable;
    }
};

/**
 * @brief Memory layout information
 */
struct MemoryLayoutInfo {
    std::string name;        ///< Region name (RAM, FLASH, etc.)
    uint64_t address;        ///< Region start address
    uint64_t size;           ///< Region size in bytes
    uint64_t permissions;    ///< Region permissions (r/w/x)
    std::string type;        ///< Region type (LOAD, etc.)
};

/**
 * @brief Enhanced ELF symbol with additional information
 */
struct ExtractedSymbol {
    std::string name;        ///< Symbol name
    uint64_t address;        ///< Symbol address
    uint64_t size;           ///< Symbol size (if available)
    char type;               ///< Symbol type (function, variable, etc.)
    std::string section;     ///< Section name
    bool isGlobal;           ///< True if global symbol
    bool isWeak;             ///< True if weak symbol
    bool isUndefined;        ///< True if undefined symbol
    bool isVariable;         ///< True if variable/function
    bool isFunction;         ///< True if function
    std::string demangledName; ///< Demangled name (for C++ symbols)
    uint64_t elementCount;   ///< Number of elements (for arrays)

    ExtractedSymbol() : address(0), size(0), type('?'), isGlobal(false), isWeak(false),
                       isUndefined(false), isVariable(false), isFunction(false),
                       elementCount(0) {}

    /**
     * @brief Get the section name for this symbol
     */
    std::string getSectionName() const { return section; }

    /**
     * @brief Check if symbol is in data section
     */
    bool isInDataSection() const {
        return section == ".data" || section == ".bss" || section == ".rodata" ||
               section.find(".data.") == 0 || section.find(".bss.") == 0;
    }

    /**
     * @brief Check if symbol is an array
     */
    bool isArray() const {
        return elementCount > 1;
    }

    /**
     * @brief Get estimated element size
     */
    uint64_t getElementSize() const {
        return size > 0 && elementCount > 0 ? size / elementCount : 0;
    }
};

/**
 * @class ElfSymbolExtractor
 * @brief Extracts ELF symbols using system tools
 *
 * This class provides static methods for extracting ELF symbols using
 * system tools like nm and objdump, complementing the DWARF-based analysis.
 */
class ElfSymbolExtractor {
public:
    /**
     * @brief Extract all symbols from ELF file
     * @param filename Path to ELF file
     * @return Vector of extracted symbols
     */
    static std::vector<ExtractedSymbol> extractSymbols(const std::string& filename);

    /**
     * @brief Get variable symbols from extracted symbols
     * @param symbols Vector of extracted symbols
     * @return Vector of variable symbols
     */
    static std::vector<ExtractedSymbol> getVariables(const std::vector<ExtractedSymbol>& symbols);

    /**
     * @brief Get function symbols from extracted symbols
     * @param symbols Vector of extracted symbols
     * @return Vector of function symbols
     */
    static std::vector<ExtractedSymbol> getFunctions(const std::vector<ExtractedSymbol>& symbols);

    /**
     * @brief Get linker symbols from extracted symbols
     * @param symbols Vector of extracted symbols
     * @return Vector of linker symbols
     */
    static std::vector<ExtractedSymbol> getLinkerSymbols(const std::vector<ExtractedSymbol>& symbols);

    /**
     * @brief Get weak symbols from extracted symbols
     * @param symbols Vector of extracted symbols
     * @return Vector of weak symbols
     */
    static std::vector<ExtractedSymbol> getWeakSymbols(const std::vector<ExtractedSymbol>& symbols);

    /**
     * @brief Get symbols in specific section
     * @param symbols Vector of extracted symbols
     * @param section Section name
     * @return Vector of symbols in section
     */
    static std::vector<ExtractedSymbol> getSymbolsInSection(const std::vector<ExtractedSymbol>& symbols,
                                                            const std::string& section);

    /**
     * @brief Get symbol statistics
     * @param symbols Vector of extracted symbols
     * @return Map of symbol type to count
     */
    static std::map<std::string, size_t> getSymbolStats(const std::vector<ExtractedSymbol>& symbols);

    /**
     * @brief Extract ELF section information
     * @param filename Path to ELF file
     * @return Vector of ELF sections
     */
    static std::vector<ElfSection> extractSections(const std::string& filename);

    /**
     * @brief Get memory layout from ELF program headers
     * @param filename Path to ELF file
     * @return Vector of memory regions
     */
    static std::vector<MemoryLayoutInfo> getMemoryLayout(const std::string& filename);

    /**
     * @brief Discover variables in sections
     * @param sections Vector of ELF sections
     * @param symbols Vector of extracted symbols
     * @return Vector of discovered variables
     */
    static std::vector<ExtractedSymbol> discoverSectionVariables(
        const std::vector<ElfSection>& sections,
        const std::vector<ExtractedSymbol>& symbols);

    /**
     * @brief Detect array bounds and enhance symbols
     * @param symbols Vector of extracted symbols
     * @param sections Vector of ELF sections
     * @return Enhanced symbols with array information
     */
    static std::vector<ExtractedSymbol> detectArrayBounds(
        const std::vector<ExtractedSymbol>& symbols,
        const std::vector<ElfSection>& sections);

    /**
     * @brief Extract cross-reference symbols from relocation entries
     * @param filename Path to ELF file
     * @return Vector of cross-reference symbols
     */
    static std::vector<ExtractedSymbol> extractCrossReferenceSymbols(const std::string& filename);

    /**
     * @brief Demangle C++ symbol names
     * @param mangledName Mangled symbol name
     * @return Demangled symbol name
     */
    static std::string demangleSymbol(const std::string& mangledName);

    /**
     * @brief Check if symbol is a linker symbol
     * @param symbol Symbol to check
     * @return True if linker symbol
     */
    static bool isLinkerSymbol(const ExtractedSymbol& symbol);

private:
    /**
     * @brief Parse nm output line
     * @param line Line from nm output
     * @return Parsed symbol
     */
    static ExtractedSymbol parseNmLine(const std::string& line);

    /**
     * @brief Parse readelf section output
     * @param line Line from readelf output
     * @return Parsed section
     */
    static ElfSection parseReadelfSectionLine(const std::string& line);

    /**
     * @brief Parse objdump relocation output
     * @param line Line from objdump output
     * @return Parsed symbol
     */
    static ExtractedSymbol parseObjdumpRelocationLine(const std::string& line);

    /**
     * @brief Get symbol type from nm character
     * @param typeChar Type character from nm
     * @return Symbol type string
     */
    static std::string getSymbolType(char typeChar);

    /**
     * @brief Parse size from nm output
     * @param sizeStr Size string from nm
     * @return Size value
     */
    static uint64_t parseSize(const std::string& sizeStr);

    /**
     * @brief Parse address from nm output
     * @param addrStr Address string from nm
     * @return Address value
     */
    static uint64_t parseAddress(const std::string& addrStr);

    /**
     * @brief Check if symbol type is a variable
     * @param type Type character from nm
     * @return True if variable type
     */
    static bool isVariableType(char type);

    /**
     * @brief Check if symbol type is a function
     * @param type Type character from nm
     * @return True if function type
     */
    static bool isFunctionType(char type);

    /**
     * @brief Check if symbol should be included
     * @param symbol Symbol to check
     * @return True if symbol should be included
     */
    static bool shouldIncludeSymbol(const ExtractedSymbol& symbol);

    /**
     * @brief Estimate array element count from size
     * @param symbol Symbol to analyze
     * @param sections ELF sections
     * @return Estimated element count
     */
    static uint64_t estimateElementCount(const ExtractedSymbol& symbol,
                                         const std::vector<ElfSection>& sections);

    /**
     * @brief Create basic sections when objdump is not available
     * @return Vector of basic ELF sections
     */
    static std::vector<ElfSection> createBasicSections();

    /**
     * @brief Fallback symbol extraction using system tools
     * @param filename Path to ELF file
     * @return Vector of symbols
     */
    static std::vector<ExtractedSymbol> extractSymbolsFallback(const std::string& filename);

    /**
     * @brief Parse ELF symbol from libelf data
     * @param sym ELF symbol structure
     * @param name Symbol name
     * @param is64bit Whether this is a 64-bit ELF
     * @return ExtractedSymbol structure
     */
    static ExtractedSymbol parseElfSymbol(void* sym, const char* name, bool is64bit);

    /**
     * @brief Parse basic nm output line (without size information)
     * @param line NM output line
     * @return ExtractedSymbol structure
     */
    static ExtractedSymbol parseNmLineBasic(const std::string& line);

    /**
     * @brief Parse ELF relocation symbol from libelf data
     * @param elf ELF handle
     * @param symIndex Symbol index in relocation
     * @param offset Relocation offset
     * @param ehdr ELF header
     * @return ExtractedSymbol structure
     */
    static ExtractedSymbol parseRelocationSymbol(Elf* elf, uint32_t symIndex, uint64_t offset, void* ehdr);
};