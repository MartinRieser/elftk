/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include "ElfStructures.h"

#ifdef HAVE_LIBDWARF
    #include <dwarf.h>
    #include <libdwarf.h>
#else
typedef struct Dwarf_Debug_s* Dwarf_Debug;
typedef struct Dwarf_Error_s* Dwarf_Error;
#endif

/**
 * @file ThreadLocalContext.h
 * @brief Thread-local storage management for parallel ELF processing
 *
 * This file provides thread-local storage management for multi-threading,
 * specifically designed to handle libdwarf contexts safely in multi-threaded
 * environments. libdwarf is not thread-safe, so each thread needs its own context.
 *
 * Key Features:
 * - Thread-safe libdwarf context management
 * - Per-thread DWARF data storage
 * - Automatic resource cleanup
 * - Exception-safe initialization
 * - Performance monitoring per thread
 *
 * @author ELF Symbol Reader Development Team
 * @date 2025
 */

/**
 * @brief Per-thread DWARF processing context
 *
 * Contains all thread-local data needed for DWARF processing in a single thread.
 * Each worker thread gets its own instance to ensure thread safety.
 */
struct ThreadDwarfContext {
    Dwarf_Debug dbg;          ///< libdwarf debug context for this thread
    Dwarf_Error err;          ///< libdwarf error context for this thread
    std::string filename;     ///< ELF file associated with this context
    bool is_initialized;      ///< Whether libdwarf context is properly initialized
    uint64_t cu_count;        ///< Number of compilation units processed
    uint64_t type_count;      ///< Number of types processed
    uint64_t variable_count;  ///< Number of variables processed

    ThreadDwarfContext()
        : dbg(nullptr),
          err(nullptr),
          is_initialized(false),
          cu_count(0),
          type_count(0),
          variable_count(0) {}

    ~ThreadDwarfContext() {
        cleanup();
    }

    /**
     * @brief Initialize libdwarf context for this thread
     * @param elf_filename Path to ELF file to analyze
     * @return true if initialization succeeded
     */
    bool initialize(const std::string& elf_filename);

    /**
     * @brief Clean up libdwarf resources
     */
    void cleanup();

    /**
     * @brief Check if context is valid and ready for use
     * @return true if context is properly initialized
     */
    bool isValid() const {
        return is_initialized && dbg != nullptr;
    }
};

/**
 * @brief Thread-local context manager for parallel processing
 *
 * Manages thread-local storage for DWARF contexts, providing safe multi-threaded
 * access to libdwarf functionality. Each thread gets its own isolated context.
 */
class ThreadLocalContextManager {
private:
    static std::atomic<uint64_t> next_thread_id_;

public:
    /**
     * @brief Get or create thread-local context for specified ELF file
     * @param elf_filename Path to ELF file
     * @return Thread-local context pointer
     */
    static ThreadDwarfContext* getContext(const std::string& elf_filename);

    /**
     * @brief Get current thread's context (must be initialized)
     * @return Current thread context or nullptr if not initialized
     */
    static ThreadDwarfContext* getCurrentContext();

    /**
     * @brief Check if current thread has a valid context
     * @return true if context is valid and initialized
     */
    static bool hasValidContext();

    /**
     * @brief Get current thread ID
     * @return Unique thread identifier
     */
    static uint64_t getCurrentThreadId();

    /**
     * @brief Reset current thread's context
     */
    static void resetContext();

    /**
     * @brief Get statistics for all threads
     * @return Map of thread_id to processing statistics
     */
    static std::unordered_map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>
    getAllThreadStats();

    /**
     * @brief Cleanup all thread contexts (call during shutdown)
     */
    static void cleanupAll();
};

/**
 * @brief RAII helper for thread-local context management
 *
 * Automatically manages thread-local context lifetime, ensuring proper
 * initialization and cleanup. Use this in worker threads.
 */
class ThreadContextGuard {
private:
    ThreadDwarfContext* context_;

public:
    /**
     * @brief Create context guard for specified ELF file
     * @param elf_filename Path to ELF file
     */
    explicit ThreadContextGuard(const std::string& elf_filename)
        : context_(ThreadLocalContextManager::getContext(elf_filename)) {}

    /**
     * @brief Get the managed context
     * @return ThreadDwarfContext pointer or nullptr if failed
     */
    ThreadDwarfContext* getContext() const {
        return context_;
    }

    /**
     * @brief Check if context is valid
     * @return true if context is properly initialized
     */
    bool isValid() const {
        return context_ != nullptr;
    }

    // Non-copyable
    ThreadContextGuard(const ThreadContextGuard&) = delete;
    ThreadContextGuard& operator=(const ThreadContextGuard&) = delete;
};