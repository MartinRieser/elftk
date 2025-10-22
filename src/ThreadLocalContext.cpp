/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ThreadLocalContext.h"
#include <iostream>
#include <thread>
#include "ElfReader.h"

bool ThreadDwarfContext::initialize(const std::string& elf_filename) {
    if (is_initialized) {
        cleanup();  // Clean up any existing context
    }

    filename = elf_filename;
    cu_count = 0;
    type_count = 0;
    variable_count = 0;

#ifdef HAVE_LIBDWARF
    // Use the same initialization logic as ElfReader
    #if defined(DW_LIBDWARF_VERSION_MAJOR) && (DW_LIBDWARF_VERSION_MAJOR >= 2) ||                  \
        defined(__APPLE__) || (defined(_WIN32) && defined(__MINGW64__))
    // libdwarf 2.x API or macOS/Windows with simplified API (8 parameters)
    int result = dwarf_init_path(
        elf_filename.c_str(), nullptr, 0, DW_GROUPNUMBER_ANY, nullptr, nullptr, &dbg, &err);
    #elif defined(__linux__)
    // Ubuntu/Debian libdwarf API with 11 parameters
    int result = dwarf_init_path(elf_filename.c_str(),
                                 nullptr,
                                 0,
                                 DW_GROUPNUMBER_ANY,
                                 0,
                                 nullptr,
                                 nullptr,
                                 0,
                                 &dbg,
                                 nullptr,
                                 nullptr,
                                 &err);
    #else
    // Older libdwarf API with extended parameters (12 parameters)
    int result = dwarf_init_path(elf_filename.c_str(),
                                 nullptr,
                                 0,
                                 DW_GROUPNUMBER_ANY,
                                 0,
                                 nullptr,
                                 nullptr,
                                 0,
                                 &dbg,
                                 nullptr,
                                 nullptr,
                                 &err);
    #endif

    if (result == DW_DLV_OK) {
        is_initialized = true;
        return true;
    } else {
        std::cerr << "Failed to initialize libdwarf for thread " << std::this_thread::get_id()
                  << " with file " << elf_filename << ": error " << result << std::endl;
        return false;
    }
#else
    // For builds without libdwarf, we can't do real DWARF processing
    std::cerr << "Warning: libdwarf not available, thread context initialization failed"
              << std::endl;
    return false;
#endif
}

void ThreadDwarfContext::cleanup() {
    if (is_initialized && dbg != nullptr) {
#ifdef HAVE_LIBDWARF
        #if defined(__linux__)
        // Ubuntu/Debian libdwarf requires error parameter
        dwarf_finish(dbg, &err);
        #else
        // macOS/Windows libdwarf doesn't require error parameter
        dwarf_finish(dbg);
        #endif
#endif
        dbg = nullptr;
        err = nullptr;
        is_initialized = false;
    }
}

// Thread-local storage definitions (free variables)
thread_local std::unique_ptr<ThreadDwarfContext> current_context_;
thread_local std::string current_filename_;
thread_local uint64_t thread_id_ = 0;
std::atomic<uint64_t> ThreadLocalContextManager::next_thread_id_{1};

// Implementation of ThreadLocalContextManager methods

ThreadDwarfContext* ThreadLocalContextManager::getContext(const std::string& elf_filename) {
    // If we already have a context for this file, return it
    if (current_context_ && current_filename_ == elf_filename && current_context_->isValid()) {
        return current_context_.get();
    }

    // Otherwise, create a new context
    current_context_ = std::make_unique<ThreadDwarfContext>();
    current_filename_ = elf_filename;

    if (current_context_->initialize(elf_filename)) {
        return current_context_.get();
    } else {
        // Failed to initialize, clean up
        resetContext();
        return nullptr;
    }
}

ThreadDwarfContext* ThreadLocalContextManager::getCurrentContext() {
    return current_context_.get();
}

bool ThreadLocalContextManager::hasValidContext() {
    return current_context_ && current_context_->isValid();
}

uint64_t ThreadLocalContextManager::getCurrentThreadId() {
    if (thread_id_ == 0) {
        thread_id_ = next_thread_id_.fetch_add(1) + 1;
    }
    return thread_id_;
}

void ThreadLocalContextManager::resetContext() {
    current_context_.reset();
    current_filename_.clear();
}

std::unordered_map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>
ThreadLocalContextManager::getAllThreadStats() {
    // This is a simplified implementation - in practice, you'd need a more sophisticated
    // approach to collect statistics from all threads
    static std::mutex stats_mutex;
    static std::unordered_map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> global_stats;

    std::lock_guard<std::mutex> lock(stats_mutex);
    return global_stats;
}

void ThreadLocalContextManager::cleanupAll() {
    // In practice, this would signal all threads to cleanup their contexts
    // For now, just clean up current thread
    resetContext();
}

// Note: The getAllThreadStats() implementation in the header is simplified.
// In a production environment, you'd need a more sophisticated approach to collect
// statistics from all threads, possibly using a shared atomic metrics structure.