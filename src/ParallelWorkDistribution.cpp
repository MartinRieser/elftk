/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ParallelWorkDistribution.h"
#include <algorithm>
#include <iostream>
#include <thread>
#include "ElfReader.h"

ParallelWorkDistribution::ParallelWorkDistribution(ThreadPool& pool) : thread_pool_(pool) {
    std::cout << "ParallelWorkDistribution initialized" << std::endl;
}

ParallelWorkDistribution::~ParallelWorkDistribution() {
    shutdown();
}

std::future<bool> ParallelWorkDistribution::submitCompilationUnit(
    const std::string& elf_filename,
    Dwarf_Die cu_die,
    uint64_t cu_offset,  // NOLINT(bugprone-easily-swappable-parameters) - cu_offset and priority
                         // have different types and meanings
    uint32_t priority) {
    auto work = std::make_unique<WorkItem>(WorkItemType::COMPILATION_UNIT,
                                           next_work_id_.fetch_add(1),
                                           priority,
                                           "Compilation Unit processing");

    work->elf_filename = elf_filename;
    work->cu_die = cu_die;
    work->cu_offset = cu_offset;
    work->start_time = std::chrono::high_resolution_clock::now();

    // Store work item
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        work_items_.push_back(std::move(work));
    }

    // Submit to thread pool
    WorkItem* work_ptr = work_items_.back().get();
    return thread_pool_.submit([this, work_ptr]() {
        executeWorkItem(work_ptr);
        return !work_ptr->failed.load();
    });
}

std::future<bool> ParallelWorkDistribution::submitSymbolChunk(
    const std::string& elf_filename,
    size_t start_index,  // NOLINT(bugprone-easily-swappable-parameters) - start_index, count, and
                         // priority have different semantic meanings
    size_t count,
    uint32_t priority) {
    auto work = std::make_unique<WorkItem>(WorkItemType::SYMBOL_CHUNK,
                                           next_work_id_.fetch_add(1),
                                           priority,
                                           "Symbol chunk processing");

    work->elf_filename = elf_filename;
    work->symbol_start = start_index;
    work->symbol_count = count;
    work->start_time = std::chrono::high_resolution_clock::now();

    // Store work item
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        work_items_.push_back(std::move(work));
    }

    // Submit to thread pool
    WorkItem* work_ptr = work_items_.back().get();
    return thread_pool_.submit([this, work_ptr]() {
        executeWorkItem(work_ptr);
        return !work_ptr->failed.load();
    });
}

std::future<bool> ParallelWorkDistribution::submitStructureExpansion(
    const std::string& elf_filename,
    const std::string& structure_name,
    uint64_t base_address,  // NOLINT(bugprone-easily-swappable-parameters) - base_address and
                            // priority have different types and meanings
    uint32_t priority) {
    auto work = std::make_unique<WorkItem>(WorkItemType::STRUCTURE_EXPANSION,
                                           next_work_id_.fetch_add(1),
                                           priority,
                                           "Structure expansion");

    work->elf_filename = elf_filename;
    work->structure_name = structure_name;
    work->base_address = base_address;
    work->start_time = std::chrono::high_resolution_clock::now();

    // Store work item
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        work_items_.push_back(std::move(work));
    }

    // Submit to thread pool
    WorkItem* work_ptr = work_items_.back().get();
    return thread_pool_.submit([this, work_ptr]() {
        executeWorkItem(work_ptr);
        return !work_ptr->failed.load();
    });
}

std::future<bool> ParallelWorkDistribution::submitCachePopulation(const std::string& elf_filename,
                                                                  const std::string& cache_type,
                                                                  uint32_t priority) {
    auto work = std::make_unique<WorkItem>(
        WorkItemType::CACHE_POPULATION, next_work_id_.fetch_add(1), priority, "Cache population");

    work->elf_filename = elf_filename;
    work->cache_type = cache_type;
    work->start_time = std::chrono::high_resolution_clock::now();

    // Store work item
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        work_items_.push_back(std::move(work));
    }

    // Submit to thread pool
    WorkItem* work_ptr = work_items_.back().get();
    return thread_pool_.submit([this, work_ptr]() {
        executeWorkItem(work_ptr);
        return !work_ptr->failed.load();
    });
}

void ParallelWorkDistribution::executeWorkItem(WorkItem* work) {
    if (!work || shutdown_requested_.load()) {
        return;
    }

    try {
        switch (work->type) {
            case WorkItemType::COMPILATION_UNIT:
                processCompilationUnit(work);
                break;
            case WorkItemType::SYMBOL_CHUNK:
                processSymbolChunk(work);
                break;
            case WorkItemType::STRUCTURE_EXPANSION:
                processStructureExpansion(work);
                break;
            case WorkItemType::CACHE_POPULATION:
                processCachePopulation(work);
                break;
            default:
                std::cerr << "Unknown work item type: " << static_cast<int>(work->type)
                          << std::endl;
                work->failed.store(true);
                break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in work item " << work->id << ": " << e.what() << std::endl;
        work->failed.store(true);
    } catch (...) {
        std::cerr << "Unknown exception in work item " << work->id << std::endl;
        work->failed.store(true);
    }

    work->end_time = std::chrono::high_resolution_clock::now();
    work->completed.store(true);
}

void ParallelWorkDistribution::processCompilationUnit(WorkItem* work) {
    if (!work || shutdown_requested_.load()) {
        return;
    }

    // Get thread-local context for this ELF file
    ThreadContextGuard context_guard(work->elf_filename);
    ThreadDwarfContext* context = context_guard.getContext();

    if (!context || !context->isValid()) {
        std::cerr << "Failed to get thread-local context for compilation unit processing"
                  << std::endl;
        work->failed.store(true);
        return;
    }

#ifdef HAVE_LIBDWARF
    // Process compilation unit with thread-local libdwarf context
    // This would contain the actual DWARF compilation unit processing logic
    // For now, we'll simulate the work with a delay and metrics update

    context->cu_count++;

    // In a real implementation, you would:
    // 1. Parse the compilation unit DIE
    // 2. Extract all types, variables, functions
    // 3. Build thread-local type registry
    // 4. Merge results with global registry

    // Simulate processing time based on complexity
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
#else
    std::cerr << "libdwarf not available for compilation unit processing" << std::endl;
    work->failed.store(true);
#endif
}

void ParallelWorkDistribution::processSymbolChunk(WorkItem* work) {
    if (!work || shutdown_requested_.load()) {
        return;
    }

    // Get thread-local context for this ELF file
    ThreadContextGuard context_guard(work->elf_filename);
    ThreadDwarfContext* context = context_guard.getContext();

    if (!context || !context->isValid()) {
        std::cerr << "Failed to get thread-local context for symbol processing" << std::endl;
        work->failed.store(true);
        return;
    }

    // Process symbol chunk
    // In a real implementation, you would:
    // 1. Read symbols from the specified chunk
    // 2. Match symbols with DWARF type information
    // 3. Perform demangling and classification
    // 4. Update global symbol database

    context->variable_count += work->symbol_count;

    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
}

void ParallelWorkDistribution::processStructureExpansion(WorkItem* work) {
    if (!work || shutdown_requested_.load()) {
        return;
    }

    // Get thread-local context for this ELF file
    ThreadContextGuard context_guard(work->elf_filename);
    ThreadDwarfContext* context = context_guard.getContext();

    if (!context || !context->isValid()) {
        std::cerr << "Failed to get thread-local context for structure expansion" << std::endl;
        work->failed.store(true);
        return;
    }

    // Process structure expansion
    // In a real implementation, you would:
    // 1. Find the structure type in thread-local registry
    // 2. Expand all members recursively
    // 3. Calculate memory layout and addresses
    // 4. Generate MemberInfo objects

    context->type_count++;

    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
}

void ParallelWorkDistribution::processCachePopulation(WorkItem* work) {
    if (!work || shutdown_requested_.load()) {
        return;
    }

    // Get thread-local context for this ELF file
    ThreadContextGuard context_guard(work->elf_filename);
    ThreadDwarfContext* context = context_guard.getContext();

    if (!context || !context->isValid()) {
        std::cerr << "Failed to get thread-local context for cache population" << std::endl;
        work->failed.store(true);
        return;
    }

    // Process cache population
    // In a real implementation, you would:
    // 1. Build hash tables for quick lookups
    // 2. Create symbol-to-type mappings
    // 3. Populate thread-local caches
    // 4. Merge caches into global cache

    // Simulate processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
}

bool ParallelWorkDistribution::waitForAllWork(int timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        size_t pending = getPendingWorkCount();
        if (pending == 0) {
            return true;  // All work completed
        }

        if (timeout_ms > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start_time)
                               .count();

            if (elapsed >= timeout_ms) {
                return false;  // Timeout occurred
            }
        }

        // Wait a bit before checking again
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

size_t ParallelWorkDistribution::getPendingWorkCount() const {
    std::lock_guard<std::mutex> lock(work_mutex_);
    return work_items_.size();
}

void ParallelWorkDistribution::shutdown() {
    shutdown_requested_.store(true);
    std::cout << "ParallelWorkDistribution shutdown initiated" << std::endl;

    // Wait for all pending work to complete or timeout
    waitForAllWork(5000);  // 5 second timeout

    // Clear remaining work items
    {
        std::lock_guard<std::mutex> lock(work_mutex_);
        size_t remaining = work_items_.size();
        if (remaining > 0) {
            std::cout << "Warning: " << remaining << " work items remaining at shutdown"
                      << std::endl;
            work_items_.clear();
        }
    }
}