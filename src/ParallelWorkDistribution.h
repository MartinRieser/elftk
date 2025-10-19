/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <vector>
#include "ThreadLocalContext.h"
#include "ThreadPool.h"

#ifdef HAVE_LIBDWARF
    #include <dwarf.h>
    #include <libdwarf.h>
#else
typedef struct Dwarf_Debug_s* Dwarf_Debug;
typedef struct Dwarf_Die_s* Dwarf_Die;
typedef struct Dwarf_Error_s* Dwarf_Error;
#endif

/**
 * @file ParallelWorkDistribution.h
 * @brief Work distribution system for parallel DWARF and ELF processing
 *
 * This file implements the work distribution mechanism for Phase 2 multi-threading,
 * providing efficient task scheduling and workload balancing for parallel ELF analysis.
 *
 * Key Features:
 * - Compilation unit parallelization with work stealing
 * - Symbol table chunking for concurrent processing
 * - Structure expansion parallelization
 * - Thread-safe result aggregation
 * - Dynamic load balancing based on task complexity
 *
 * @author ELF Symbol Reader Development Team
 * @date 2025 - Phase 2 Multi-threading Implementation
 */

/**
 * @brief Types of parallel work items that can be distributed
 */
enum class WorkItemType {
    COMPILATION_UNIT,     ///< Process a single DWARF compilation unit
    SYMBOL_CHUNK,         ///< Process a chunk of symbol table entries
    STRUCTURE_EXPANSION,  ///< Expand a single structure with all members
    CACHE_POPULATION,     ///< Populate lookup tables and caches
    VALIDATION            ///< Perform validation checks
};

/**
 * @brief Work item representing a task for parallel processing
 */
struct WorkItem {
    WorkItemType type;        ///< Type of work to perform
    uint32_t id;              ///< Unique work item identifier
    uint32_t priority;        ///< Processing priority (lower = higher priority)
    std::string description;  ///< Human-readable description for debugging

    // Work-specific data
    std::string elf_filename;  ///< ELF file being processed

    // For compilation units
    Dwarf_Die cu_die;    ///< Compilation unit DIE (if applicable)
    uint64_t cu_offset;  ///< DWARF offset of compilation unit

    // For symbol chunks
    size_t symbol_start;  ///< Starting index in symbol table
    size_t symbol_count;  ///< Number of symbols to process

    // For structure expansion
    std::string structure_name;  ///< Name of structure to expand
    uint64_t base_address;       ///< Base address of structure

    // For cache population
    std::string cache_type;  ///< Type of cache to populate

    // Performance tracking
    std::atomic<bool> completed{false};                         ///< Whether work item is completed
    std::atomic<bool> failed{false};                            ///< Whether work item failed
    std::chrono::high_resolution_clock::time_point start_time;  ///< When work started
    std::chrono::high_resolution_clock::time_point end_time;    ///< When work ended

    WorkItem(WorkItemType t, uint32_t item_id, uint32_t prio, const std::string& desc)
        : type(t),
          id(item_id),
          priority(prio),
          description(desc),
          cu_die(nullptr),
          cu_offset(0),
          symbol_start(0),
          symbol_count(0),
          base_address(0) {}
};

/**
 * @brief Result aggregation for parallel processing
 *
 * Thread-safe container for collecting results from parallel work items.
 */
template<typename T>
class ThreadSafeResultAggregator {
private:
    std::vector<T> results_;
    mutable std::mutex mutex_;
    std::atomic<size_t> expected_count_{0};
    std::atomic<size_t> received_count_{0};

public:
    /**
     * @brief Set expected number of results
     * @param count Expected result count
     */
    void setExpectedCount(size_t count) {
        expected_count_.store(count);
        results_.reserve(count);
    }

    /**
     * @brief Add a result from a worker thread
     * @param result Result to add
     * @return true if result was accepted
     */
    bool addResult(const T& result) {
        std::lock_guard<std::mutex> lock(mutex_);
        results_.push_back(result);
        received_count_.fetch_add(1);
        return true;
    }

    /**
     * @brief Check if all expected results have been received
     * @return true if complete
     */
    bool isComplete() const {
        return received_count_.load() >= expected_count_.load();
    }

    /**
     * @brief Get all collected results
     * @return Vector of results
     */
    std::vector<T> getResults() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return results_;
    }

    /**
     * @brief Get completion percentage
     * @return Percentage (0-100)
     */
    double getCompletionPercentage() const {
        size_t expected = expected_count_.load();
        if (expected == 0)
            return 100.0;
        return (static_cast<double>(received_count_.load()) / expected) * 100.0;
    }

    /**
     * @brief Reset aggregator for new work batch
     */
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        results_.clear();
        expected_count_.store(0);
        received_count_.store(0);
    }
};

/**
 * @brief Parallel work distribution manager
 *
 * Coordinates work distribution among worker threads and manages result aggregation.
 * Provides high-level interface for parallel ELF processing operations.
 */
class ParallelWorkDistribution {
private:
    ThreadPool& thread_pool_;                            ///< Thread pool for execution
    std::vector<std::unique_ptr<WorkItem>> work_items_;  ///< Pending work items
    mutable std::mutex work_mutex_;                      ///< Mutex for work items access
    std::atomic<uint32_t> next_work_id_{1};              ///< Next work item ID
    std::atomic<bool> shutdown_requested_{false};        ///< Shutdown flag

    /**
     * @brief Execute a single work item
     * @param work Work item to execute
     */
    void executeWorkItem(WorkItem* work);

    /**
     * @brief Process compilation unit in parallel
     * @param work Work item containing compilation unit data
     */
    void processCompilationUnit(WorkItem* work);

    /**
     * @brief Process symbol table chunk in parallel
     * @param work Work item containing symbol chunk data
     */
    void processSymbolChunk(WorkItem* work);

    /**
     * @brief Process structure expansion in parallel
     * @param work Work item containing structure data
     */
    void processStructureExpansion(WorkItem* work);

    /**
     * @brief Process cache population in parallel
     * @param work Work item containing cache data
     */
    void processCachePopulation(WorkItem* work);

public:
    /**
     * @brief Construct work distribution manager
     * @param pool Thread pool to use for execution
     */
    explicit ParallelWorkDistribution(ThreadPool& pool);

    /**
     * @brief Destructor - ensures graceful shutdown
     */
    ~ParallelWorkDistribution();

    /**
     * @brief Submit compilation unit for parallel processing
     * @param elf_filename ELF file path
     * @param cu_die Compilation unit DIE
     * @param cu_offset DWARF offset of compilation unit
     * @param priority Processing priority
     * @return Future for completion status
     */
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - parameters have distinct types
    std::future<bool> submitCompilationUnit(const std::string& elf_filename,
                                            Dwarf_Die cu_die,
                                            uint64_t cu_offset,
                                            uint32_t priority = 1);

    /**
     * @brief Submit symbol table chunk for parallel processing
     * @param elf_filename ELF file path
     * @param start_index Starting symbol index
     * @param count Number of symbols to process
     * @param priority Processing priority
     * @return Future for completion status
     */
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - parameters have distinct types
    std::future<bool> submitSymbolChunk(const std::string& elf_filename,
                                        size_t start_index,
                                        size_t count,
                                        uint32_t priority = 1);

    /**
     * @brief Submit structure expansion for parallel processing
     * @param elf_filename ELF file path
     * @param structure_name Name of structure to expand
     * @param base_address Base address of structure
     * @param priority Processing priority
     * @return Future for completion status
     */
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters) - parameters have distinct types
    std::future<bool> submitStructureExpansion(const std::string& elf_filename,
                                               const std::string& structure_name,
                                               uint64_t base_address,
                                               uint32_t priority = 1);

    /**
     * @brief Submit cache population for parallel processing
     * @param elf_filename ELF file path
     * @param cache_type Type of cache to populate
     * @param priority Processing priority
     * @return Future for completion status
     */
    std::future<bool> submitCachePopulation(const std::string& elf_filename,
                                            const std::string& cache_type,
                                            uint32_t priority = 2);

    /**
     * @brief Wait for all submitted work to complete
     * @param timeout_ms Maximum wait time in milliseconds (0 = wait indefinitely)
     * @return true if all work completed, false if timeout occurred
     */
    bool waitForAllWork(int timeout_ms = 0);

    /**
     * @brief Get number of pending work items
     * @return Pending work count
     */
    size_t getPendingWorkCount() const;

    /**
     * @brief Shutdown work distribution gracefully
     */
    void shutdown();

    /**
     * @brief Check if shutdown has been requested
     * @return true if shutdown requested
     */
    bool isShutdownRequested() const {
        return shutdown_requested_.load();
    }
};