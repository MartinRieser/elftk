/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

/**
 * @file ThreadPool.h
 * @brief High-performance thread pool for parallel ELF processing
 *
 * This file implements a comprehensive thread pool system designed for Phase 2
 * multi-threading support in ELF analysis. The thread pool provides:
 * - Dynamic load balancing with efficient task distribution
 * - Thread-local storage for libdwarf contexts
 * - Comprehensive performance metrics and monitoring
 * - Exception-safe task execution
 * - Graceful shutdown and resource cleanup
 *
 * Key Features:
 * - Efficient task queue for load distribution
 * - Configurable thread count with CPU core detection
 * - Atomic performance counters for thread-safe monitoring
 * - Future-based task submission with result retrieval
 * - Thread-safe exception handling and error propagation
 *
 * @author ELF Symbol Reader Development Team
 * @date 2025 - Phase 2 Multi-threading Implementation
 */

/**
 * @brief Performance metrics for thread pool monitoring
 *
 * Tracks comprehensive performance data for thread pool optimization
 * and load balancing decisions.
 */
struct ThreadPoolMetrics {
    std::atomic<uint64_t> tasks_submitted{0};
    std::atomic<uint64_t> tasks_completed{0};
    std::atomic<uint64_t> tasks_failed{0};
    std::atomic<uint64_t> total_wait_time_us{0};
    std::atomic<uint64_t> total_execution_time_us{0};
    std::atomic<uint64_t> active_threads{0};
    std::atomic<uint64_t> idle_threads{0};

    /**
     * @brief Get average task execution time
     * @return Average execution time in microseconds
     */
    double getAverageExecutionTime() const {
        uint64_t completed = tasks_completed.load();
        if (completed == 0)
            return 0.0;
        return static_cast<double>(total_execution_time_us.load()) / completed;
    }

    /**
     * @brief Get task success rate
     * @return Percentage of successful tasks (0-100)
     */
    double getSuccessRate() const {
        uint64_t submitted = tasks_submitted.load();
        if (submitted == 0)
            return 100.0;
        return (static_cast<double>(tasks_completed.load()) / submitted) * 100.0;
    }

    /**
     * @brief Reset all metrics to zero
     */
    void reset() {
        tasks_submitted.store(0);
        tasks_completed.store(0);
        tasks_failed.store(0);
        total_wait_time_us.store(0);
        total_execution_time_us.store(0);
        active_threads.store(0);
        idle_threads.store(0);
    }
};

/**
 * @brief Exception-safe task wrapper with metrics tracking
 *
 * Wraps user tasks with timing, exception handling, and metrics collection.
 */
class Task {
private:
    std::function<void()> task_;
    ThreadPoolMetrics* metrics_;

public:
    explicit Task(std::function<void()> task, ThreadPoolMetrics* metrics)
        : task_(std::move(task)), metrics_(metrics) {}

    /**
     * @brief Execute the wrapped task with timing and exception handling
     */
    void operator()() {
        auto start_time = std::chrono::high_resolution_clock::now();

        // Increment active threads and ensure decrement happens on all exit paths
        metrics_->active_threads.fetch_add(1);

        try {
            task_();
            metrics_->tasks_completed.fetch_add(1);
        } catch (...) {
            metrics_->tasks_failed.fetch_add(1);
            metrics_->active_threads.fetch_sub(1);  // Decrement before re-throwing
            throw;
        }

        // Decrement on normal completion
        metrics_->active_threads.fetch_sub(1);

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration =
            std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        metrics_->total_execution_time_us.fetch_add(duration.count());
    }
};

/**
 * @brief High-performance thread pool with work-stealing and metrics
 *
 * Implements a production-ready thread pool designed for parallel ELF processing.
 * Features work-stealing for optimal load distribution and comprehensive metrics.
 */
class ThreadPool {
private:
    std::vector<std::thread> workers_;         ///< Worker threads
    std::queue<std::function<void()>> tasks_;  ///< Main task queue
    std::mutex queue_mutex_;                   ///< Main queue mutex
    std::condition_variable condition_;        ///< Condition variable for workers
    std::atomic<bool> stop_;                   ///< Stop flag for graceful shutdown

    ThreadPoolMetrics metrics_;  ///< Performance metrics
    size_t thread_count_;        ///< Number of worker threads

    /**
     * @brief Worker thread function with work-stealing
     * @param thread_id ID of this worker thread
     */
    void worker(size_t thread_id);

    /**
     * @brief Try to steal work from other threads
     * @param thread_id Current thread ID (to avoid stealing from self)
     * @return Task if work was stolen, empty function otherwise
     */
    std::function<void()> try_steal_work(size_t thread_id);

    /**
     * @brief Get task from local queue or main queue
     * @param thread_id Thread ID for local queue access
     * @return Task if available, empty function otherwise
     */
    std::function<void()> get_task(size_t thread_id);

public:
    /**
     * @brief Construct thread pool with specified thread count
     * @param num_threads Number of worker threads (0 = auto-detect CPU cores)
     *
     * Automatically detects optimal thread count based on CPU cores if
     * num_threads is 0. Recommended for ELF processing is typically
     * number of physical cores to avoid hyperthreading contention.
     */
    explicit ThreadPool(size_t num_threads = 0);

    /**
     * @brief Destructor - gracefully shuts down all threads
     */
    ~ThreadPool();

    /**
     * @brief Submit a task for execution and return future for result
     * @tparam F Function type
     * @tparam Args Argument types
     * @param f Function to execute
     * @param args Arguments to pass to function
     * @return std::future for the function result
     *
     * Example usage:
     * ```cpp
     * auto future = pool.submit([](int x) { return x * 2; }, 21);
     * int result = future.get(); // result = 42
     * ```
     */
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args) -> std::future<typename std::invoke_result_t<F, Args...>>;

    /**
     * @brief Submit a task without return value (fire-and-forget)
     * @tparam F Function type
     * @tparam Args Argument types
     * @param f Function to execute
     * @param args Arguments to pass to function
     */
    template<class F, class... Args>
    void execute(F&& f, Args&&... args);

    /**
     * @brief Get current performance metrics
     * @return Reference to current metrics (thread-safe snapshot)
     */
    const ThreadPoolMetrics& getMetrics() const {
        return metrics_;
    }

    /**
     * @brief Reset performance metrics
     */
    void resetMetrics() {
        metrics_.reset();
    }

    /**
     * @brief Get number of worker threads
     * @return Thread count
     */
    size_t getThreadCount() const {
        return thread_count_;
    }

    /**
     * @brief Get number of pending tasks
     * @return Pending task count
     */
    size_t getPendingTasks() const {
        std::unique_lock<std::mutex> lock(const_cast<std::mutex&>(queue_mutex_));
        return tasks_.size();
    }

    /**
     * @brief Check if thread pool is stopping
     * @return true if shutdown initiated
     */
    bool isStopping() const {
        return stop_.load();
    }

    /**
     * @brief Wait for all pending tasks to complete
     * @param timeout_ms Maximum wait time in milliseconds (0 = wait indefinitely)
     * @return true if all tasks completed, false if timeout occurred
     */
    bool waitForCompletion(int timeout_ms = 0);

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
};

// Template method implementations

template<class F, class... Args>
auto ThreadPool::submit(F&& f, Args&&... args)
    -> std::future<typename std::invoke_result_t<F, Args...>> {
    using return_type = typename std::invoke_result_t<F, Args...>;

    // Create packaged task to get future
    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<return_type> result = task->get_future();

    // Wrap in lambda that executes the packaged task
    auto wrapped_task = [task]() { (*task)(); };

    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) {
            throw std::runtime_error("ThreadPool is stopping - cannot submit new tasks");
        }

        tasks_.emplace(wrapped_task);
        metrics_.tasks_submitted.fetch_add(1);
    }

    condition_.notify_one();
    return result;
}

template<class F, class... Args>
void ThreadPool::execute(F&& f, Args&&... args) {
    // Fire-and-forget task submission
    auto wrapped_task = std::bind(std::forward<F>(f), std::forward<Args>(args)...);

    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) {
            throw std::runtime_error("ThreadPool is stopping - cannot submit new tasks");
        }

        tasks_.emplace(wrapped_task);
        metrics_.tasks_submitted.fetch_add(1);
    }

    condition_.notify_one();
}