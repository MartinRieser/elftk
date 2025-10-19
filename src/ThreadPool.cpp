/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ThreadPool.h"
#include <algorithm>
#include <iostream>

ThreadPool::ThreadPool(size_t num_threads) : stop_(false) {
    // Determine optimal thread count
    if (num_threads == 0) {
        // Auto-detect based on hardware concurrency
        thread_count_ =
            std::max(size_t(1), static_cast<size_t>(std::thread::hardware_concurrency()));
    } else {
        thread_count_ = std::max(size_t(1), num_threads);
    }

    // Create worker threads
    workers_.reserve(thread_count_);
    for (size_t i = 0; i < thread_count_; ++i) {
        workers_.emplace_back(&ThreadPool::worker, this, i);
    }

    std::cout << "ThreadPool initialized with " << thread_count_ << " worker threads" << std::endl;
}

ThreadPool::~ThreadPool() {
    // Signal all threads to stop
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }

    condition_.notify_all();

    // Wait for all threads to finish
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    std::cout << "ThreadPool shutdown complete" << std::endl;
}

void ThreadPool::worker(size_t thread_id) {
    (void)
        thread_id;  // Suppress unused parameter warning - thread_id is kept for future enhancements
    while (true) {
        std::function<void()> task;

        // Try to get work from main queue
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);

            // Wait for work or stop signal
            condition_.wait(lock, [this] { return stop_.load() || !tasks_.empty(); });

            if (stop_.load()) {
                break;
            }

            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }

        if (task) {
            // Execute task with metrics tracking
            Task wrapped_task(std::move(task), &metrics_);
            wrapped_task();
        }
    }
}

std::function<void()> ThreadPool::try_steal_work(size_t thread_id) {
    (void)thread_id;  // Suppress unused parameter warning - thread_id kept for future work-stealing
                      // logic
    // Simplified work stealing - just check main queue
    std::unique_lock<std::mutex> lock(queue_mutex_, std::try_to_lock);
    if (lock.owns_lock() && !tasks_.empty()) {
        auto task = std::move(tasks_.front());
        tasks_.pop();
        return task;
    }
    return {};
}

std::function<void()> ThreadPool::get_task(size_t thread_id) {
    // Try to get work from main queue
    std::unique_lock<std::mutex> lock(queue_mutex_, std::try_to_lock);
    if (lock.owns_lock() && !tasks_.empty()) {
        auto task = std::move(tasks_.front());
        tasks_.pop();
        return task;
    }

    // If no immediate work available, try work stealing
    return try_steal_work(thread_id);
}

bool ThreadPool::waitForCompletion(int timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (tasks_.empty()) {
                return true;  // All work completed
            }
        }

        if (timeout_ms > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start_time)
                               .count();

            if (elapsed >= timeout_ms) {
                return false;  // Timeout occurred
            }
        }

        // Brief sleep to avoid busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}