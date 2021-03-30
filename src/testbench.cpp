#include "testbench.hpp"

#include <algorithm>
#include <chrono>
#include <random>

void tb::test_modules(unsigned long test_flags) {
    if (test_flags | TEST_NO_CACHE) {
        __test_no_cache_lookup_timing();
    }
}
void tb::__test_no_cache_lookup_timing() {
    const unsigned int RUN_COUNT = 100000;

    // Set up vectors to track runtime information
    std::vector<double> avg_runtimes(256, 0.0);
    std::vector<aes::byte> lookup_values{};
    for (std::size_t i = 0; i < 256; ++i) {
        lookup_values.push_back(static_cast<aes::byte>(i));
    }
    std::random_device rd;
    std::mt19937 g(rd());
    
    for (std::size_t l = 0; l < RUN_COUNT; ++l) {
        std::shuffle(lookup_values.begin(), lookup_values.end(), g); // Shuffle order of execution for each run

        for (const auto& i : lookup_values) {
            aes::byte val = aes::S_BOX.at(i);
            auto ncache_start = std::chrono::steady_clock::now();
            aes::byte val_other = no_cache_lookup(i & 0xF0U, i & 0xFU, aes::S_BOX.data());
            auto ncache_end = std::chrono::steady_clock::now();
            
            if (val != val_other) {
                std::cerr << "Val " << static_cast<int>(val) << " does not equal val_other " << static_cast<int>(val_other) 
                << "for index " << static_cast<int>(i) << "\n";
                exit(1);
            } else {
                auto ncache_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(ncache_end - ncache_start).count();
                avg_runtimes[i] = (avg_runtimes[i] * l + ncache_ns) / (l + 1);
            }
        }
    }

    std::cout <<"==========NO CACHE TEST==========\n";
    for (int i = 0; i < 256; ++i) {        
        std::cout << static_cast<std::size_t>(i) << ": " << static_cast<int>(avg_runtimes[i]) << "\n";
    }
    std::cout <<"==========END NO CACHE TEST==========\n";
}