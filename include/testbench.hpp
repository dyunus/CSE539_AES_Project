/**
 * @file testbench.hpp
 * @author Bailey Capuano
 * @brief Utilized to test the runtime of a given module
 * @version 0.1
 * @date 2021-03-30
 * 
 */

#ifndef TESTBENCH_HPP
#define TESTBENCH_HPP
#include "aes.hpp"

namespace tb {
    enum TESTCASES {
        TEST_NO_CACHE = 0x1
    };

    /**
     * @brief Used to test the average runtime of no_cache_lookup as a means of ensuring constant time execution
    * 
    */
    void __test_no_cache_lookup_timing();

    /**
     * @brief Function to call to test specific modules within the program
    * 
    * @param test_flags OR combination of TESTCASES you'd like to test
    */
    void test_modules(unsigned long test_flags);
} // namespace tb
#endif // TESTBENCH_HPP
