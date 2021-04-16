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
	TEST_MANUAL_SBOX = 0x10;
	TEST_SUB_BYTES = 0x100;
	TEST_SHIFT_ROW = 0x1000;
	TEST_FIELD_MULTIPLY_BY_2= 0x10000;
	TEST_MIX_COLUMNS = 0x100000;
	TEST_ADD_ROUND_KEY = 0x1000000;
	TEST_KEY_EXPANSION = 0x10000000;
	TEST_AES_TIMING = 0x100000000;
	TEST_ECB = 0x1000000000;
	TEST_CBC = 0x10000000000;
	TEST_OFB = 0x100000000000;
	TEST_CTR = 0x1000000000000;
	TEST_GENERIC = 0x10000000000000;
    };

    /**
     * @brief Helper function to print the contents of a vector
     * @param vec: Vector to print
     */
    template<typename T>
    void print_vector(std::vector<T> vec) {
        for (std::size_t i = 0; i < vec.size(); ++i) {
            if (i % 16 == 0){
                printf("\n");     
            }
            printf("0x%02x ", vec[i]);
        }
        std::cout << std::endl;
    }

    /**
     * @brief Used to test the average runtime of no_cache_lookup as a means of ensuring constant time execution
    * 
    */
    void test_no_cache_lookup_timing();

    /**
     * @brief Used to test the encryption, decryption process of OFM to ensure equality
     * 
     */
    void test_ofm_mode_accuracy(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes);

    void test_ecb_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes);

    void test_ctr_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes);

    void test_cbc_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes);

    void test_cfb_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes);

    void test_key_expansion(const std::vector<aes::byte>& key_bytes);

    void test_manual_sbox();    
   
    void test_shiftRow_timing();

    void test_mixColumns_timing();

    void test_subBytes_timing();

    void test_fieldmultiply2_timing();

    void test_addRounkey_state_timing();

    void test_addRounkey_roundkey_timing();

    void test_addRounkey_timing();

    void test_keyexpansion128_timing();

    void test_keyexpansion192_timing();

    void test_keyexpansion256_timing();

    void test_aes128_text_timing();

    void test_aes192_text_timing();

    void test_aes256_text_timing();

    void test_aes128_key_timing();

    void test_aes192_key_timing();

    void test_aes256_key_timing();
    
    void test_aes();
    /**
     * @brief Function to call to test specific modules within the program
    * 
    * @param test_flags OR combination of TESTCASES you'd like to test
    */
    void test_modules(uint64_t test_flags, std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes);
} // namespace tb
#endif // TESTBENCH_HPP
