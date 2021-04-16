#include "testbench.hpp"
#include "aes_exceptions.hpp"
#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
#include <iostream>
#include "ciphermodes.hpp"
#include "yandom.hpp"

void tb::test_modules(uint64_t test_flags, std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes) {
    /* In accordance with exp46-c: do not use a bitwise operator with a Boolean-like operand
     * In order to avoid ambiguity, it is recommended to envelop the bitwise operation in parenthesis as seen below.
     */
    if ((test_flags & TEST_NO_CACHE) != 0U) {
        test_no_cache_lookup_timing();
    }
    if ((test_flags & TEST_MANUAL_SBOX) != 0U){
	test_manual_sbox();
    }
    if ((test_flags & TEST_SUB_BYTES) != 0U){
	test_subBytes_timing();
    }
    if ((test_flags & TEST_SHIFT_ROW) != 0U){
	test_shiftRow_timing();
    }
    if ((test_flags & TEST_FIELD_MULTIPLY_BY_2) != 0U){
	test_fieldmultiply2_timing();
    }
    if ((test_flags & TEST_MIX_COLUMNS) != 0U){
	test_mixColumns_timing();
    }
    if ((test_flags & TEST_ADD_ROUND_KEY) != 0U){
	test_addRounkey_state_timing();
     	test_addRounkey_roundkey_timing();
	test_addRounkey_timing();
    }
    if ((test_flags & TEST_KEY_EXPANSION) != 0U){
	test_keyexpansion128_timing();
	test_keyexpansion192_timing();
	test_keyexpansion256_timing();
	test_key_expansion(key_bytes)
    }
    if ((test_flags & TEST_AES_TIMING) != 0U){
	test_aes128_text_timing();
	test_aes192_text_timing();
	test_aes256_text_timing();
	test_aes128_key_timing();
	test_aes192_key_timing();
	test_aes256_key_timing();
    }
    if ((test_flags & TEST_ECB) != 0U){
	test_ecb_mode(plaintext_bytes,key_bytes);
    }
    if ((test_flags & TEST_CBC) != 0U){
	test_cbc_mode(plaintext_bytes, key_bytes);
    }
    if ((test_flags & TEST_CFB) != 0U){
	test_cfb_mode(plaintext_bytes, key_bytes);
    }
    if ((test_flags & TEST_OFB) != 0U){
	test_ofm_mode_accuracy(plaintext_bytes, key_bytes);
    }
    if ((test_flags & TEST_CTR) != 0U){
	test_ctr_mode(plaintext_bytes, key_bytes);
    }
    if ((test_flags & TEST_GENERIC) != 0U){
	test_aes();
}

void tb::test_no_cache_lookup_timing() {
    const unsigned int RUN_COUNT = 1000;

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
                std::stringstream ss;
                ss << "Val " << static_cast<int>(val) << " does not equal val_other " << static_cast<int>(val_other)
                  << "for index " << static_cast<int>(i) << "\n";
                throw testbench_error(ss.str().c_str(), Tests::NO_CACHE);
            }

            auto ncache_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(ncache_end - ncache_start).count();
            avg_runtimes[i] = (avg_runtimes[i] * l + ncache_ns) / static_cast<double>(l + 1);
        }
    }

    std::cout <<"==========NO CACHE TEST==========\n";
    for (std::size_t i = 0; i < 256; ++i) {
        std::cout << static_cast<std::size_t>(i) << ": " << static_cast<int>(avg_runtimes[i]) << "\n";
    }
    std::cout <<"==========END NO CACHE TEST==========\n";
}

void tb::test_ofm_mode_accuracy(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes) {
    std::cout <<"==========OFM TEST==========\n";

    std::cout << "Plaintext\n";
    print_vector<aes::byte>(plaintext_bytes);

    std::vector<aes::byte> ciphertext = ciphermodes::OFM_Encrypt(plaintext_bytes, key_bytes);
    std::cout << "OFM Ciphertext\n";
    print_vector<aes::byte>(ciphertext);

    auto decrypted_bytes = ciphermodes::OFM_Decrypt(ciphertext, key_bytes);

    std::cout << "OFM Decrypted\n";
    print_vector<aes::byte>(decrypted_bytes);

    for (std::size_t i = 0; i < decrypted_bytes.size(); ++i) {
        if (plaintext_bytes[i] != decrypted_bytes[i]) {
          throw testbench_error("Decryption does not match!", Tests::OFM);
        }
    }

    std::cout <<"==========END OFM TEST==========\n";
}


void tb::test_ecb_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){
    std::cout <<"==========ECB TEST==========\n";

    std::cout << "Plaintext\n";
    print_vector<aes::byte>(plaintext_bytes);

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::ECB_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nECB Ciphertext:\n";
    print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::ECB_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nECB Decrypted:\n";
    print_vector<aes::byte>(decrypted_bytes);

    for (std::size_t i = 0; i < decrypted_bytes.size(); ++i) {
        if (plaintext_bytes[i] != decrypted_bytes[i]) {
          throw testbench_error("Decryption does not match!", Tests::ECB);
        }
    }
    std::cout <<"==========END ECB TEST==========\n";
}


void tb::test_ctr_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){

    std::cout <<"==========CTR TEST==========\n";

    std::cout << "Plaintext\n";
    print_vector<aes::byte>(plaintext_bytes);

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::CTR_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nCTR Ciphertext:\n";
    print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::CTR_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nCTR Decrypted:\n";
    print_vector<aes::byte>(decrypted_bytes);

     for (std::size_t i = 0; i < decrypted_bytes.size(); ++i) {
        if (plaintext_bytes[i] != decrypted_bytes[i]) {
          throw testbench_error("Decryption does not match!", Tests::CTR);
        }
     }
    std::cout <<"==========END CTR TEST==========\n";
}



void tb::test_cbc_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){

    std::cout <<"==========CBC TEST==========\n";

    std::cout << "Plaintext\n";
    print_vector<aes::byte>(plaintext_bytes);

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::CBC_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nCBC Ciphertext:\n";
    print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::CBC_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nCBC Decrypted:\n";
    print_vector<aes::byte>(decrypted_bytes);

    for (std::size_t i = 0; i < decrypted_bytes.size(); ++i) {
        if (plaintext_bytes[i] != decrypted_bytes[i]) {
          throw testbench_error("Decryption does not match!", Tests::CBC);
        }
    }

    std::cout <<"==========END CBC TEST==========\n";
}


void tb::test_cfb_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){

    std::cout <<"==========CFB TEST==========\n";

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::CFB_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nCFB Ciphertext:\n";
    print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::CFB_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nCFB Decrypted:\n";
    print_vector<aes::byte>(decrypted_bytes);

    for (std::size_t i = 0; i < decrypted_bytes.size(); ++i) {
      if (decrypted_bytes[i] != plaintext_bytes[i]) {
        throw testbench_error("Error in decryption!\n", Tests::CFB);
      }
    }

    std::cout <<"==========END CFB TEST==========\n";
}

void tb::test_key_expansion(const std::vector<aes::byte>& key_bytes){
    std::cout <<"==========KEY EXPANSION TEST==========\n";
    int Nk = -1;
    int Nr = -1;

        // determine Nk and Nr
    if (key_bytes.size() == 16){
        Nk = 4;
        Nr = 10;
    }

    else if (key_bytes.size() == 24){
        Nk = 6;
        Nr = 12;
    }

    else if (key_bytes.size() == 32){
        Nk = 8;
        Nr = 14;
    }

    else{
        throw testbench_error("Invalid Key Length for AES!\n", Tests::KEY_EXPANSION);
    }
    // create a vector to store expanded key
    std::vector<aes::word> expandedKey(aes::NB * (Nr + 1));

    aes::key_expansion(key_bytes, expandedKey, Nk, Nr);

    //DEBUGGING: confirm if key expansion is correct for a 128,192, 256 bit key:
    unsigned int expand = (Nk == 4) ? 43 : (Nk == 6) ? 51 : 59; 
    for(std::size_t i = 0; i <= expand; i++){
        printf("0x%02x \n", expandedKey[i]);
    }
    std::cout <<"==========END KEY EXPANSION TEST==========\n";
}

void tb::test_manual_sbox(){
    const unsigned int RUN_COUNT = 1000;

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
            auto man_start = std::chrono::steady_clock::now();
            aes::byte val_other = aes::get_S_BOX_value(i);
            auto man_end = std::chrono::steady_clock::now();

            if (val != val_other) {
                std::stringstream ss;
                ss << "Val " << static_cast<int>(val) << " does not equal val_other " << static_cast<int>(val_other)
                << "for index " << static_cast<int>(i) << "\n";
                throw testbench_error(ss.str().c_str(), Tests::MANUAL_SBOX);
            }
            auto man_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(man_end - man_start).count();
            avg_runtimes[i] = (avg_runtimes[i] * l + man_ns) / static_cast<double>(l + 1);
        }
    }

    std::cout <<"==========MANUAL S-BOX  TEST==========\n";
    for (std::size_t i = 0; i < 256; ++i) {
        std::cout << static_cast<std::size_t>(i) << ": " << static_cast<int>(avg_runtimes[i]) << "\n";
    }
    std::cout <<"==========END MANUAL S-BOX TEST==========\n";
}

void tb:: test_shiftRow_timing(){
	const unsigned int RUN_COUNT = 1000;

	std::vector<double> avg_runtimes(5, 0.0);
	std::vector<aes::state> states;
	std::vector<int> shuffleVector = {0,1,2,3,4};
	for(std::size_t i=0; i<5; i++){
		auto temp = randgen<128>();
		std::vector<aes::byte> arr;
        	for(size_t i =0; i<16; i++){
               		arr.push_back(temp.at(i));
        	}
		aes:: state state = ciphermodes::convert_block_to_state(arr);
		states.push_back(state);
	}
	std::random_device rd;
	std::mt19937 g(rd());
	for (std::size_t l = 0; l < RUN_COUNT; ++l) {
		std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
		for (const auto& i : shuffleVector) {
			aes::state val = states[i];
            		auto shift_start = std::chrono::steady_clock::now();
            		aes::shift_rows(val);
            		auto shift_end = std::chrono::steady_clock::now();
                	auto shift_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(shift_end - shift_start).count();
                	avg_runtimes[i] = (avg_runtimes[i] * l + shift_ns) / static_cast<double>(l + 1);
		}
	}
	std::cout <<"==========SHIFTROW TIMING TEST==========\n";
    	for (std::size_t i = 0; i < 5; ++i) {
		aes::debug_print_state(states[i]);
        	std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
    	}
    	std::cout <<"==========END SHIFTROW TIMING TEST==========\n";
}

void tb:: test_mixColumns_timing(){
        const unsigned int RUN_COUNT = 1000;

        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> states;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes:: state state = ciphermodes::convert_block_to_state(arr);
                states.push_back(state);
        }
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        aes::state val = states[i];
                        auto mix_start = std::chrono::steady_clock::now();
                        aes::mix_columns(val);
                        auto mix_end = std::chrono::steady_clock::now();
                        auto mix_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(mix_end - mix_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + mix_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========MIXCOLUMNS TIMING TEST==========\n";
        for (std::size_t i = 0; i < 5; ++i) {
                aes::debug_print_state(states[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END MIXCOLUMNS TIMING TEST==========\n";
}

void tb:: test_subBytes_timing(){
        const unsigned int RUN_COUNT = 1000;

        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> states;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes:: state state = ciphermodes::convert_block_to_state(arr);
                states.push_back(state);
        }
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        aes::state val = states[i];
                        auto sub_start = std::chrono::steady_clock::now();
                        aes::sub_bytes(val);
                        auto sub_end = std::chrono::steady_clock::now();
                        auto sub_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(sub_end - sub_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + sub_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========SUBBYTES TIMING TEST==========\n";
        for (std::size_t i = 0; i < 5; ++i) {
                aes::debug_print_state(states[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END SUBBYTES TIMING TEST==========\n";
}

void tb::test_fieldmultiply2_timing(){
    const unsigned int RUN_COUNT = 1000;

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
            auto mult_start = std::chrono::steady_clock::now();
	    aes::field_multiply_by_2(i);
            auto mult_end = std::chrono::steady_clock::now();
            auto mult_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(mult_end - mult_start).count();
            avg_runtimes[i] = (avg_runtimes[i] * l + mult_ns) / static_cast<double>(l + 1);
        }
    }

    std::cout <<"==========FIELDMULTIPLYBY2 TIMING  TEST==========\n";
    for (std::size_t i = 0; i < 256; ++i) {
        std::cout << static_cast<std::size_t>(i) << ": " << static_cast<int>(avg_runtimes[i]) << "\n";
    }
    std::cout <<"==========END FIELDMULTIPYBY2 TIMING TEST==========\n";
}

void tb:: test_addRounkey_state_timing(){
	const unsigned int RUN_COUNT = 1000;

        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> states;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes:: state state = ciphermodes::convert_block_to_state(arr);
                states.push_back(state);
        }
	auto temp =randgen<128>();
	std::vector<aes::byte> arr;
	for(size_t i=0; i<16; i++){
		arr.push_back(temp.at(i));
	}
	aes::state roundkey = ciphermodes::convert_block_to_state(arr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        auto add_start = std::chrono::steady_clock::now();
                        aes::add_round_key(states[i],roundkey);
                        auto add_end = std::chrono::steady_clock::now();
                        auto add_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(add_end - add_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + add_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========ADDROUNKEY STATE TIMING TEST==========\n";
        for (size_t i = 0; i < states.size(); ++i) {
                aes::debug_print_state(states[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END ADDROUNDKEY STATE TIMING TEST==========\n";
}

void tb:: test_addRounkey_roundkey_timing(){
        const unsigned int RUN_COUNT = 1000;

        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> roundkeys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes:: state roundkey = ciphermodes::convert_block_to_state(arr);
                roundkeys.push_back(roundkey);
        }
        auto temp =randgen<128>();
        std::vector<aes::byte> arr;
        for(size_t i=0; i<16; i++){
                arr.push_back(temp.at(i));
        }
        aes::state state = ciphermodes::convert_block_to_state(arr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        auto add_start = std::chrono::steady_clock::now();
                        aes::add_round_key(state,roundkeys[i]);
                        auto add_end = std::chrono::steady_clock::now();
                        auto add_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(add_end - add_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + add_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========ADDROUNKEY ROUNDKEY TIMING TEST==========\n";
        for (size_t i = 0; i < roundkeys.size(); ++i) {
                aes::debug_print_state(roundkeys[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END ADDROUNDKEY ROUNDKEY TIMING TEST==========\n";
}

void tb:: test_addRounkey_timing(){
        const unsigned int RUN_COUNT = 1000;

        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> states;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes:: state state = ciphermodes::convert_block_to_state(arr);
                states.push_back(state);
        }
	std::vector<aes::state> roundkeys;
	for( std::size_t i=0; i<5; i++){
        	auto temp =randgen<128>();
        	std::vector<aes::byte> arr;
        	for(size_t i=0; i<16; i++){
                	arr.push_back(temp.at(i));
        	}
        	aes::state roundkey = ciphermodes::convert_block_to_state(arr);
		roundkeys.push_back(roundkey);
	}
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        auto add_start = std::chrono::steady_clock::now();
                        aes::add_round_key(states[i],roundkeys[i]);
                        auto add_end = std::chrono::steady_clock::now();
                        auto add_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(add_end - add_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + add_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========ADDROUNKEY TIMING TEST==========\n";
        for (size_t i = 0; i < states.size(); ++i) {
                aes::debug_print_state(states[i]);
		std::cout<<"\n";
		aes::debug_print_state(roundkeys[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END ADDROUNDKEY TIMING TEST==========\n";
}

void tb:: test_keyexpansion128_timing(){
	const unsigned int RUN_COUNT = 1000;

	int Nk = 4;
        int Nr = 10;
	std::vector<double> avg_runtimes(5, 0.0);
        std::vector<std::vector<aes::byte>> keys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> key;
                for(size_t i =0; i<16; i++){
                        key.push_back(temp.at(i));
                }
                keys.push_back(key);
        }
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        std::vector<aes::word> expandedKey(aes::NB * (Nr + 1));
			std::vector<aes::byte> val = keys[i];
			auto exp_start = std::chrono::steady_clock::now();
                        aes::key_expansion(val, expandedKey, Nk, Nr);
                        auto exp_end = std::chrono::steady_clock::now();
                        auto exp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(exp_end - exp_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + exp_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========KEYEXPANSION128 TIMING TEST==========\n";
        for (std::size_t i = 0; i < 5; ++i) {
		std::cout<<"Key: ";
		for(unsigned char chr : keys.at(i)){
			 printf("0x%02x ", chr);
		}
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END KEYEXPANSION128 TIMING TEST==========\n";

}

void tb:: test_keyexpansion192_timing(){
        const unsigned int RUN_COUNT = 1000;

        int Nk = 6;
        int Nr = 12;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<std::vector<aes::byte>> keys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<256>();
                std::vector<aes::byte> key;
                for(size_t i =0; i<24; i++){
                        key.push_back(temp.at(i));
                }
                keys.push_back(key);
        }
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        std::vector<aes::word> expandedKey(aes::NB * (Nr + 1));
			std::vector<aes::byte> val = keys[i];
			auto exp_start = std::chrono::steady_clock::now();
                        aes::key_expansion(val, expandedKey, Nk, Nr);
                        auto exp_end = std::chrono::steady_clock::now();
                        auto exp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(exp_end - exp_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + exp_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========KEYEXPANSION192 TIMING TEST==========\n";
        for (std::size_t i = 0; i < 5; ++i) {
                std::cout<<"Key: ";
                for(unsigned char chr : keys.at(i)){
                         printf("0x%02x ", chr);
                }
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END KEYEXPANSION192 TIMING TEST==========\n";

}


void tb:: test_keyexpansion256_timing(){
        const unsigned int RUN_COUNT = 1000;

        int Nk = 8;
        int Nr = 14;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<std::vector<aes::byte>> keys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<256>();
                std::vector<aes::byte> key;
                for(size_t i =0; i<32; i++){
                        key.push_back(temp.at(i));
                }
                keys.push_back(key);
        }
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        std::vector<aes::word> expandedKey(aes::NB * (Nr + 1));
                        std::vector<aes::byte> val = keys[i];
                        auto exp_start = std::chrono::steady_clock::now();
                        aes::key_expansion(val, expandedKey, Nk, Nr);
                        auto exp_end = std::chrono::steady_clock::now();
                        auto exp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(exp_end - exp_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + exp_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========KEYEXPANSION256 TIMING TEST==========\n";
        for (std::size_t i = 0; i < 5; ++i) {
                std::cout<<"Key: ";
                for(size_t j=0; j<keys[i].size(); j++){
                         printf("0x%02x ", keys.at(i).at(j));
                }
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END KEYEXPANSION256 TIMING TEST==========\n";

}

void tb::test_aes128_text_timing(){
	const unsigned int RUN_COUNT = 1000;

        int Nk = 4;
        int Nr = 10;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> texts;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
		aes::state text = ciphermodes::convert_block_to_state(arr);
                texts.push_back(text);
        }
	auto temp =randgen<128>();
        std::vector<aes::byte> key;
        for(size_t i=0; i<16; i++){
                key.push_back(temp.at(i));
        }
	std::vector<aes::word>expandedKey(aes::NB*(Nr+1));
	aes::key_expansion(key,expandedKey, Nk,Nr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
			aes::state val = texts[i];
                        auto enc_start = std::chrono::steady_clock::now();
                        aes::encrypt(Nr, val, expandedKey);
                        auto enc_end = std::chrono::steady_clock::now();
                        auto enc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(enc_end - enc_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + enc_ns) / static_cast<double>(l + 1);
                }
        }
        std::cout <<"==========AES128 TEXT TIMING TEST==========\n";
	std::cout<<"Key: ";
        for(unsigned char chr : key){
                printf("0x%02x ", chr);
        }
	printf("\n");
	for (std::size_t i = 0; i < 5; ++i) {
                aes::debug_print_state(texts[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END AES128 TEXT TIMING TEST==========\n";
}

void tb::test_aes192_text_timing(){
        const unsigned int RUN_COUNT = 1000;

        int Nk = 6;
        int Nr = 12;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> texts;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes::state text = ciphermodes::convert_block_to_state(arr);
                texts.push_back(text);
        }
        auto temp =randgen<256>();
        std::vector<aes::byte> key;
        for(size_t i=0; i<24; i++){
                key.push_back(temp.at(i));
        }
        std::vector<aes::word>expandedKey(aes::NB*(Nr+1));
        aes::key_expansion(key,expandedKey, Nk,Nr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        aes::state val = texts[i];
                        auto enc_start = std::chrono::steady_clock::now();
                        aes::encrypt(Nr, val, expandedKey);
                        auto enc_end = std::chrono::steady_clock::now();
                        auto enc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(enc_end - enc_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + enc_ns) / static_cast<double>(l + 1);
                }
        }
	std::cout <<"==========AES192 TEXT TIMING TEST==========\n";
        std::cout<<"Key: ";
        for(unsigned char chr : key){
                printf("0x%02x ", chr);
        }
	printf("\n");
        for (std::size_t i = 0; i < 5; ++i) {
                aes::debug_print_state(texts[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END AES192 TEXT TIMING TEST==========\n";
}

void tb::test_aes256_text_timing(){
        const unsigned int RUN_COUNT = 2000;

        int Nk = 8;
        int Nr = 14;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<aes::state> texts;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> arr;
                for(size_t i =0; i<16; i++){
                        arr.push_back(temp.at(i));
                }
                aes::state text = ciphermodes::convert_block_to_state(arr);
                texts.push_back(text);
        }
        auto temp =randgen<256>();
        std::vector<aes::byte> key;
        for(size_t i=0; i<32; i++){
                key.push_back(temp.at(i));
        }
        std::vector<aes::word>expandedKey(aes::NB*(Nr+1));
        aes::key_expansion(key,expandedKey, Nk,Nr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        aes::state val = texts[i];
                        auto enc_start = std::chrono::steady_clock::now();
                        aes::encrypt(Nr, val, expandedKey);
                        auto enc_end = std::chrono::steady_clock::now();
                        auto enc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(enc_end - enc_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + enc_ns) / static_cast<double>(l + 1);
                }
        }
	std::cout <<"==========AES256 TEXT TIMING TEST==========\n";
        std::cout<<"Key: ";
        for(unsigned char chr : key){
                printf("0x%02x ", chr);
        }
	printf("\n");
        for (std::size_t i = 0; i < 5; ++i) {
                aes::debug_print_state(texts[i]);
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END AES256 TEXT TIMING TEST==========\n";
}

void tb::test_aes128_key_timing(){
        const unsigned int RUN_COUNT = 2000;

        int Nk = 4;
        int Nr = 10;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<std::vector<aes::byte>> keys;
	std::vector<std::vector<aes::word>> expandedKeys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<128>();
                std::vector<aes::byte> key;
                for(size_t i =0; i<16; i++){
                        key.push_back(temp.at(i));
                }
                keys.push_back(key);
		std::vector<aes::word>expandedKey(aes::NB*(Nr+1));
        	aes::key_expansion(key,expandedKey, Nk,Nr);
                expandedKeys.push_back(expandedKey);
        }
        auto temp =randgen<128>();
        std::vector<aes::byte> arr;
        for(size_t i=0; i<16; i++){
                arr.push_back(temp.at(i));
        }
        aes::state text = ciphermodes::convert_block_to_state(arr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
			std::vector<aes::word> val = expandedKeys[i];
			std::state state = text;
                        auto enc_start = std::chrono::steady_clock::now();
                        aes::encrypt(Nr, state, val);
                        auto enc_end = std::chrono::steady_clock::now();
                        auto enc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(enc_end - enc_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + enc_ns) / static_cast<double>(l + 1);
                }
        }
	std::cout <<"==========AES128 KEY TIMING TEST==========\n";
        std::cout<<"PlainText: ";
        aes::debug_print_state(text[i]);
        printf("\n");
        for (std::size_t i = 0; i < 5; ++i) {
		std::cout<<"Key: ";
        	for(unsigned char chr : keys[i]){
                	printf("0x%02x ", chr);
        	}
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END AES128 KEY TIMING TEST==========\n";
}

void tb::test_aes192_key_timing(){
        const unsigned int RUN_COUNT = 2000;

        int Nk = 6;
        int Nr = 12;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<std::vector<aes::byte>> keys;
        std::vector<std::vector<aes::word>> expandedKeys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<256>();
                std::vector<aes::byte> key;
                for(size_t i =0; i<24; i++){
                        key.push_back(temp.at(i));
                }
                keys.push_back(key);
                std::vector<aes::word>expandedKey(aes::NB*(Nr+1));
                aes::key_expansion(key,expandedKey, Nk,Nr);
                expandedKeys.push_back(expandedKey);
        }
        auto temp =randgen<128>();
        std::vector<aes::byte> arr;
        for(size_t i=0; i<16; i++){
                arr.push_back(temp.at(i));
        }
        aes::state text = ciphermodes::convert_block_to_state(arr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        std::vector<aes::word> val = expandedKeys[i];
                        std::state state = text;
                        auto enc_start = std::chrono::steady_clock::now();
                        aes::encrypt(Nr, state, val);
                        auto enc_end = std::chrono::steady_clock::now();
                        auto enc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(enc_end - enc_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + enc_ns) / static_cast<double>(l + 1);
                }
        }
	std::cout <<"==========AES192 KEY TIMING TEST==========\n";
        std::cout<<"PlainText: ";
        aes::debug_print_state(text[i]);
        printf("\n");
        for (std::size_t i = 0; i < 5; ++i) {
                std::cout<<"Key: ";
                for(unsigned char chr : keys[i]){
                        printf("0x%02x ", chr);
                }
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END AES192 KEY TIMING TEST==========\n";
}

void tb::test_aes256_key_timing(){
        const unsigned int RUN_COUNT = 2000;

        int Nk = 8;
        int Nr = 14;
        std::vector<double> avg_runtimes(5, 0.0);
        std::vector<std::vector<aes::byte>> keys;
        std::vector<std::vector<aes::word>> expandedKeys;
        std::vector<int> shuffleVector = {0,1,2,3,4};
        for(std::size_t i=0; i<5; i++){
                auto temp = randgen<256>();
                std::vector<aes::byte> key;
                for(size_t i =0; i<32; i++){
                        key.push_back(temp.at(i));
                }
                keys.push_back(key);
                std::vector<aes::word>expandedKey(aes::NB*(Nr+1));
                aes::key_expansion(key,expandedKey, Nk,Nr);
                expandedKeys.push_back(expandedKey);
        }
        auto temp =randgen<128>();
        std::vector<aes::byte> arr;
        for(size_t i=0; i<16; i++){
                arr.push_back(temp.at(i));
        }
        aes::state text = ciphermodes::convert_block_to_state(arr);
        std::random_device rd;
        std::mt19937 g(rd());
        for (std::size_t l = 0; l < RUN_COUNT; ++l) {
                std::shuffle(shuffleVector.begin(), shuffleVector.end(), g); // Shuffle order of execution for each run
                for (const auto& i : shuffleVector) {
                        std::vector<aes::word> val = expandedKeys[i];
                        std::state state = text;
                        auto enc_start = std::chrono::steady_clock::now();
                        aes::encrypt(Nr, state, val);
                        auto enc_end = std::chrono::steady_clock::now();
                        auto enc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(enc_end - enc_start).count();
                        avg_runtimes[i] = (avg_runtimes[i] * l + enc_ns) / static_cast<double>(l + 1);
                }
        }
	std::cout <<"==========AES256 KEY TIMING TEST==========\n";
        std::cout<<"PlainText: ";
        aes::debug_print_state(text[i]);
        printf("\n");
        for (std::size_t i = 0; i < 5; ++i) {
                std::cout<<"Key: ";
                for(unsigned char chr : keys[i]){
                        printf("0x%02x ", chr);
                }
                std::cout << "Average runtime (ns):"<<static_cast<int>(avg_runtimes[i])<<"\n";
        }
        std::cout <<"==========END AES256 KEY TIMING TEST==========\n";
}


void tb::test_aes(){

        // aes::state state = {{
    //     {0x32, 0x88, 0x31, 0xe0},
    //     {0x43, 0x5a, 0x31, 0x37},
    //     {0xf6, 0x30, 0x98, 0x07},
    //     {0xa8, 0x8d, 0xa2, 0x34}
    // }};

    // aes::encrypt(Nr, state, expandedKey);
    // aes::__debug_print_state(state);
    // aes::decrypt(Nr, state, expandedKey);
    // aes::__debug_print_state(state);
 
    aes::state state = {{{0x19, 0xa0, 0x9a, 0xe9},
                         {0x3d, 0xf4, 0xc6, 0xf8},
                         {0xe3, 0xe2, 0x8d, 0x48},
                         {0xbe, 0x2b, 0x2a, 0x08}}};

    std::cout << "Testing sub bytes:\n";

    // Sub bytes test (using state from NIST)
    aes::debug_print_state(state);
    aes::sub_bytes(state);
    aes::debug_print_state(state);
    aes::inv_sub_bytes(state);
    aes::debug_print_state(state);

    std::cout << "Testing Shift Rows:\n";

    // shift rows test (using state from NIST)
    aes::state state3 = {{{0xd4, 0xe0, 0xb8, 0x1e},
                          {0x27, 0xbf, 0xb4, 0x41},
                          {0x11, 0x98, 0x5d, 0x52},
                          {0xae, 0xf1, 0xe5, 0x30}}};
    aes::debug_print_state(state3);
    aes::shift_rows(state3);
    aes::debug_print_state(state3);
    aes::inv_shift_rows(state3);
    aes::debug_print_state(state3);

    std::cout << "Testing Mix Columns:\n";

    aes::state state2 = {{{0xd4, 0xe0, 0xb8, 0x1e},
                          {0xbf, 0xb4, 0x41, 0x27},
                          {0x5d, 0x52, 0x11, 0x98},
                          {0x30, 0xae, 0xf1, 0xe5}}};
    aes::debug_print_state(state2);
    aes::mix_columns(state2);
    aes::debug_print_state(state2);
    aes::inv_mix_columns(state2);
    aes::debug_print_state(state2);

    std::cout << "Testing Add Round Key:\n";
    aes::state state4 = {{{0x04, 0xe0, 0x48, 0x28},
                          {0x66, 0xcb, 0xf8, 0x06},
                          {0x81, 0x19, 0xd3, 0x26},
                          {0xe5, 0x9a, 0x7a, 0x4c}}};

    // NIST standard shows AddRoundKey() called with a slice of the word schedule
    // array
    // the slice consists of 4 words
    // a helper function will need to be made to extract our own slices/round keys
    aes::state roundKeyValue = {{{0xa0, 0x88, 0x23, 0x2a},
                                 {0xfa, 0x54, 0xa3, 0x6c},
                                 {0xfe, 0x2c, 0x39, 0x76},
                                 {0x17, 0xb1, 0x39, 0x05}}};

    aes::debug_print_state(state4);
    aes::add_round_key(state4, roundKeyValue);
    aes::debug_print_state(state4);
    aes::add_round_key(state4, roundKeyValue);
    aes::debug_print_state(state4);

    std::cout <<"Testing Manual Calculation of S-Box:\n";
    aes::byte b = 0U;
    for (std::size_t i = 0; i < 256; i++)
    {
        aes::byte sbox = aes::get_S_BOX_value(b);
        printf("0x%02x  ", sbox);
        if (i % 16 == 15) {
            printf("\n");
        }
        b += 1U;
    }
    printf("\n\n");
    
    std::cout << "Testing Manual Calculation of Inverse S-Box:\n";
    b = 0U;
    for (std::size_t i = 0; i < 256; i++)
    {
        aes::byte sbox = aes::get_inverse_S_BOX_value(b);
        printf("0x%02x  ", sbox);
        if (i % 16 == 15) {
            printf("\n");
        }
        b += 1U;
    }  
}
