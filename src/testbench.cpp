#include "testbench.hpp"


#include <algorithm>
#include <cassert>
#include <chrono>
#include <random>
#include "ciphermodes.hpp"

void tb::test_modules(unsigned long test_flags) {
    if (test_flags | TEST_NO_CACHE) {
        __test_no_cache_lookup_timing();
    }
}
void tb::__test_no_cache_lookup_timing() {
    const unsigned int RUN_COUNT = 10000;

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

void tb::test_ofm_mode_accuracy(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes) {
    std::cout <<"==========OFM TEST==========\n";

    std::cout << "Plaintext\n";
    __print_vector<aes::byte>(plaintext_bytes);
    
    aes::CipherTuple cipher_tuple = ciphermodes::OFM_Encrypt(plaintext_bytes, key_bytes);
    std::cout << "OFM Ciphertext\n";
    __print_vector<aes::byte>(cipher_tuple.element2);

    auto decrypted_plaintext_bytes = ciphermodes::OFM_Decrypt(cipher_tuple.element2, key_bytes, cipher_tuple.element1);
    std::cout << "OFM Decrypted\n";
    __print_vector<aes::byte>(decrypted_plaintext_bytes);


    for (int i = 0; i < decrypted_plaintext_bytes.size(); ++i) {
        assert(plaintext_bytes[i] == decrypted_plaintext_bytes[i] && "Decryption does not match!");
    }

    std::cout <<"==========END OFM TEST==========\n";
}


void tb::test_ecb_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){
    std::cout <<"==========ECB TEST==========\n";

    std::cout << "Plaintext\n";
    __print_vector<aes::byte>(plaintext_bytes);

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::ECB_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nECB Ciphertext:\n";
    __print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::ECB_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nECB Decrypted:\n";
    __print_vector<aes::byte>(decrypted_bytes);

    for (int i = 0; i < decrypted_bytes.size(); ++i) {
        assert(plaintext_bytes[i] == decrypted_bytes[i] && "Decryption does not match!");
    }
    std::cout <<"==========END ECB TEST==========\n";
}


void tb::test_ctr_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){

    std::cout <<"==========CTR TEST==========\n";

    std::cout << "Plaintext\n";
    __print_vector<aes::byte>(plaintext_bytes);

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::CTR_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nCTR Ciphertext:\n";
    __print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::CTR_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nCTR Decrypted:\n";
    __print_vector<aes::byte>(decrypted_bytes);

     for (int i = 0; i < decrypted_bytes.size(); ++i) {
        assert(plaintext_bytes[i] == decrypted_bytes[i] && "Decryption does not match!");
    }
    std::cout <<"==========END CTR TEST==========\n";
}



void tb::test_cbc_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){

    std::cout <<"==========CBC TEST==========\n";
    
    std::cout << "Plaintext\n";
    __print_vector<aes::byte>(plaintext_bytes);
    
    aes:: Tuple<std::vector <aes::byte>, std::vector<aes::byte>> ciphertext = ciphermodes::CBC_Encrypt(plaintext_bytes, key_bytes);

    std::vector<aes::byte> IV = ciphertext.element1;
    std::vector<aes::byte> ciphertext_bytes = ciphertext.element2;
    
    
    std::cout << "\nCBC Ciphertext:\n";
    __print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::CBC_Decrypt(ciphertext_bytes, key_bytes, IV);
    
    std::cout << "\nCBC Decrypted:\n";
    __print_vector<aes::byte>(decrypted_bytes);
    
    for (int i = 0; i < decrypted_bytes.size(); ++i) {
        assert(plaintext_bytes[i] == decrypted_bytes[i] && "Decryption does not match!");
    }

    std::cout <<"==========END CBC TEST==========\n";
}


void tb::test_cfb_mode(std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes){

    std::cout <<"==========CFB TEST==========\n";

    std::vector<aes::byte> ciphertext_bytes = ciphermodes::CFB_Encrypt(plaintext_bytes, key_bytes);

    std::cout << "\nCFB Ciphertext:\n";
    __print_vector<aes::byte>(ciphertext_bytes);

    std::vector<aes::byte> decrypted_bytes = ciphermodes::CFB_Decrypt(ciphertext_bytes, key_bytes);

    std::cout << "\nCFB Decrypted:\n";
    __print_vector<aes::byte>(decrypted_bytes);
    
    for (int i = 0; i < decrypted_bytes.size(); ++i) {
        assert(plaintext_bytes[i] == decrypted_bytes[i] && "Decryption does not match!");
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
        std::cerr << "Invalid Key Length for AES!\n";
        exit(1);
    }
    // create a vector to store expanded key
    std::vector<aes::word> expandedKey(aes::NB * (Nr + 1));

    aes::key_expansion(key_bytes, expandedKey, Nk, Nr);

    //DEBUGGING: confirm if key expansion is correct for a 128,192, 256 bit key:
    int expand = (Nk == 4) ? 43 : (Nk == 6) ? 51 : 59; 
    for(int i = 0; i <= expand; i++){
        printf("0x%02x \n", expandedKey[i]);
    }
    std::cout <<"==========END KEY EXPANSION TEST==========\n";
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
    aes::__debug_print_state(state);
    aes::sub_bytes(state);
    aes::__debug_print_state(state);
    aes::inv_sub_bytes(state);
    aes::__debug_print_state(state);

    std::cout << "Testing Shift Rows:\n";

    // shift rows test (using state from NIST)
    aes::state state3 = {{{0xd4, 0xe0, 0xb8, 0x1e},
                          {0x27, 0xbf, 0xb4, 0x41},
                          {0x11, 0x98, 0x5d, 0x52},
                          {0xae, 0xf1, 0xe5, 0x30}}};
    aes::__debug_print_state(state3);
    aes::shift_rows(state3);
    aes::__debug_print_state(state3);
    aes::inv_shift_rows(state3);
    aes::__debug_print_state(state3);

    std::cout << "Testing Mix Columns:\n";

    aes::state state2 = {{{0xd4, 0xe0, 0xb8, 0x1e},
                          {0xbf, 0xb4, 0x41, 0x27},
                          {0x5d, 0x52, 0x11, 0x98},
                          {0x30, 0xae, 0xf1, 0xe5}}};
    aes::__debug_print_state(state2);
    aes::mix_columns(state2);
    aes::__debug_print_state(state2);
    aes::inv_mix_columns(state2);
    aes::__debug_print_state(state2);

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

    aes::__debug_print_state(state4);
    aes::add_round_key(state4, roundKeyValue);
    aes::__debug_print_state(state4);
    aes::add_round_key(state4, roundKeyValue);
    aes::__debug_print_state(state4);

    aes::byte b = 0U;
    for (std::size_t i = 0; i < 256; i++)
    {
        aes::byte sbox = aes::__get_S_BOX_value(b);
        printf("0x%02x  ", sbox);
        if (i % 16 == 15) {
            printf("\n");
        }
        b += 1U;
    }
    printf("\n\n");
    b = 0U;
    for (std::size_t i = 0; i < 256; i++)
    {
        aes::byte sbox = aes::__get_inverse_S_BOX_value(b);
        printf("0x%02x  ", sbox);
        if (i % 16 == 15) {
            printf("\n");
        }
        b += 1U;
    }  
}