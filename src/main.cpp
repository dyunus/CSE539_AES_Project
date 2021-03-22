#include "aes.hpp"
#include "yandom.hpp"
#include <fstream> // File I/O
#include <iostream>
#include <string>
#include <vector>
#include <chrono>


auto read_binary_file(const char *file_name, std::vector<aes::byte> &vec)
{
    std::ifstream file(file_name, std::ios::in | std::ios::binary);

    if (!file.is_open())
    {
        // Was not able to open this file
        std::cerr << "Unable to open " << file_name << "!\n";
        exit(1);
    }

    char byte_in{};
    while (file.read(&byte_in, 1) && (byte_in != EOF || !file.eof()))
    {
        vec.push_back(static_cast<aes::byte>(byte_in));
    }
}
auto main(int argc, const char *argv[]) -> int
{
    // Sanity checks for file input
    if (argc != 3)
    {
        std::cerr << "Must provide a file-input and keyfile!\n";
        exit(1);
    }

    std::vector<aes::byte> plaintext_bytes;
    std::vector<aes::byte> key_bytes;
    int Nk = -1;
    int Nr = -1;

    // Read file
    read_binary_file(argv[1], plaintext_bytes);

    // Read key
    read_binary_file(argv[2], key_bytes);

    // determine Nk and Nr
    if (key_bytes.size() == 16)
    {
        Nk = 4;
        Nr = 10;
    }

    else if (key_bytes.size() == 24)
    {
        Nk = 6;
        Nr = 12;
    }

    else if (key_bytes.size() == 32)
    {
        Nk = 8;
        Nr = 14;
    }

    else
    {
        std::cerr << "Invalid Key Length for AES!\n";
        exit(1);
    }

    // create a vector to store expanded key
    std::vector<aes::word> expandedKey(aes::NB * (Nr + 1));

    aes::key_expansion(key_bytes, expandedKey, Nk, Nr);

    // debug statemetns to confirm if key expansion is correct for a 128,192, 256
    // bit key:
    int expand = (Nk == 4) ? 43 : (Nk == 6) ? 51
                                            : 59;
    for (int i = 0; i <= expand; i++)
    {
        printf("0x%02x \n", expandedKey[i]);
    }

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
    for (int i = 0; i < 256; i++)
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
    for (int i = 0; i < 256; i++)
    {
        aes::byte sbox = aes::__get_inverse_S_BOX_value(b);
        printf("0x%02x  ", sbox);
        if (i % 16 == 15) {
            printf("\n");
        }
        b += 1U;
    }

    // Accuracy and timing check
    for (int i = 0; i < 256; ++i) {
        auto cache_start = std::chrono::steady_clock::now();
        aes::byte val = aes::S_BOX.at(i);
        auto cache_end = std::chrono::steady_clock::now();
        auto ncache_start = std::chrono::steady_clock::now();
        aes::byte val_other = no_cache_lookup(i, aes::S_BOX.data());
        auto ncache_end = std::chrono::steady_clock::now();


        if (val != val_other) {
            std::cerr << "Val " << static_cast<int>(val) << " does not equal val_other " << static_cast<int>(val_other) 
            << "for index " << i << "\n";
            exit(1);
        } else {
            std::cout << static_cast<int>(val) << " (" 
                    << std::chrono::duration_cast<std::chrono::nanoseconds>(cache_end - cache_start).count()
                    << "ns)" 
                    << " == " << static_cast<int>(val_other) << " ("
                    << std::chrono::duration_cast<std::chrono::nanoseconds>(ncache_end - ncache_start).count()
                    << "ns)"
                    << std::endl;
        }
    }
}