#include "aes.hpp"
#include <fstream>  // File I/O
#include <iostream>
#include <string>
#include <vector>

auto main(int argc, const char * argv[]) -> int {
    // Sanity checks for file input
    if (argc != 2) {
        std::cerr << "Must provide a file-input!\n";
        exit(1);
    }

    std::vector<aes::byte> plaintext_bytes;
    std::ifstream plaintext_file(argv[1], std::ios::binary); // TODO(bailey): I don't know if he'd attack us here, but we might need some sanity checks on file input.

    // Read file
    while (plaintext_file) {
        char byte{};
        plaintext_file.get(byte);
        plaintext_bytes.push_back(int(byte));
    }

    aes::state state = {{
        {0x19, 0xa0, 0x9a, 0xe9},
        {0x3d, 0xf4, 0xc6, 0xf8},
        {0xe3, 0xe2, 0x8d, 0x48},
        {0xbe, 0x2b, 0x2a, 0x08}
    }};

    // Sub bytes test (using state from NIST)
    aes::__debug_print_state(state);
    aes::sub_bytes(state);
    aes::__debug_print_state(state);
    aes::inv_sub_bytes(state);
    aes::__debug_print_state(state);



    std::cout << "Testing Shift Rows:\n";
    // shift rows test (using state from NIST)
    aes:: state state3= {{
	    {0xd4, 0xe0, 0xb8, 0x1e},
	    {0x27, 0xbf, 0xb4, 0x41},
	    {0x11, 0x98, 0x5d, 0x52},
	    {0xae, 0xf1, 0xe5, 0x30}
    }};
    aes::__debug_print_state(state3);
    aes::shift_rows(state3);
    aes::__debug_print_state(state3);
    aes::inv_shift_rows(state3);
    aes::__debug_print_state(state3);


    aes:: state state2= {{
	    {0xd4, 0xe0, 0xb8, 0x1e},
	    {0xbf, 0xb4, 0x41, 0x27},
	    {0x5d, 0x52, 0x11, 0x98},
	    {0x30, 0xae, 0xf1, 0xe5}
    }};
    aes::__debug_print_state(state2);
    aes::mix_columns(state2);
    aes::__debug_print_state(state2);
    aes::inv_mix_columns(state2);
    aes::__debug_print_state(state2);


    aes:: state state4= {{
	    {0x04, 0xe0, 0x48, 0x28},
	    {0x66, 0xcb, 0xf8, 0x06},
	    {0x81, 0x19, 0xd3, 0x26},
	    {0xe5, 0x9a, 0x7a, 0x4c}
    }};

    //NIST standard shows AddRoundKey() called with a slice of the word schedule array
    // the slice consists of 4 words
    //a helper function will need to be made to extract our own slices/round keys
    aes:: state roundKeyValue= {{
	    {0xa0, 0x88, 0x23, 0x2a},
	    {0xfa, 0x54, 0xa3, 0x6c},
	    {0xfe, 0x2c, 0x39, 0x76},
	    {0x17, 0xb1, 0x39, 0x05}
    }};
    
    aes::__debug_print_state(state4);
    aes::add_round_key(state4,roundKeyValue);
    aes::__debug_print_state(state4);
    aes::add_round_key(state4,roundKeyValue);
    aes::__debug_print_state(state4);
}
