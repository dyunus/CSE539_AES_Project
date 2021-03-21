#include "aes.hpp"
#include "ciphermodes.hpp"
#include <fstream>  // File I/O
#include <iostream>
#include <string>
#include <vector>

auto main(int argc, const char * argv[]) -> int {
    // Sanity checks for file input
    if (argc != 3) {
        std::cerr << "Must provide a file-input and keyfile!\n";
        exit(1);
    }

    std::vector<aes::byte> plaintext_bytes;
    std::vector<std::vector<aes::byte> > plaintext_blocks;
    std::vector<aes::byte> key_bytes;
    std::ifstream plaintext_file(argv[1], std::ios::binary); // TODO(bailey): I don't know if he'd attack us here, but we might need some sanity checks on file input.
    std::ifstream key_file(argv[2], std::ios::binary);
    int Nk = -1;
    int Nr = -1;
    // Read file
    while (plaintext_file) {
        char byte{};
        plaintext_file.get(byte);
        plaintext_bytes.push_back(int(byte));
    }
    //appears our way of reading a file appends a 0 at the end uncessarily, this trims it as a quick dirty patch
    plaintext_bytes.pop_back();

    std::cout << "PLAINTEXT SIZE: " << plaintext_bytes.size() << std::endl;

    //Pad File if needed according to PKCS #7
    bool padding = true; //TODO: replace with a decision based on mode of operation selected
    if(padding){ciphermodes::pad_plaintext(plaintext_bytes);}

    std::cout << "PLAINTEXT SIZE AFTER POTENTIAL PADDING: " << plaintext_bytes.size() << std::endl;

    //Populate vector of blocks
    //A new block is created every 128 bytes, it is possible that the final block is not a complete 128 bytes since not all modes of operation require padding
    ciphermodes::create_blocks(plaintext_blocks, plaintext_bytes);


    //DEBUGGING:Output each block
        for(int i = 0; i < plaintext_blocks.size(); i++){
            std::cout << "BLOCK #" << i << std::endl;
            for(int j = 0; j < plaintext_blocks[i].size(); j++){
                printf("0x%02x  ", plaintext_blocks[i][j]);
            }
            std::cout << std::endl;
    }

    // Read key
    while (key_file) {
        char byte{};
        key_file.get(byte);
        key_bytes.push_back(int(byte));
    }

    //appears our way of reading a file appends a 0 at the end uncessarily, this trims it as a quick dirty patch
    key_bytes.pop_back();

    //determine Nk and Nr
    if(key_bytes.size() == 16){Nk = 4; Nr = 10;}

    else if(key_bytes.size() == 24){Nk = 6;Nr = 12;}

    else if(key_bytes.size() == 32){Nk = 8;Nr = 14;}

    else{std::cerr << "Invalid Key Length for AES!\n"; exit(1);}

    //create a vector to store expanded key
    std::vector<aes::word> expandedKey(aes::NB*(Nr+1));

    aes::key_expansion(key_bytes, expandedKey, Nk, Nr);

    //DEBUGGING: confirm if key expansion is correct for a 128,192, 256 bit key:
    int expand = (Nk == 4) ? 43 : (Nk == 6) ? 51 : 59; 
    for(int i = 0; i <= expand; i++){
        printf("0x%02x \n", expandedKey[i]);
    }
    

    aes::state state = {{
        {0x32, 0x88, 0x31, 0xe0},
        {0x43, 0x5a, 0x31, 0x37},
        {0xf6, 0x30, 0x98, 0x07},
        {0xa8, 0x8d, 0xa2, 0x34}
    }};

    aes::encrypt(Nr, state, expandedKey);
    aes::__debug_print_state(state);
    aes::decrypt(Nr, state, expandedKey);
    aes::__debug_print_state(state);
}
