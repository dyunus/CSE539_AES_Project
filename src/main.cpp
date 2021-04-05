#include "aes.hpp"
#include "ciphermodes.hpp"
#include <fstream> // File I/O
#include <iostream>
#include <string>
#include "testbench.hpp"
#include <vector>
#include "yandom.hpp"

auto read_binary_file(const char *file_name, std::vector<aes::byte> &vec){
    std::ifstream file(file_name, std::ios::in | std::ios::binary);

    if (!file.is_open()){
        // Was not able to open this file
        std::cerr << "Unable to open " << file_name << "!\n";
        exit(1);
    }

    char byte_in{};
    while (file.read(&byte_in, 1) && (byte_in != EOF || !file.eof())){
        vec.push_back(static_cast<aes::byte>(byte_in));
    }
}

auto main(int argc, const char *argv[]) -> int{
    // Sanity checks for file input
    if (argc != 3){
        std::cerr << "Must provide a file-input and keyfile!\n";
        exit(1);
    }

    std::vector<aes::byte> plaintext_bytes;
    std::vector<aes::byte> key_bytes;

    // Read file
    read_binary_file(argv[1], plaintext_bytes);

    // Read key
    read_binary_file(argv[2], key_bytes);

    test_modules(tb::TEST_NO_CACHE);

    tb::test_ecb_mode(plaintext_bytes, key_bytes);

    tb::test_ctr_mode(plaintext_bytes, key_bytes);

    tb::test_cbc_mode(plaintext_bytes, key_bytes);

    tb::test_cfb_mode(plaintext_bytes, key_bytes);

    tb::test_ofm_mode_accuracy(plaintext_bytes, key_bytes);
   
    tb::test_key_expansion(key_bytes);

    tb::test_aes();
}
