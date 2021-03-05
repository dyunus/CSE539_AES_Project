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

}
