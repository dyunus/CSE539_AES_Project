#include "aes.hpp"
#include <fstream>  // File I/O
#include <iostream>
#include <string>
#include <vector>

int main(int argc, const char * argv[]) {
    // Sanity checks for file input
    if (argc != 2) {
        fprintf(stderr, "Must provide a file-input!\n");
        exit(1);
    }

    std::vector<aes::byte> plaintext_bytes;
    std::ifstream plaintext_file(argv[1], std::ios::binary); // TODO: I don't know if he'd attack us here, but we might need some sanity checks on file input.

    // Read file
    while (plaintext_file) {
        char byte{};
        plaintext_file.get(byte);
        plaintext_bytes.push_back(int(byte));
    }

}