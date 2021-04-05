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

    std::vector<aes::byte> input_bytes;
    std::vector<aes::byte> key_bytes;
    std::vector<aes::byte> IV_Bytes;
    bool plaintext_provided = false;
    bool keyfile_provided = false;
    bool encrypt = false;
    bool decrypt = false;
     enum MODES_OF_OPERATION {
        ECB = 0,
        CBC = 1,
        CTR = 2,
        CFB = 3,
        OFM = 4,
        DEBUG = 5,
    };
    bool mode = -1; 



    for(int i = 0; i < argc; i++){
        if(strncmp(argv[i], "-in", sizeof("-in")) == 0){
            // Read file
            read_binary_file(argv[i+1], input_bytes);
            i++;
        }

        else if(strncmp(argv[i], "-k", sizeof("-k")) == 0){
            // Read key
            read_binary_file(argv[i+1], key_bytes);
            i++;
        }
        
        else if(strncmp(argv[i], "-iv", sizeof("-iv")) == 0){
            // Read key
            read_binary_file(argv[i+1], IV_Bytes);
            i++;
        }

        else if(strncmp(argv[i], "-d", sizeof("-d")) == 0){
            decrypt = true;
        }

        else if(strncmp(argv[i], "-e", sizeof("-e")) == 0){
            encrypt = true;
        }

        else if(strncmp(argv[i], "-m", sizeof("-m")) == 0){
            i++;
            if(strncmp(argv[i], "-ecb", sizeof("-ecb")) == 0){
                mode = ECB;
            }
            else if(strncmp(argv[i], "-cbc", sizeof("-cbc")) == 0){
                mode = CBC;
            }
            else if(strncmp(argv[i], "-ctr", sizeof("-ctr")) == 0){
                mode = CTR;
            }
            else if(strncmp(argv[i], "-cfb", sizeof("-cfb")) == 0){
                mode = CFB;
            }
            else if(strncmp(argv[i], "-ofm", sizeof("-ofm")) == 0){
                mode = OFM;
            }
        }
        else if(strncmp(argv[i], "-D", sizeof("-D")) == 0){
            mode = DEBUG;
        }
    }

    //ecb: 0
    //cbc: 1
    //ctr: 2
    //cfb: 3
    //ofm: 4
    //DEBUGGING: 5

    if(mode == ECB){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::ECB_Encrypt(input_bytes, key_bytes);
            ciphermodes::print_blocks(ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::ECB_Encrypt(input_bytes, key_bytes);
            ciphermodes::print_blocks(plaintext);
        }
    }
    
    if(mode == CBC){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::CBC_Encrypt(input_bytes, key_bytes);
            ciphermodes::print_blocks(ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::CBC_Decrypt(input_bytes, key_bytes, IV_Bytes); //NEEDS IV
            ciphermodes::print_blocks(plaintext);
        }
    }

    if(mode == CTR){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::CTR_Encrypt(input_bytes,key_bytes);
            ciphermodes::print_blocks(ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::CTR_Decrypt(input_bytes,key_bytes);
            ciphermodes::print_blocks(plaintext);
        }
    }

    if(mode == CFB){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::CFB_Encrypt(input_bytes,key_bytes);
            ciphermodes::print_blocks(ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::CFB_Decrypt(input_bytes,key_bytes);
            ciphermodes::print_blocks(plaintext);
        }
    }

    if(mode == OFM){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::OFM_Encrypt(input_bytes,key_bytes);
            ciphermodes::print_blocks(ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::OFM_Decrypt(input_bytes,key_bytes, IV_Bytes);
            ciphermodes::print_blocks(plaintext);
        }
    }

    if(mode == DEBUG){
        test_modules(tb::TEST_NO_CACHE);

        tb::test_ecb_mode(input_bytes, key_bytes);

        tb::test_cbc_mode(input_bytes, key_bytes);

        tb::test_ctr_mode(input_bytes, key_bytes);

        tb::test_cfb_mode(input_bytes, key_bytes);

        tb::test_ofm_mode_accuracy(input_bytes, key_bytes);
    
        tb::test_key_expansion(key_bytes);

        tb::test_aes();
    }
}
