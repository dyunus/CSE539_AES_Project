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

auto write_binary_file(const char *file_name, std::vector<aes::byte> &vec){
    std::ofstream file(file_name, std::ios::out | std::ios::binary);

    if (!file.is_open()){
        // Was not able to open this file
        std::cerr << "Unable to open " << file_name << "!\n";
        exit(1);
    }
    for (const auto &e : vec) file << e;
}


auto main(int argc, const char *argv[]) -> int{
    // Sanity checks for file input
    // if (argc != 3){
    //     std::cerr << "Must provide a file-input and keyfile!\n";
    //     exit(1);
    // }

    std::vector<aes::byte> input_bytes;
    std::vector<aes::byte> key_bytes;
    std::vector<aes::byte> IV_Bytes;
    const char* message_file_name;
    const char* iv_file_name;
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
    int mode = -1; 


    for(int i = 0; i < argc; i++){
        if(strncmp(argv[i], "-in", sizeof("-in")) == 0){
            // Read file
            read_binary_file(argv[i+1], input_bytes);
        }

        if(strncmp(argv[i], "-out", sizeof("-out")) == 0){
                message_file_name = argv[i+1];
        }

        else if(strncmp(argv[i], "-k", sizeof("-k")) == 0){
            // Read key
            read_binary_file(argv[i+1], key_bytes);
        }
        
        else if(strncmp(argv[i], "-iv", sizeof("-iv")) == 0){
            // Read key
            read_binary_file(argv[i+1], IV_Bytes);
        }

        else if(strncmp(argv[i], "-d", sizeof("-d")) == 0){
            decrypt = true;
        }

        else if(strncmp(argv[i], "-e", sizeof("-e")) == 0){
            encrypt = true;
        }

        else if(strncmp(argv[i], "-m", sizeof("-m")) == 0){
            if(strncmp(argv[i+1], "ecb", sizeof("ecb")) == 0){
                mode = ECB;
            }
            else if(strncmp(argv[i+1], "cbc", sizeof("cbc")) == 0){
                mode = CBC;
            }
            else if(strncmp(argv[i+1], "ctr", sizeof("ctr")) == 0){
                mode = CTR;
            }
            else if(strncmp(argv[i+1], "cfb", sizeof("cfb")) == 0){
                mode = CFB;
            }
            else if(strncmp(argv[i+1], "ofm", sizeof("ofm")) == 0){
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
            write_binary_file(message_file_name, ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::ECB_Decrypt(input_bytes, key_bytes);
            write_binary_file(message_file_name, plaintext);
        }
    }
    
    if(mode == CBC){
        if(encrypt){
            aes:: Tuple<std::vector <aes::byte>, std::vector<aes::byte>> ciphertext = ciphermodes::CBC_Encrypt(input_bytes, key_bytes);
            std::vector <aes::byte> initialization_vector = ciphertext.element1;
            std::vector <aes::byte> encrypted_message = ciphertext.element2;
            write_binary_file("IV", initialization_vector);
            write_binary_file(message_file_name, encrypted_message);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::CBC_Decrypt(input_bytes, key_bytes, IV_Bytes); //NEEDS IV
            write_binary_file(message_file_name, plaintext);
        }
    }

    if(mode == CTR){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::CTR_Encrypt(input_bytes,key_bytes);
            write_binary_file(message_file_name, ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::CTR_Decrypt(input_bytes,key_bytes);
            write_binary_file(message_file_name, plaintext);
        }
    }

    if(mode == CFB){
        if(encrypt){
            std::vector<aes::byte> ciphertext = ciphermodes::CFB_Encrypt(input_bytes,key_bytes);
            write_binary_file(message_file_name, ciphertext);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::CFB_Decrypt(input_bytes,key_bytes);
            write_binary_file(message_file_name, plaintext);
        }
    }

    if(mode == OFM){
        if(encrypt){
            aes::Tuple<std::vector <aes::byte>, std::vector<aes::byte>> ciphertext = ciphermodes::OFM_Encrypt(input_bytes,key_bytes);
            write_binary_file("IV", ciphertext.element1);
            write_binary_file(message_file_name, ciphertext.element2);
        }
        else if(decrypt){
            std::vector<aes::byte> plaintext = ciphermodes::OFM_Decrypt(input_bytes,key_bytes, IV_Bytes);
            write_binary_file(message_file_name, plaintext);
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
