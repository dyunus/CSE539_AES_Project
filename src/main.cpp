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

    for (const auto &e : vec) {
        file << e;
    }
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
    const char* message_file_name; //storing the file name when parsing args
    bool plaintext_provided = false;
    bool keyfile_provided = false;
    bool IV_provided = false;
    bool outfile_provided = false;
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

         if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            // Print help information
            printf("%s\n", "Usage: aes_exec [OPTION]...");
            printf("%-40s %s\n", "-h, --help", "Display this help text");
            printf("%-40s %s\n", "-e, --encrypt", "Encrypt a given input");
            printf("%-40s %s\n", "-d, --decrypt", "Decrypt a given input");
            printf("%-40s %s\n", "-m <ecb | cbc | ctr | cfb | ofm>", "Designate a mode of operation");
            printf("%-40s %s\n", "-in <argument>", "Input filename");
            printf("%-40s %s\n", "-out <argument>", "Output filename");
            printf("%-40s %s\n", "-k <argument>", "Specify key for AES");
            printf("%-40s %s\n", "-iv <argument>", "Specify Initialazion Vector for certain modes of operation");
            exit(0);
        }

        if(strncmp(argv[i], "-in", sizeof("-in")) == 0){
            // Read file
            read_binary_file(argv[i+1], input_bytes);
            plaintext_provided = true;
        }

        if(strncmp(argv[i], "-out", sizeof("-out")) == 0){
            message_file_name = argv[i+1];
            outfile_provided = true;
        }

        else if(strncmp(argv[i], "-k", sizeof("-k")) == 0){
            // Read key
            read_binary_file(argv[i+1], key_bytes);
            keyfile_provided = true;
        }
        
        else if(strncmp(argv[i], "-iv", sizeof("-iv")) == 0){
            // Read key
            read_binary_file(argv[i+1], IV_Bytes);
            IV_provided = true;
        }

        else if(strncmp(argv[i], "-d", sizeof("-d")) == 0|| strcmp(argv[i], "--decrypt") == 0){
            decrypt = true;
        }

        else if(strncmp(argv[i], "-e", sizeof("-e")) == 0|| strcmp(argv[i], "--encrypt") == 0){
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

    if(mode == -1){
        std::cerr << "Please designate a mode of operation! USAGE: -m <ecb | cbc | ctr | cfb | ofm>\n";
        exit(1);  
    }
    
    if(encrypt && decrypt){
        std::cerr << "ERROR: Both encryption and decryption options were selected\n";
        exit(1);   
    }

    if(!keyfile_provided){
        std::cerr << "Please provide a keyfile! USAGE: -k <argument>\n";
        exit(1);
    }

    if(!plaintext_provided){
        std::cerr << "Please provide a message file! USAGE: -in <argument>\n";
        exit(1);
    }

    if(!outfile_provided && mode != DEBUG){
        std::cerr << "Please provide an ouput file! USAGE: -out <argument>\n";
        exit(1);
    }

    if(!IV_provided && decrypt && (mode == CBC || mode == OFM)){
        std::cerr << "Please provide an IV file! USAGE: -iv <argument>\n";
        exit(1);  
    }


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
