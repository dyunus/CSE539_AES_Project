#include "aes.hpp"
#include "aes_exceptions.hpp"
#include "ciphermodes.hpp"
#include <fstream> // File I/O
#include <iostream>
#include <string>
#include "testbench.hpp"
#include <vector>
#include <cstring>

auto read_binary_file(const char *file_name, std::vector<aes::byte> &vec){
    /**
     * In accordance with FIO42-C: Close files when they are no longer needed
     * As C++ builds upon the C language through the introduction of RAII (Resource Acquisition Is Initialization),
     * well-formed code should handle "acquiring resources in a constructor and [release] them in a destructor". ~ Bjarne Stroustrup, THE programmer
     * ifstream releases the underlying file resources in its destructor, triggered when it goes out of scope.
     */

    std::ifstream file;
    /**
     * In accordance with ERR50-CPP: Do not abruptly terminate the program
     * This was fixed to use exception handling over the C exit function. 
     * Prior to this project,I wasn't aware that exit() didn't follow RAII standards
     * in stack unwinding and the calling of destructors. 
     * This is especially important as the ifstream above must be allowed to perform destruction
     **/
    file.exceptions(file.exceptions() | std::ifstream::badbit | std::ifstream::failbit); // ERR50-CPP, should throw exception on failure
    file.open(file_name, std::ios::in | std::ios::binary);
    file.exceptions(std::ifstream::goodbit); // No longer should throw exceptions, as eof sets failbit

    char byte_in{};
    while (file.read(&byte_in, 1) && (byte_in != EOF || !file.eof())){
        vec.push_back(static_cast<aes::byte>(byte_in));
    }
}

auto write_binary_file(const char *file_name, std::vector<aes::byte> &vec){
    std::ofstream file;
    file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    file.open(file_name, std::ios::out | std::ios::binary);
    file.exceptions(std::ofstream::goodbit);

    for (const auto &e : vec) {
        file << e;
    }
}


auto main(int argc, const char *argv[]) -> int{
    std::vector<aes::byte> input_bytes;
    std::vector<aes::byte> key_bytes;
    const char* message_file_name = nullptr; //storing the file name when parsing args
    bool plaintext_provided = false;
    bool keyfile_provided = false;
    bool outfile_provided = false;
    bool encrypt = false;
    bool decrypt = false;
    u_int64_t testFlags = 256;
     enum MODES_OF_OPERATION {
        ECB = 0,
        CBC = 1,
        CTR = 2,
        CFB = 3,
        OFM = 4,
        DEBUG = 5,
    };
    int mode = -1;
    try {
      for(int i = 0; i < argc; i++) {

          if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
              // Print help information
              printf("%s\n", "Usage: aes_exec [OPTION]...");
              printf("%-40s %s\n", "-h, --help", "Display this help text");
              printf("%-40s %s\n", "-g <argument>, --gen <argument>",
                     "Generate random key of argument bit length and stores it in a file named genkey");
              printf("%-40s %s\n", "-e, --encrypt", "Encrypt a given input");
              printf("%-40s %s\n", "-d, --decrypt", "Decrypt a given input");
              printf("%-40s %s\n", "-m <ecb | cbc | ctr | cfb | ofm>", "Designate a mode of operation");
              printf("%-40s %s\n", "-in <argument>", "Input filename");
              printf("%-40s %s\n", "-out <argument>", "Output filename");
              printf("%-40s %s\n", "-k <argument>", "Specify key for AES");
              return EXIT_SUCCESS;
          }

          /**
           * In accordance with STR50-CPP. Guarantee that storage for strings has sufficient space
           * for character data and the null terminator.
           * Especially important here, the use of strcmp is frowned upon due to its ability to be used for data leakage with arbitrary reads
           * by ommitting the null-terminator from the argument. Rather, this program explicitly checks up until a maximum of the size of the
           * expected argument.
           *
           **/
          if (strncmp(argv[i], "-g", sizeof("-g")) == 0 || strcmp(argv[i], "--gen") == 0) {
              std::cout << "KEY Generated to file named genkey\n";
                /**
                 * In accordance with ERR34-C and ERR62-CPP. Detect errors when converting a string to a number
                 * The use of conversion functions that do not perform conversion validation such as atoi are banned
                 * std::stoi() performs conversion validation 
                 */
              key_bytes = ciphermodes::genKey(std::stoi(argv[i + 1]));
              write_binary_file("genkey", key_bytes);
              return EXIT_SUCCESS; // ERR50-CPP returning from main is preferable to a naked call to std::exit
          }

          if (strncmp(argv[i], "-in", sizeof("-in")) == 0) {
              // Read file
              std::cout << "IN specified\n";
              read_binary_file(argv[i + 1], input_bytes);
              plaintext_provided = true;
          }

          if (strncmp(argv[i], "-out", sizeof("-out")) == 0) {
              std::cout << "OUT specified\n";
              message_file_name = argv[i + 1];
              outfile_provided = true;
          } else if (strncmp(argv[i], "-k", sizeof("-k")) == 0) {
              // Read key
              std::cout << "KEY specified\n";
              read_binary_file(argv[i + 1], key_bytes);
              keyfile_provided = true;
          } else if (strncmp(argv[i], "-d", sizeof("-d")) == 0 || strcmp(argv[i], "--decrypt") == 0) {
              decrypt = true;
          } else if (strncmp(argv[i], "-e", sizeof("-e")) == 0 || strcmp(argv[i], "--encrypt") == 0) {
              encrypt = true;
          } else if (strncmp(argv[i], "-m", sizeof("-m")) == 0) {
              if (strncmp(argv[i + 1], "ecb", sizeof("ecb")) == 0) {
                  mode = ECB;
              } else if (strncmp(argv[i + 1], "cbc", sizeof("cbc")) == 0) {
                  mode = CBC;
              } else if (strncmp(argv[i + 1], "ctr", sizeof("ctr")) == 0) {
                  mode = CTR;
              } else if (strncmp(argv[i + 1], "cfb", sizeof("cfb")) == 0) {
                  mode = CFB;
              } else if (strncmp(argv[i + 1], "ofm", sizeof("ofm")) == 0) {
                  mode = OFM;
              }
          } else if (strncmp(argv[i], "-D", sizeof("-D")) == 0) {
              mode = DEBUG;
              testFlags = std::stoi(argv[i+1]);
          }
      }

      if(encrypt && decrypt){
          std::cerr << "ERROR: Both encryption and decryption options were selected\n";
          return EXIT_FAILURE;
      }

      if(mode == -1){
          std::cerr << "ERROR: Please designate a mode of operation! USAGE: -m <ecb | cbc | ctr | cfb | ofm>\n";
          return EXIT_FAILURE;
      }

      if(!keyfile_provided && encrypt){
          std::cout << "Keyfile not provided. A keyfile can be provided using the k flag. USAGE: -k <argument>\n";
          std::cout << "A new keyfile can be generated using the genkey command USAGE: -g <argument> | --gen <argument>\nThe key will be stored in a file named genkey\n";
          std::cout << "Since a keyfile was not provided for this encryption, the encryption will be performed with a newly generated 256 bit key which has been saved to a file named genkey\n.";
          key_bytes = ciphermodes::genKey(256);
          write_binary_file("genkey", key_bytes);
      }

      if(!keyfile_provided && !encrypt){
          std::cout << "Keyfile not provided. A keyfile can be provided using the k flag. USAGE: -k <argument>\n";
          std::cout << "A new keyfile can be generated using the genkey command USAGE: -g <argument> | --gen <argument>\nThe key will be stored in a file named genkey\n";
          return EXIT_FAILURE;
      }

     if(!plaintext_provided){
          std::cerr << "ERROR: Please provide a message file! USAGE: -in <argument>\n";
          return EXIT_FAILURE;
      }

      if(!outfile_provided && mode != DEBUG){
          std::cerr << "ERROR: Please provide an ouput file! USAGE: -out <argument>\n";
          return EXIT_FAILURE;
      }
      
      if((mode != DEBUG) && !encrypt && !decrypt){
          std::cerr << "ERROR: Specify encryption or decryption operations!\n";
          return EXIT_FAILURE;
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
              std::vector<aes::byte> ciphertext = ciphermodes::CBC_Encrypt(input_bytes, key_bytes);
              write_binary_file(message_file_name, ciphertext);
          }
          else if(decrypt){
              std::vector<aes::byte> plaintext = ciphermodes::CBC_Decrypt(input_bytes, key_bytes);
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
              std::vector<aes::byte> ciphertext = ciphermodes::OFM_Encrypt(input_bytes,key_bytes);
              write_binary_file(message_file_name, ciphertext);
          }
          else if(decrypt){
              std::vector<aes::byte> plaintext = ciphermodes::OFM_Decrypt(input_bytes,key_bytes);
              write_binary_file(message_file_name, plaintext);
          }
      }

      if(mode == DEBUG) {
	      tb::test_modules(testFlags, input_bytes, key_bytes);
      }
    /**
     * ERR54-CPP : Handle exceptions in order of most derived to least derived
     * In order to prevent a more generic case from beating a more specific, we decided to implement our own
     * subclasses of std::exception in order to have more fine-grained control flow in the catch handlers.
     * Furthermore, the general catch is at the way bottom of the list for those not covered above it.
     **/
    } catch(const aes_error& aes_err) { // All exceptions are captured as const references, in accordance with ERR61-CPP
        std::cerr << aes_err.what();
        return EXIT_FAILURE;
    } catch (const std::ifstream::failure& e) {
        std::cerr << "Unable to open file for reading.\n"
                << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (const std::ofstream::failure& e) {
        std::cerr << "Unable to open file for writing.\n"
                << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (const testbench_error& e) {
        std::cerr << "Error in testbench function: " << e.where() << "\n"
                << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (...) {
        /**
        * In accordance with ERR51-CPP: Handle all exceptions
        * Prior to this, I thought it was bad-practice to use a generic catch for three reasons:
        * 1) It felt lazy to have a generic catch
        * 2) I didn't know exceptions handled stack unwinding for a more graceful program exit
        * 3) I wasn't aware of the C++11 feature that allows you to capture the context's current exception for printing
        **/
        std::exception_ptr excep_ptr = std::current_exception();
        std::cerr << "Uncaught exception handled.\n";
        return EXIT_FAILURE;
    }
}
