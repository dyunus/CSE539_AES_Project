#ifndef CIPHERMODES_HPP
#define CIPHERMODES_HPP

/**
 * Defines functionality and data-types required for the implementation of cipher modes of operation
 **/

#include "aes.hpp"

namespace ciphermodes {
     /**
     * @brief Pads plaintext according to PKCS #7 [Add hex representation of b repeated b times]
     * 
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     */
    void pad_plaintext(std::vector<aes::byte>& plaintext_bytes);

     /**
     * @brief Unpads plaintext according to PKCS #7 [Add hex representation of b repeated b times]
     * 
     * @param ciphertext_bytes: Vector containing the bytes of the ciphertext
     */
    void unpad_ciphertext(std::vector<aes::byte>& ciphertext_bytes);

     /**
     * @brief Helper function to xor 2 blocks
     * 
     * @param block1: first 128 bit block to XOR
     * @param block2: second 128 bit block to XOR
     */
    auto xor_blocks(std::vector<aes::byte> block1,std::vector<aes::byte> block2) -> std::vector<aes::byte>;
    
    /**
     * @brief Helper function to print the content of a block
     * 
     * @param vec: block whose content will be printed
     */
    void print_blocks(std::vector<aes::byte> vec);

    /**
     * @brief Populate vector of blocks;
     * A new block is created every 128 bits, it is possible that the final block is not a complete 128 bits since
     * not all modes of operation require padding
     * 
     * @param plaintext_blocks: Vector of Vectors where each subvector contains 128 bits from the plaintext/padding
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     */
    auto create_blocks(std::vector<aes::byte> plaintext_bytes) -> std::vector<std::vector<aes::byte> >;

    /**
     * @brief Merge vector of blocks into a single vector of bytes;
     * 
     * @param ciphertext_blocks: Vector of Vectors where each subvector contains 128 bits from the ciphertext
     */
    auto merge_blocks(const std::vector<std::vector<aes::byte>>& ciphertext_blocks) -> std::vector<aes::byte>;

    /**
     * @brief Converts a block (byte vector) into as AES State (4x4 array)
     * 
     * @param block: desired block to convert into an AES state
     */
    auto convert_block_to_state(std::vector<aes::byte> block) -> aes::state;

    
    template <std::size_t BIT_SIZE>
    auto convert_block_to_state(const std::array<aes::byte, BIT_SIZE / 8>& block) -> aes::state {
        int index = 0;
        aes::state state{};
        for(std::size_t j = 0; j < aes::NB; j++) {
            for(std::size_t i = 0; i < aes::NB; i++){
                state[i][j] = block.at(index++);
            }
        }
        return state;
    }

    /**
     * @brief Converts a AES state (4x4 array) into a block (vector of bytes)
     * 
     * @param state: desired AES state to convert into a block
     */
    auto convert_state_to_block(aes::state state) -> std::vector<aes::byte>;

    
    /**
     * @brief Merges the IV bytes and the blocks of the ciphertext into a single vector of bytes with the IV bytes in the front
     *
     * @param IV: array containing the random bytes of the IV
     * @param ciphertext_blocks: vector of blocks containing the ciphertext after encryption
     */
    template <int SIZE>
	auto merge_IV_blocks(const std::array<aes::byte,SIZE>& IV, const std::vector<std::vector<aes::byte>>& ciphertext_blocks) -> std::vector<aes::byte>{
        	std:: vector<aes::byte> ciphertext_bytes;
          std::size_t merge_size = sizeof(aes::byte) * (IV.size() + (ciphertext_blocks.size() * ciphertext_blocks[0].size()));
          ciphertext_bytes.reserve(merge_size);
        	for(auto byte : IV){
                	ciphertext_bytes.push_back(byte);
        	}
        	for(const auto& block: ciphertext_blocks){
                	for(auto byte : block){
                        	ciphertext_bytes.push_back(byte);
                	}
        	}
		return ciphertext_bytes;
	}
    
    /**
     * @brief Creates merges a nonce with a counter to create the state that will be encrypted with AES for CTR Mode
     *
     * @param nonce: 96 bit random nonce 
     * @param counter: counter that is increased with number of blocks being encrypted
     */
    auto create_CTR(std::array<aes::byte,12> nonce, aes::word counter)->aes::state;

    
    /**
     * @brief Extracts the 96bit nonce from the ciphertext and separates the remaining bytes into blocks of length 128 bits
     *
     * @param ciphertext_bytes: the ciphertext being decrypted
     */
    auto create_nonce_blocks(std::vector<aes::byte> ciphertext_bytes) ->aes::Tuple<std::array<aes::byte, 12>, std::vector<std::vector<aes::byte>>>;

    /**
     * @brief Electronic Codebook Encryption;
     * 
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto ECB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Electronic Codebook Decryption;
     * 
     * @param ciphertext_bytes: Vector containing the bytes of the plaintext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto ECB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Counter Mode Encryption;
     *
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto CTR_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;
    
    /**
     * @brief Counter Mode Decryption;
     *
     * @param ciphertext_bytes: Vector containing the bytes of the ciphertext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto CTR_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Cipher Block Chaining Mode Encryption;
     *
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto CBC_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) ->std::vector<aes::byte>;

    /**
     * @brief Cipher Block Mode Decryption;
     *
     * @param ciphertext_bytes: Vector containing the bytes of the ciphertext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto CBC_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Cipher Feedback Mode Encryption;
     *
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto CFB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;
    
    /**
     * @brief Cipher Feedback Mode Decryption;
     *
     * @param ciphertext_bytes: Vector containing the bytes of the ciphertext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto CFB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Outback Feedback Mode Encryption;
     *
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto OFM_Encrypt(const std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Outback Feedback Mode Decryption;
     *
     * @param ciphertext_bytes: Vector containing the bytes of the ciphertext
     * @param key_bytes: Vector containing the bytes of the key
     */
    auto OFM_Decrypt(const std::vector<aes::byte>& ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    /**
     * @brief Genearates a secure AES key of a given key size
     *
     * @param keySize: desired AES key length [128 | 192 | 256]
     */
    auto genKey(int keySize) -> std::vector<aes::byte>;
} // end of namespace ciphermodes

#endif
