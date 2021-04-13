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

    void unpad_ciphertext(std::vector<aes::byte>& ciphertext_bytes);

    auto xor_blocks(std::vector<aes::byte> block1,std::vector<aes::byte> block2) -> std::vector<aes::byte>;
    
    
    void print_blocks(std::vector<aes::byte> vec);
    /**
     * @brief Populate vector of blocks;
     * A new block is created every 128 bytes, it is possible that the final block is not a complete 128 bytes since
     * not all modes of operation require padding
     * 
     * @param plaintext_blocks: Vector of Vectors where each subvector contains 128 bytes from the plaintext/padding
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     */
    auto create_blocks(std::vector<aes::byte> plaintext_bytes) -> std::vector<std::vector<aes::byte> >;


    auto merge_blocks(const std::vector<std::vector<aes::byte>>& ciphertext_blocks) -> std::vector<aes::byte>;

    auto convert_block_to_state(std::vector<aes::byte> block) -> aes::state;

    template <std::size_t BIT_SIZE>
    auto convert_block_to_state(const std::array<aes::byte, BIT_SIZE / 8>& block) -> aes::state {
        int index = 0;
        aes::state state{};
        for(std::size_t j = 0; j < aes::NB; j++) {
            for(std::size_t i = 0; i < aes::NB; i++){
                state[i][j] = block[index++];
            }
        }
        return state;
    }

    auto convert_state_to_block(aes::state state) -> std::vector<aes::byte>;

    template <int SIZE>
	auto merge_IV_blocks(std::array<aes::byte,SIZE> IV, std::vector<std::vector<aes::byte>> ciphertext_blocks) -> std::vector<aes::byte>{
        	std:: vector<aes::byte> ciphertext_bytes;
        	for(auto byte : IV){
                	ciphertext_bytes.push_back(byte);
        	}
        	for(auto block: ciphertext_blocks){
                	for(auto byte : block){
                        	ciphertext_bytes.push_back(byte);
                	}
        	}
		return ciphertext_bytes;
	}
    
    auto create_CTR(std::array<aes::byte,12> nonce, aes::word counter)->aes::state;

    auto create_nonce_blocks(std::vector<aes::byte> ciphertext_bytes) ->aes::Tuple<std::array<aes::byte, 12>, std::vector<std::vector<aes::byte>>>;

    /**
     * @brief Electronic Codebook;
     * 
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     * @param expanded_key: Vector containing the bytes of the expanded key
     * @param number_rounds: number of rounds that AES will perform
     */
    auto ECB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;
    auto ECB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    auto CTR_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;
    auto CTR_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    auto CBC_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) ->std::vector<aes::byte>;
    auto CBC_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

    auto CFB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;
    auto CFB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;


    auto OFM_Encrypt(const std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;
    auto OFM_Decrypt(const std::vector<aes::byte>& ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>;

} // end of namespace ciphermodes

#endif
