#ifndef CIPHERMODES_HPP
#define CIPHERMODES_HPP

/**
 * Defines functionality and data-types required for the implementation of cipher modes of operation
 **/

#include "aes.hpp"

// namespace aes
namespace ciphermodes {
     /**
     * @brief Pads plaintext according to PKCS #7 [Add hex representation of b repeated b times]
     * 
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     */
    void pad_plaintext(std::vector<aes::byte>& plaintext_bytes);

    /**
     * @brief Populate vector of blocks;
     * A new block is created every 128 bytes, it is possible that the final block is not a complete 128 bytes since
     * not all modes of operation require padding
     * 
     * @param plaintext_blocks: Vector of Vectors where each subvector contains 128 bytes from the plaintext/padding
     * @param plaintext_bytes: Vector containing the bytes of the plaintext
     */
    void create_blocks(std::vector<std::vector<aes::byte> >& plaintext_blocks,std::vector<aes::byte> plaintext_bytes);
} // end of namespace ciphermodes

#endif
