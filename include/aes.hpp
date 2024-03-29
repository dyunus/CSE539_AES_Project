#ifndef AES_HPP
#define AES_HPP

/**
 * Defines functionality and data-types required for the implementation of AES
 **/

#ifdef _WIN32
#include <bcrypt.h>
#endif

#include <array>
#include <cstdint> // Standardized types of guaranteed sizes
#include <vector>
#include <iostream>

/**
 * @brief Used to prevent a cache-based side-channel attack that exploits the time-delta between CPU cache and main memory
 * Given an index, loads the entire lookup table into registers, selects the requested byte, and clears state
 * Discussed in Efficient Cache Attacks on AES, and Countermeasures by Eran Tromer, Dag Arne Osvik, and Adi Shamir
 *
 * Furthermore, this declaration is in accordance with EXP56-CPP: Do not call a language with a mismatched language linkage.
 * In specifying that the linked function is in the "C" language, which is best practice for linking with x86 functions,
 * this prevents linking the program to a non C/C++ function that could expose potential vulnerabilities and stack corruption. 
 */
extern "C" uint8_t no_cache_lookup(uint8_t row, uint8_t col, const uint8_t* lookup_table); //  NOLINT(modernize-use-trailing-return-type)  Come on linter, this is C...

// namespace aes
namespace aes
{
    constexpr const unsigned int NB = 4;        // Column count of the State, constant for this standard
    constexpr const unsigned int SBOX_DIM = 16; // S-box utilizes a 16x16 matrix

    /// AES specific type-declarations (as defined in NIST)
    using byte = uint8_t;  // Little-endian sequence of 8 bits
    using word = uint32_t; // Little-endian sequence of 32 bits

    constexpr const std::array<word, 11> Rcon = {0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};


    template<class TYPE1, class TYPE2>
	    struct Tuple{
        Tuple() : element1(), element2() {};

        Tuple(TYPE1 element1, TYPE2 element2) {
          this->element1 = element1;
          this->element2 = element2;
        }

		    TYPE1 element1;
		    TYPE2 element2;
	    };

    using CipherTuple = Tuple<std::vector<aes::byte>, std::vector<aes::byte>>;

    // Templated type aliases for data structure abstraction
    template <class T, std::size_t DIM_X, std::size_t DIM_Y>
    using matrix = std::array<std::array<T, DIM_X>, DIM_Y>;

    using state = matrix<byte, NB, NB>;

    alignas(16) constexpr const std::array<byte, 256> S_BOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    alignas(16) constexpr const std::array<byte, 256>  INV_S_BOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    
    
    /**
     * @brief Helper function that performs byte substitutions
     * 
     * @param state: Reference to AES state being operated upon
     * @param sub_source: Constant reference to source array to use for substitutions
     */
    void swap_bytes(state &state, const std::array<byte, 256> &sub_source);

    /**
     * @brief Performs a non-linear byte substitution upon each byte within the state using the S-box
     * 
     * @param state: Reference to AES state being operated upon
     */
    void sub_bytes(state &state);

    /**
     * @brief Performs a non-linear byte substitution upon each byte within the state using the Inv-S-box
     * 
     * @param state: Reference to AES state being operated upon
     */

    void inv_sub_bytes(state &state);

    /**
     * @brief Performs multiplication times x(represented by byte 0x02) in the finite field of polynomials modulo x^8+x^4+x^3+x+1 
     * 
     * @param s : the byte that represents the polynomial in the finite field that will be multiplied by x
     * @return byte : the result of the multiplication
     */    
    auto field_multiply_by_2(byte s) -> byte;

    /**
     * @brief Performs multiplication between two elements in the finite field of polynomials modulo x^8+x^4+x^3+x+1
     * 
     * @param s : the byte in that represents a polynomial in the finite field
     * @param num : another byte that represents a polynomial in the finite field
     * @return byte 
     */
    auto field_multiply(byte s, uint8_t num) -> byte;

    /**
     * @brief Performs the shift rows AES operaion of all the rows of the state
     * 
     * @param state: reference to the AES state being operated upon
     */
    void shift_rows(state &state);

    /**
     * @brief Performs the inverse shift rows AES operaion of all the rows of the state
     * 
     * @param state: reference to the AES state being operated upon
     */
    void inv_shift_rows(state &state);

    /**
     * @brief Performs the mix columns AES operation on all the columns of the state
     * 
     * @param state: reference to the AES state being operated upon
     */
    void mix_columns(state &state);

    /**
     * @brief  Performs the inverse mix columns AES operation upon all the columns of the state
     * 
     * @param state: reference to the AES state being operated upon
     */
    void inv_mix_columns(state &state);

    /**
     * @brief Splits a 32bit word into an array of 4 8bit bytes
     * 
     * @param word: Reference to word to split into bytes 
     */
    auto splitWord(word word) -> std::array<byte, 4>;

    /**
     * @brief merge 4 given bytes into a single 32bit word
     * 
     * @param b1: First byte in new word
     * @param b2: Second byte in new word
     * @param b3: Third byte in new word
     * @param b4: Last byte in new word
     */
    auto buildWord(byte b1, byte b2, byte b3, byte b4) -> aes::word;

    /**
     * @brief Performs the Add Round Key Operation with a given state and round key
     * the round key is added to the state by a bitwise XOR 
     * @param currState: reference to the AES state being operated upon
     * @param roundKeyValue: refernece to the current round key
     */
    void add_round_key(state &currState, state &roundKeyValue);

    /**
     * @brief Calculates the values of Nk and Nr based on the keysize
     * 
     * @param keySize: size of the key being used for AES encryption/decryption
     */
    auto get_Nk_Nr(int keySize) -> std::array<int, 2>;

    /**
     * @brief Performs the AES key expanstion routine
     * A cipher key is expanded to generate a key schedule
     * @param keyBytes: bytes of the cipher key being used
     * @param w: vector of words of size aes::NB*(nk_nr[1]+1) to store the expanded key
     * @param Nk: Number of 32-bit words comprising the Cipher Key
     * @param Nr: Number of rounds, which is a function of Nk and Nb
     */
    void key_expansion(std::vector<byte> keyBytes, std::vector<word>& w, unsigned int Nk, unsigned int Nr);

    /**
     * @brief Performs a substition of a word using the Sbox
     * 
     * @param word: Reference to word being substituded
     */
    auto subword(word word) -> aes::word;

    /**
     * @brief Performs a rotation of a 32bit word as such: b0,b1,b2,b3 -> b1,b2,b3,b0
     * 
     * @param word: Reference to 32bit word being operated on
     */
    auto rotword(word word) -> aes::word;

    auto spliceKey(unsigned int round, const std::vector<word>& key)-> aes::state;

    /**
     * @brief Performs the AES encryption
     * @param Nr: Number of rounds, which is a function of Nk and Nb
     * @param state: Reference to AES state being operated upon
     * @param w: Reference to the expanded key
     */
    void encrypt(unsigned int Nr, state& state, const std::vector<word>& w);
    
    /**
     * @brief Performs the AES decryption
     * @param Nr: Number of rounds, which is a function of Nk and Nb
     * @param state: Reference to AES state being operated upon
     * @param w: Reference to the expanded key
     */
    void decrypt(unsigned int Nr, state& state, const std::vector<word>& w);    
    
    /**
     *@brief Calculate the position of the most signicant (right-most) bit of the byte given
     *
     *@param s: byte being operated upon
     *@return uint8_t: unsigned integer with the position of the most significant bit
     */
    auto get_most_sig_bit(byte s) -> uint8_t;


    /**
     *@brief Retrieves the inverse modulo x^8+x^4+x^3+x+1 of the given polynomial
     *
     *@param s: byte that represents an element in the finite field modulo x^8+x^4+x^3+x+1
     *@return byte: the inverse polynomial of the given polynomial given in byte form
     */
    auto get_inverse(byte s) -> byte;

    /**
     * @brief Implementation of the Extended Euclidean algorithm which finds r,t such that r(left)+t(right)=gcd(left,right) where gcd is the greatest common divisor
     *
     * @param left: One of the bytes whose greatest common divisor will be found. NOTE, left must be greater than right
     * @param right: One of the bytes whose greatest common divisor will be found. NOTE, right must be less than right
     * @param sigbit: Unsigned integer that represents the most significant bit location of left.
     * @return array<byte,2>: Array that contains the value of r in index 0 and the value of t in index 1
     */
    auto extended_euclidean_algorithm(byte left, byte right, uint8_t sigbit) -> std::array<byte, 2>;

    /**
     * @brief Calculates the S-Box value of the given byte
     *
     * @param s: Byte whose S-Box value we want to find
     * @return byte: The S-Box value associated with the given byte
     */
    auto get_S_BOX_value(byte s) -> byte;

    /**
     * @brief Calculates the inverse S-Box value of the given byte
     *
     * @param s: Byte whose inverse S-Box value we want to find
     * @return byte: The inverse S-Box value associated with the given byte
     */
    auto get_inverse_S_BOX_value(byte s) -> byte;

    /**
     * @brief Used to print the current contents of the state, for debugging purposes
     * 
     * @param state: Constant reference to AES state to be printed
     */
    void debug_print_state(const state &state);

} // end of namespace aes

#endif
