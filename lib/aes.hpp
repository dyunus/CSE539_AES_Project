/**
 * Defines functionality and data-types required for the implementation of AES
 **/

#include <array>    
#include <cstdint>  // Standardized types of guaranteed sizes


namespace aes {
    constexpr const int NB = 4; // Column count of the State, constant for this standard

    /// AES specific type-declarations (as defined in NIST)
    using byte = uint8_t;   // Little-endian sequence of 8 bits
    using word = uint32_t;  // Little-endian sequence of 32 bits

    using state = std::array<std::array<byte, NB>, NB>;


}


/**
 * Todo:
 * Add CMakeLists
 * Add ClangTidy
 **/