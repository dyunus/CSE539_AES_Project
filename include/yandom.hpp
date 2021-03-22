#ifndef KEYGEN_HPP
#define KEYGEN_HPP

#ifdef _WIN32

//  Windows
#define cpuid(info, x)    __cpuidex(info, x, 0)

#else
#include <cpuid.h>

void cpuid(unsigned int info[4], int InfoType);
#endif // CPUID


#include "aes.hpp"
#include <cassert>
#include <fstream>
#include <immintrin.h>
#include <iostream>

constexpr const uint64_t RDSEED_FLAG = 0x40000; // 18th bit asserted

/**
 * @brief Preferred solution for RNG (Hardware based solution)
 * 
 * Utilizes Intel's RDSEED instruction (a cryptographic RNG that complies with the cryptographic standards set forth
 * in NIST SP 800-90A)
 * 
 * @tparam rand_len_bits : Length of the random number to generate, in bits.
 * @return std::array<aes::byte, RAND_LEN / 8> : A collection of bytes produced from a hardware RNG
 */
template<std::size_t RAND_LEN>
auto __rdseed_rand() -> std::array<aes::byte, RAND_LEN / 8> {
    // Sadly Intel Intrinsics insists on using ull over uint64_t. 
    static_assert(sizeof(uint64_t) == sizeof(unsigned long long), "ULL must be 64bit! Change compilers.");    

    aes::byte keygen_rounds = RAND_LEN / 64;
    std::array<aes::byte, RAND_LEN / 8> key_bytes{};

    for (int r = 0; r < keygen_rounds; ++r) {     
        unsigned long long key_portion{};
        assert(_rdseed64_step(&key_portion)); // Returns 0 on failure (sometimes it's too fast)

        // Extract 8 bits from 64-bit random key-chunk
        auto* byte_ptr = reinterpret_cast<aes::byte*>(&key_portion);
        for (std::size_t i = 0; i < 8; ++i) {
            key_bytes.at(r*8 + i) =byte_ptr[i];
        }            
    }

    return key_bytes;
}


/**
 * @brief Used as a means of preventing DoS attacks against the system's available entropy
 * Only functional on Linux-like distributions that support the entropy pool file
 * @return unsigned int : The system's available entropy pool-size.
 */
auto __get_available_entropy() -> unsigned int;


/**
 * @brief 
 * 
 * @param rand_len_bits 
 * @return std::array<aes::byte, RAND_LEN / 8> 
 */
template<std::size_t RAND_LEN>
auto __os_randgen() -> std::array<aes::byte, RAND_LEN / 8> {
    aes::byte keygen_rounds = RAND_LEN / sizeof(uint64_t);
    std::array<aes::byte, RAND_LEN / 8> key_bytes{};

#ifdef _WIN32
    // The newest CSPRNG API exposed by Microsoft, the default RNG complies with NIST SP800-90     
    // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
    // https://www.microsoft.com/security/blog/2019/11/25/going-in-depth-on-the-windows-10-random-number-generation-infrastructure/
    NTSTATUS status_code = BCryptGenRandom(
        nullptr,
        key_bytes.data(),
        RAND_LEN / 8,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status_code != STATUS_SUCCESS) {
        std::cerr << "non-hardware key-generation is not currently supported on this Windows system.\n";
    }
    
#else
    // UNIX based system, can use /dev/urandom as it utilizes a CSPRNG 
    // https://linux.die.net/man/4/urandom

    std::ifstream rand_file;
 
    rand_file = std::ifstream("/dev/urandom", std::ios::in | std::ios::binary);

    if (!rand_file.is_open()) {
        std::cerr << "non-hardware key-generation is not currently supported on this UNIX distribution.\n";
        exit(1);
    }

    for (int i = 0; !rand_file.eof() && i < keygen_rounds; ++i) {
        char rand_byte{};
        rand_file.read(&rand_byte, 1);
        key_bytes.at(i) = static_cast<aes::byte>(rand_byte);

        // Check, in each loop, what the system entropy currently is as a means of detecting entropy attacks
        if (__get_available_entropy() < RAND_LEN / 8) {
            std::cerr << "ERROR: "
                << "System entropy has decreased to a dangerously low level (naturally or by DoS)\n"
                << "Ending execution prematurely to uphold key-strength.";
            exit(1);
        }
    }

#endif

    return key_bytes;
}


/**
 * @brief Wrapper function for generation of a random number, of a given size
 * 
 * @tparam RAND_LEN : 64-bit multiple of a random-number to be generated (MUST BE IN BITS)
 * @return std::array<aes::byte, RAND_LEN> : An array containing the bytes of the randomly generated number
 */
template<std::size_t RAND_LEN>
auto randgen() -> std::array<aes::byte, RAND_LEN / 8> {
    // Determine if hardware RDRAND is supported on the system's CPU
    static_assert(RAND_LEN % 64 == 0, "RAND_LEN must be multiple of 64-bits!");

    std::array<unsigned int, 4> cpu_info{};
    std::array<aes::byte, RAND_LEN / 8> key_bytes{};
    cpuid(cpu_info.data(), 0);

    // If RDSEED is supported on an AMD or Intel processor, EBX bit 18 will be set.
    key_bytes = (cpu_info[1] & RDSEED_FLAG != 0) ? __rdseed_rand<RAND_LEN>() : __os_randgen<RAND_LEN>();

    assert(key_bytes.size() == RAND_LEN / sizeof(uint64_t));
    return key_bytes;
}

#endif // KEYGEN_HPP