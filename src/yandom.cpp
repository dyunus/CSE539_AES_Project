#include "yandom.hpp"

auto __get_available_entropy() -> unsigned int {
    std::ifstream entropy_file("/proc/sys/kernel/random/entropy_avail", std::ios::in);

    if (!entropy_file.is_open()) {
        return 0;
    }

    std::string pool_size{};
    std::getline(entropy_file, pool_size);
    return std::stoi(pool_size) / 8;
}

#ifndef _WIN32
void cpuid(unsigned int info[4], int InfoType) { // NOLINT   Again, we don't have a say here, it also can't be const as cpuid_count changes it
    __cpuid_count(InfoType, 0, info[0], info[1], info[2], info[3]); // NOLINT9hicpp-no-assembler) Unavoidable ASM
}
#endif