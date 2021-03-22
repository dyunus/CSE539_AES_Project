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
void cpuid(unsigned int info[4], int InfoType) {
    __cpuid_count(InfoType, 0, info[0], info[1], info[2], info[3]);
}
#endif