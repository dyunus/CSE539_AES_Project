#include "aes.hpp"

using aes::byte;
using aes::state;

void aes::__swap_bytes(state& state, const std::array<byte, 256>& sub_source) {
    for (int r = 0; r < NB; ++r) {
        for (int c = 0; c < NB; ++c) {
            byte curr_byte = state[r][c];
            state[r][c] = sub_source.at((curr_byte & 0xF0U) + (curr_byte & 0xFU));
        }
    }
}

void aes::sub_bytes(state& state) {
    __swap_bytes(state, S_BOX);
}

void aes::inv_sub_bytes(state& state) {
    __swap_bytes(state, INV_S_BOX);
}

void aes::__debug_print_state(const state& state) {
    for (const auto& row : state) {
        for (byte val : row) {
            printf("0x%02x ", val);
        }
        printf("\n");
    }
    printf("\n");
}