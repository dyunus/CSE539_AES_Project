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



byte aes:: __field_multiply_by_2(byte s){
        byte result = s;
        byte sig_bit = s>>7;
        if (sig_bit == 0x00){
                result = s<<1;

        }
        else{
                byte shifted = s <<1;
                result = shifted ^ 0x1b;
        }
        return result;

}


byte aes::__field_multiply(byte s, int num) {
	
	byte result = s;
	if (num == 9){
		byte temp = __field_multiply_by_2(s);
		temp = __field_multiply_by_2(temp);
		temp = __field_multiply_by_2(temp);
		result = temp ^ s;
	}
	else if (num == 11){
		byte temp = __field_multiply_by_2(s);
		temp = __field_multiply_by_2(temp);
		temp = temp ^ s;
		temp = __field_multiply_by_2(temp);
		result = temp ^ s;
	}
	else if (num == 13){
		byte temp = __field_multiply_by_2(s);
		temp = temp ^ s;
		temp = __field_multiply_by_2(temp);
		temp = __field_multiply_by_2(temp);
		result = temp ^ s;
	}
	else if (num==14){
		byte temp = __field_multiply_by_2(s);
		temp = temp ^ s;
		temp = __field_multiply_by_2(temp);
		temp = temp ^ s;
		result = __field_multiply_by_2(temp);
	}
	return result;
}


void aes::mix_columns(state& state) {
	for(int c =0; c<NB; ++c){
		byte s0 = state[0][c];
		byte s1 = state[1][c];
		byte s2 = state[2][c];
		byte s3 = state[3][c];
		byte s0_mult2 = __field_multiply_by_2(s0);
		byte s1_mult2 = __field_multiply_by_2(s1);
		byte s2_mult2 = __field_multiply_by_2(s2);
		byte s3_mult2 = __field_multiply_by_2(s3);
		byte s0_mult3 = s0_mult2 ^ s0;
		byte s1_mult3 = s1_mult2 ^ s1;
		byte s2_mult3 = s2_mult2 ^ s2;
		byte s3_mult3 = s3_mult2 ^ s3;
		state[0][c]=s0_mult2 ^ s1_mult3 ^ s2 ^ s3;
		state[1][c]=s0 ^ s1_mult2 ^ s2_mult3 ^ s3;
		state[2][c]=s0 ^ s1 ^ s2_mult2 ^ s3_mult3;
		state[3][c]=s0_mult3 ^ s1 ^ s2 ^ s3_mult2;
	}
}


void aes::inv_mix_columns(state& state) {
	for(int c=0; c<NB; ++c){
		byte s0 = state[0][c];
                byte s1 = state[1][c];
                byte s2 = state[2][c];
                byte s3 = state[3][c];
                byte s0_mult9 = __field_multiply(s0, 9);
                byte s1_mult9 = __field_multiply(s1, 9);
                byte s2_mult9 = __field_multiply(s2, 9);
                byte s3_mult9 = __field_multiply(s3, 9);
                byte s0_multB = __field_multiply(s0, 11);
                byte s1_multB = __field_multiply(s1, 11);
                byte s2_multB = __field_multiply(s2, 11);
                byte s3_multB = __field_multiply(s3, 11);
		byte s0_multD = __field_multiply(s0, 13);
		byte s1_multD = __field_multiply(s1, 13);
		byte s2_multD = __field_multiply(s2, 13);
		byte s3_multD = __field_multiply(s3, 13);
		byte s0_multE = __field_multiply(s0, 14);
		byte s1_multE = __field_multiply(s1, 14);
		byte s2_multE = __field_multiply(s2, 14);
		byte s3_multE = __field_multiply(s3, 14);
                state[0][c]=s0_multE ^ s1_multB ^ s2_multD ^ s3_mult9;
                state[1][c]=s0_mult9 ^ s1_multE ^ s2_multB ^ s3_multD;
                state[2][c]=s0_multD ^ s1_mult9 ^ s2_multE ^ s3_multB;
                state[3][c]=s0_multB ^ s1_multD ^ s2_mult9 ^ s3_multE;
	}
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


