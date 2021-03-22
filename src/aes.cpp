#include "aes.hpp"

void aes::__swap_bytes(state& state, const std::array<byte, 256>& sub_source) {
    for (std::size_t r = 0; r < NB; ++r) {
        for (std::size_t c = 0; c < NB; ++c) {
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

void aes::shift_rows(state& state) {
	//shift row 1 
	byte temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	//shift row 2
	//swap index 0 and 2
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	//swap index 1 and 3
	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	//shift row 3
	temp = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = temp;
}

void aes::inv_shift_rows(state& state) {
	//inverse shift row 1 
	byte temp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	//inverse shift row 2
	//swap index 0 and 2
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	//swap index 1 and 3
	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	//inverse shift row 3
	temp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;
}


auto aes::__field_multiply_by_2(byte s) -> aes::byte {
    byte result = s;
    byte sig_bit = s>>7U;
    if (sig_bit == 0x00){
        result = s << 1U;
    }
    else{
        byte shifted = s << 1U;
        result = shifted ^ 0x1BU;
    }
    return result;
}


auto aes::__field_multiply(byte s, uint8_t num) -> aes::byte {
	
	byte result = s;
	std::vector<int> multiplication_order;
	while (num >1){
		if(num % 2 == 1)
			multiplication_order.push_back(1);
		multiplication_order.push_back(2);
		num = num/2;
	}
	for( int i = multiplication_order.size()-1; i >=0; i--){
		if(multiplication_order[i] == 2)
			result = __field_multiply_by_2(result);
		else if(multiplication_order[i] ==1)
			result = result ^ s;
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
		state[0][c] = s0_mult2 ^ s1_mult3 ^ s2 ^ s3;
		state[1][c] = s0 ^ s1_mult2 ^ s2_mult3 ^ s3;
		state[2][c] = s0 ^ s1 ^ s2_mult2 ^ s3_mult3;
		state[3][c] = s0_mult3 ^ s1 ^ s2 ^ s3_mult2;
	}
}


void aes::inv_mix_columns(state& state) {
	for(int c=0; c<NB; ++c){
		byte s0 = state[0][c];
        	byte s1 = state[1][c];
        	byte s2 = state[2][c];
        	byte s3 = state[3][c];
        	byte s0_mult9 = __field_multiply(s0, 9U);
        	byte s1_mult9 = __field_multiply(s1, 9U);
        	byte s2_mult9 = __field_multiply(s2, 9U);
        	byte s3_mult9 = __field_multiply(s3, 9U);
        	byte s0_multB = __field_multiply(s0, 0xbU);
        	byte s1_multB = __field_multiply(s1, 0xbU);
        	byte s2_multB = __field_multiply(s2, 0xbU);
        	byte s3_multB = __field_multiply(s3, 0xbU);
		byte s0_multD = __field_multiply(s0, 0xdU);
		byte s1_multD = __field_multiply(s1, 0xdU);
		byte s2_multD = __field_multiply(s2, 0xdU);
		byte s3_multD = __field_multiply(s3, 0xdU);
		byte s0_multE = __field_multiply(s0, 0xeU);
		byte s1_multE = __field_multiply(s1, 0xeU);
		byte s2_multE = __field_multiply(s2, 0xeU);
		byte s3_multE = __field_multiply(s3, 0xeU);
        	state[0][c] = s0_multE ^ s1_multB ^ s2_multD ^ s3_mult9;
        	state[1][c] = s0_mult9 ^ s1_multE ^ s2_multB ^ s3_multD;
        	state[2][c] = s0_multD ^ s1_mult9 ^ s2_multE ^ s3_multB;
        	state[3][c] = s0_multB ^ s1_multD ^ s2_mult9 ^ s3_multE;
	}
}
    /**
     *
     */
    void aes::add_round_key(state& currState, state& roundKeyValue){
		//XORs each column of the State with a word from the key schedule
		for(int i = 0; i < 4; i++){
			for(int j = 0; j < 4; j++){
				currState[i][j] ^= roundKeyValue[i][j];
			}
		}
	}

	auto aes::splitWord(word word) -> std::array<int, 4>{
		std::array<int, 4> split;
		split[0] = (word & 0xff000000UL) >> 24;
		split[1] = (word & 0x00ff0000UL) >> 16;
		split[2] = (word & 0x0000ff00UL) >>  8;
		split[3] = (word & 0x000000ffUL);
		return split;
	}

    auto aes::buildWord(byte b1, byte b2, byte b3, byte b4) -> aes::word{
        return (b1 << 24) | (b2 << 16) | ( b3 << 8 ) | (b4);
    }

	auto aes::rotword(word word) -> aes::word{
		std::array<int, 4> split = splitWord(word);
		return buildWord(split[1],split[2],split[3],split[0]);
	}

	auto aes::subword(word word) -> aes::word{
		std::array<int, 4> split = splitWord(word);
        byte b1 = S_BOX.at((split[0] & 0xF0U) + (split[0] & 0xFU));
		byte b2 = S_BOX.at((split[1] & 0xF0U) + (split[1] & 0xFU));
		byte b3 = S_BOX.at((split[2] & 0xF0U) + (split[2] & 0xFU));
		byte b4 = S_BOX.at((split[3] & 0xF0U) + (split[3] & 0xFU));
		return buildWord(b1,b2,b3,b4);
	}

	auto aes::get_Nk_Nr(int keySize) -> std::array<int, 2>{
		std::array<int, 2> nk_nr;
		//determine Nk and Nr
		if(keySize== 16){nk_nr[0] = 4; nk_nr[1] = 10;}

		else if(keySize == 24){nk_nr[0] = 6;nk_nr[1] = 12;}

		else if(keySize== 32){nk_nr[0] = 8;nk_nr[1] = 14;}

    	else{std::cerr << "Invalid Key Length for AES!\n"; exit(1);}

		return nk_nr;
	}

	void aes::key_expansion(std::vector<byte> keyBytes, std::vector<word>& w, int Nk, int Nr){
		word temp = -1;
		int i = 0;

		while(i < Nk){
			w[i] = aes::buildWord(keyBytes[4*i],keyBytes[4*i+1],keyBytes[4*i+2],keyBytes[4*i+3]);
			i++;
		}

		i = Nk;

		while(i < NB* (Nr+1)){
			temp = w[i-1];
			if(i % Nk == 0){
				temp = aes::rotword(aes::subword(temp)) ^ Rcon[i/Nk];
			}
			else if(Nk > 6 && (i % Nk == 4)){
				temp = aes::subword(temp);
			}
			w[i] = w[i-Nk] ^ temp;
			i++;
		}
	}


auto aes:: __spliceKey(int round, std::vector<word> key)-> aes::state{
	state roundKey;
	for(int i=0; i<4; i++){
		word temp = key[4*round+i];
		byte b0 = (temp & 0xff000000)>>24U;
		byte b1 = (temp & 0x00ff0000)>>16U;
		byte b2 = (temp & 0x0000ff00)>>8U;
		byte b3 = (temp & 0x000000ff);
		roundKey[0][i] = b0;
		roundKey[1][i] = b1;
		roundKey[2][i] = b2;
		roundKey[3][i] = b3;
	}
	return roundKey;
}

void aes:: encrypt(int Nr, state& state, std::vector<word> w){
	aes::state roundKey = __spliceKey(0, w);
	add_round_key(state, roundKey);
	//__debug_print_state(state);
	for(int i =1; i < Nr; i++){
		//printf("Round number %d\n",i);
		sub_bytes(state);
		//__debug_print_state(state);
		shift_rows(state);
		//__debug_print_state(state);
		mix_columns(state);
		//__debug_print_state(state);
		roundKey = __spliceKey(i, w);
		add_round_key(state, roundKey);
		//__debug_print_state(state);
	}
	sub_bytes(state);
	//__debug_print_state(state);
	shift_rows(state);
	//__debug_print_state(state);
	roundKey = __spliceKey(Nr, w);
	add_round_key(state, roundKey);
}

void aes:: decrypt(int Nr, state& state, std::vector<word> w){
	aes:: state roundKey = __spliceKey(Nr, w);
	add_round_key(state, roundKey);
	inv_shift_rows(state);
	inv_sub_bytes(state);
	for(int i = 1; i<Nr; i++){
		roundKey = __spliceKey(Nr-i, w);
		add_round_key(state,roundKey);
		inv_mix_columns(state);
		inv_shift_rows(state);
		inv_sub_bytes(state);
	}
	roundKey = __spliceKey(0, w);
	add_round_key(state, roundKey);
}



auto aes:: __get_most_sig_bit(byte s)-> uint8_t{
        uint8_t sig_bit = 0u;
         for(uint8_t i =0u; i<8u; i++){
                 byte temp = s >> i;
                 if(temp == 1U){
                         sig_bit = i;
                 }
         }
         return sig_bit;
}

void aes::__euclidean_algorithm(byte left, byte right, uint8_t sigbit){
	if( right == 0x00){
		printf("0x00");
		return;
	}
	if(right == 1U)
		return;
	uint8_t quotient = 0U;
	uint8_t quotient_sig_bit = __get_most_sig_bit(right);
	uint8_t diff = sigbit - quotient_sig_bit;
	quotient += 1U << diff;
	uint8_t remainder = left ^ (right<<diff);
	uint8_t temp_bit = __get_most_sig_bit(remainder);
	while(quotient_sig_bit<= temp_bit){
		diff = temp_bit-quotient_sig_bit;
		remainder = remainder ^ (right <<diff);
		quotient += 1U <<diff;
		temp_bit = __get_most_sig_bit(remainder);
	}
	printf("0x%02x = 0x%02x (0x%02x) + 0x%02x\n",left,right,quotient,remainder);
	__euclidean_algorithm(right, remainder, quotient_sig_bit);
}

auto aes:: __get_inverse(byte s) -> byte{
	return __extended_euclidean_algorithm(0x1bU, s, 8U)[1];
}

auto aes:: __extended_euclidean_algorithm(byte left, byte right, uint8_t sigbit) -> std::array<byte,2>{
	if( right == 0u){
		std:: array<byte,2> result = {0U, 0U};
                return result;
        }
        if(right == 1U){
		std:: array<byte,2> result = {0U,1U};
                return result;
	}
        uint8_t quotient = 0U;
        uint8_t quotient_sig_bit = __get_most_sig_bit(right);
        uint8_t diff = sigbit - quotient_sig_bit;
        quotient += 1U << diff;
        uint8_t remainder = left ^ (right<<diff);
        uint8_t temp_bit = __get_most_sig_bit(remainder);
        while(quotient_sig_bit<= temp_bit){
                diff = temp_bit-quotient_sig_bit;
                remainder = remainder ^ (right <<diff);
                quotient += 1U <<diff;
                temp_bit = __get_most_sig_bit(remainder);
        }
	if(remainder == 0U){
		std:: array<byte,2> result = {0U,1U};
                return result;
	}
	std::array<byte,2> rt = __extended_euclidean_algorithm(right, remainder, quotient_sig_bit);
	byte r = rt[1];
	byte temp = __field_multiply(rt[1], quotient);
	byte t = temp ^ rt[0];
	std::array<byte,2> result = {r, t};
	return result;
}


auto aes:: __get_S_BOX_value(byte s)->byte{

	byte inverse = __get_inverse(s);
	byte b0 = inverse & 1U;
	byte b1 = (inverse & 2U)>>1U;
	byte b2 = (inverse & 4U)>>2U;
	byte b3 = (inverse & 8U)>>3U;
	byte b4 = (inverse & 16U)>>4U;
	byte b5 = (inverse & 32U)>>5U;
	byte b6 = (inverse & 64U)>>6U;
	byte b7 = (inverse & 128U)>>7U;
	byte b_prime0 = b0 ^ b4 ^ b5 ^ b6 ^ b7;
	byte b_prime1 = b0 ^ b1 ^ b5 ^ b6 ^ b7;
	byte b_prime2 = b0 ^ b1 ^ b2 ^ b6 ^ b7;
	byte b_prime3 = b0 ^ b1 ^ b2 ^ b3 ^ b7;
	byte b_prime4 = b0 ^ b1 ^ b2 ^ b3 ^ b4;
	byte b_prime5 = b1 ^ b2 ^ b3 ^ b4 ^ b5;
	byte b_prime6 = b2 ^ b3 ^ b4 ^ b5 ^ b6;
	byte b_prime7 = b3 ^ b4 ^ b5 ^ b6 ^ b7;
	byte temp = b_prime0;
	temp ^= b_prime1 << 1U;
	temp ^= b_prime2 << 2U;
	temp ^= b_prime3 << 3U;
	temp ^= b_prime4 << 4U;
	temp ^= b_prime5 << 5U;
	temp ^= b_prime6 << 6U;
	temp ^= b_prime7 << 7U;
	byte result = temp ^ 0x63U;
	return result;
}

auto aes:: __get_inverse_S_BOX_value(byte s)->byte{
	byte temp = s ^ 0x63U;
	byte b0 = temp & 1U;
        byte b1 = (temp & 2U)>>1U;
        byte b2 = (temp & 4U)>>2U;
        byte b3 = (temp & 8U)>>3U;
        byte b4 = (temp & 16U)>>4U;
        byte b5 = (temp & 32U)>>5U;
        byte b6 = (temp & 64U)>>6U;
        byte b7 = (temp & 128U)>>7U;
	byte b_prime0 = b2 ^ b5 ^ b7;
        byte b_prime1 = b0 ^ b3 ^ b6;
        byte b_prime2 = b1 ^ b4 ^ b7;
        byte b_prime3 = b0 ^ b2 ^ b5;
        byte b_prime4 = b1 ^ b3 ^ b6;
        byte b_prime5 = b2 ^ b4 ^ b7;
        byte b_prime6 = b0 ^ b3 ^ b5;
        byte b_prime7 = b1 ^ b4 ^ b6;
	temp = b_prime0;
        temp ^= b_prime1 << 1U;
        temp ^= b_prime2 << 2U;
        temp ^= b_prime3 << 3U;
        temp ^= b_prime4 << 4U;
        temp ^= b_prime5 << 5U;
        temp ^= b_prime6 << 6U;
        temp ^= b_prime7 << 7U;
	byte result = __get_inverse(temp);
	return result;
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


