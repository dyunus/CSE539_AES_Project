#include "aes.hpp"
#include "aes_exceptions.hpp"

void aes::swap_bytes(state &state, const std::array<byte, 256> &sub_source) {
  for (std::size_t r = 0; r < NB; ++r) {
    for (std::size_t c = 0; c < NB; ++c) {
      byte curr_byte = state[r][c];
      state[r][c] = no_cache_lookup(curr_byte & 0xF0U, curr_byte & 0xFU,
                                    sub_source.data());
    }
  }
}

void aes::sub_bytes(state &state) { swap_bytes(state, S_BOX); }

void aes::inv_sub_bytes(state &state) { swap_bytes(state, INV_S_BOX); }

void aes::shift_rows(state &state) {
  // shift row 1
  byte temp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp;

  // shift row 2
  // swap index 0 and 2
  temp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = temp;

  // swap index 1 and 3
  temp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = temp;

  // shift row 3
  temp = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = state[3][0];
  state[3][0] = temp;
}

void aes::inv_shift_rows(state &state) {
  // inverse shift row 1
  byte temp = state[1][3];
  state[1][3] = state[1][2];
  state[1][2] = state[1][1];
  state[1][1] = state[1][0];
  state[1][0] = temp;

  // inverse shift row 2
  // swap index 0 and 2
  temp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = temp;

  // swap index 1 and 3
  temp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = temp;

  // inverse shift row 3
  temp = state[3][0];
  state[3][0] = state[3][1];
  state[3][1] = state[3][2];
  state[3][2] = state[3][3];
  state[3][3] = temp;
}

auto aes::field_multiply_by_2(byte s) -> aes::byte {
  byte result = s;
  byte sig_bit = s >> 7U;
  byte xorByte;

  //if the byte has most significant bit of 0 XORING with 0x1B is not needed so we XOR with 0x00 to maintain same number of operations
  if (sig_bit == 0x00) {
    xorByte=0x00U;
  } 
  else {
    xorByte=0x1BU;
  }
  byte shifted = s<<1U; 
  result =shifted ^ xorByte;
  return result;
}

auto aes::field_multiply(byte s, uint8_t num) -> aes::byte {

  byte result = s;
  std::vector<int> multiplication_order;
  
  //converts the num into a sequence of additions and multiplications by 2
  //EX: 11 = 1+2(1+2(2)) so 11s = (2(2(2s)+s)+s
  while (num > 1) {
    if (num % 2 == 1) {
      multiplication_order.push_back(1);
    }
    multiplication_order.push_back(2);
    num = num / 2;
  }

  //traverse the representation created above backwards since that is the correct order
  for (auto i = static_cast<int64_t>(multiplication_order.size() - 1); i >= 0;
       i--) {
    if (multiplication_order[i] == 2) {
      result = field_multiply_by_2(result);
    } 
    else if (multiplication_order[i] == 1) {
      result = result ^ s;
    }
  }
  return result;
}

void aes::mix_columns(state &state) {
  for (std::size_t c = 0; c < NB; ++c) {
    byte s0 = state[0][c];
    byte s1 = state[1][c];
    byte s2 = state[2][c];
    byte s3 = state[3][c];

    //multiplies all the bytes in current column by x (0x01)
    byte s0_mult2 = field_multiply_by_2(s0);
    byte s1_mult2 = field_multiply_by_2(s1);
    byte s2_mult2 = field_multiply_by_2(s2);
    byte s3_mult2 = field_multiply_by_2(s3);

    //multiplies all the bytes in current column by x+1 (0x03)
    byte s0_mult3 = s0_mult2 ^ s0;
    byte s1_mult3 = s1_mult2 ^ s1;
    byte s2_mult3 = s2_mult2 ^ s2;
    byte s3_mult3 = s3_mult2 ^ s3;
    
    //column vector resulting from multiplying current column with the matrix specified in the AES standard
    state[0][c] =
        static_cast<byte>(s0_mult2 ^ s1_mult3) ^ static_cast<byte>(s2 ^ s3);
    state[1][c] =
        static_cast<byte>(s0 ^ s1_mult2) ^ static_cast<byte>(s2_mult3 ^ s3);
    state[2][c] =
        static_cast<byte>(s0 ^ s1) ^ static_cast<byte>(s2_mult2 ^ s3_mult3);
    state[3][c] =
        static_cast<byte>(s0_mult3 ^ s1) ^ static_cast<byte>(s2 ^ s3_mult2);
  }
}

void aes::inv_mix_columns(state &state) {
  for (std::size_t c = 0; c < NB; ++c) {
    byte s0 = state[0][c];
    byte s1 = state[1][c];
    byte s2 = state[2][c];
    byte s3 = state[3][c];

    //multiplies all the bytes in the current column by x^3+1 (0x09)
    byte s0_mult9 = field_multiply(s0, 9U);
    byte s1_mult9 = field_multiply(s1, 9U);
    byte s2_mult9 = field_multiply(s2, 9U);
    byte s3_mult9 = field_multiply(s3, 9U);

    //multiplies all the bytes in the current column by x^3+x+1 (0x0b)
    byte s0_multB = field_multiply(s0, 0xbU);
    byte s1_multB = field_multiply(s1, 0xbU);
    byte s2_multB = field_multiply(s2, 0xbU);
    byte s3_multB = field_multiply(s3, 0xbU);
    
    //multiplies all the bytes in the current column by x^3+x^2+1 (0x0d)
    byte s0_multD = field_multiply(s0, 0xdU);
    byte s1_multD = field_multiply(s1, 0xdU);
    byte s2_multD = field_multiply(s2, 0xdU);
    byte s3_multD = field_multiply(s3, 0xdU);
    
    //multiplies all the bytes in the current column by x^3+x^2+x (0x0e)
    byte s0_multE = field_multiply(s0, 0xeU);
    byte s1_multE = field_multiply(s1, 0xeU);
    byte s2_multE = field_multiply(s2, 0xeU);
    byte s3_multE = field_multiply(s3, 0xeU);

    //collumn vector resulting from multiplying current column with the matrix specified in AES standard
    state[0][c] = static_cast<byte>(s0_multE ^ s1_multB) ^
                  static_cast<byte>(s2_multD ^ s3_mult9);
    state[1][c] = static_cast<byte>(s0_mult9 ^ s1_multE) ^
                  static_cast<byte>(s2_multB ^ s3_multD);
    state[2][c] = static_cast<byte>(s0_multD ^ s1_mult9) ^
                  static_cast<byte>(s2_multE ^ s3_multB);
    state[3][c] = static_cast<byte>(s0_multB ^ s1_multD) ^
                  static_cast<byte>(s2_mult9 ^ s3_multE);
  }
}
/**
 *
 */
void aes::add_round_key(state &currState, state &roundKeyValue) {
  // XORs each column of the State with a word from the key schedule
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      currState[i][j] ^= roundKeyValue[i][j];
    }
  }
}

auto aes::splitWord(word word) -> std::array<byte, 4> {
  std::array<byte, 4> split{};
  split[0] = (word & 0xff000000UL) >> 24U;
  split[1] = (word & 0x00ff0000UL) >> 16U;
  split[2] = (word & 0x0000ff00UL) >> 8U;
  split[3] = (word & 0x000000ffUL);
  return split;
}

auto aes::buildWord(byte b1, byte b2, byte b3, byte b4) -> aes::word {
  return (b1 << 24U) | (b2 << 16U) | (b3 << 8U) | (b4); // NOLINT(hicpp-signed-bitwise) : This is using proper unsigned
               // conventions, but is too complicated for the linter
}

auto aes::rotword(word word) -> aes::word {
  //performs a cyclic permutation
  auto split = splitWord(word);
  return buildWord(split[1], split[2], split[3], split[0]);
}

auto aes::subword(word word) -> aes::word {
  
  auto split = splitWord(word);
  auto *sbox_ptr = S_BOX.data();
 //applies the Sbox to each byte of an input word to produce an output word
  byte b1 = no_cache_lookup(split[0] & 0xF0U, split[0] & 0xFU, sbox_ptr);
  byte b2 = no_cache_lookup(split[1] & 0xF0U, split[1] & 0xFU, sbox_ptr);
  byte b3 = no_cache_lookup(split[2] & 0xF0U, split[2] & 0xFU, sbox_ptr);
  byte b4 = no_cache_lookup(split[3] & 0xF0U, split[3] & 0xFU, sbox_ptr);

  return buildWord(b1, b2, b3, b4);
}

auto aes::get_Nk_Nr(int keySize) -> std::array<int, 2> {
  std::array<int, 2> nk_nr{};
  // determine Nk and Nr based on the size of the cipher key
  if (keySize == 16) {
    nk_nr[0] = 4;
    nk_nr[1] = 10;
  } else if (keySize == 24) {
    nk_nr[0] = 6;
    nk_nr[1] = 12;
  } else if (keySize == 32) {
    nk_nr[0] = 8;
    nk_nr[1] = 14;
  } else {
    throw aes_error("Invalid Key Length for AES!\n");
  }

  return nk_nr;
}

void aes::key_expansion(std::vector<byte> keyBytes, std::vector<word> &w, unsigned int Nk, unsigned int Nr) {
  word temp = -1;
  unsigned int i = 0;

  //the first Nk words of the expanded key are filled with the cipher key
  while (i < Nk) {
    w[i] = aes::buildWord(keyBytes[4 * i], keyBytes[4 * i + 1], keyBytes[4 * i + 2], keyBytes[4 * i + 3]);
    i++;
  }

  i = Nk;

  //for every following word, w[i] is equal to the XOR of the previous word and the word Nk positions earlier
  while (i < NB * (Nr + 1)) {
    temp = w[i - 1];
    //for words in positions that are a multiple of Nk, a transformation is applied to w[i-1] prior to the XOR, followed by an XOR with a round constant
    if (i % Nk == 0) {
      // The transformation applied is the cyclic shift of RotWord() and a table lookup substituion using SubWord()
      temp = aes::rotword(aes::subword(temp)) ^ Rcon.at(i / Nk);
    } 
    //for 256 bit cipher keys, a subword is applied to w[i-1] prior to the xor when i-4 is a multiple of Nk
    else if (Nk > 6 && (i % Nk == 4)) {
      temp = aes::subword(temp);
    }
    w[i] = w[i - Nk] ^ temp;
    i++;
  }
}

auto aes::spliceKey(unsigned int round, const std::vector<word> &key) -> aes::state {
  state roundKey;
  for (std::size_t i = 0; i < 4; i++) {
    word temp = key[4 * round + i];
    byte b0 = (temp & 0xff000000U) >> 24U;
    byte b1 = (temp & 0x00ff0000U) >> 16U;
    byte b2 = (temp & 0x0000ff00U) >> 8U;
    byte b3 = (temp & 0x000000ffU);
    roundKey[0][i] = b0;
    roundKey[1][i] = b1;
    roundKey[2][i] = b2;
    roundKey[3][i] = b3;
  }
  return roundKey;
}

void aes::encrypt(unsigned int Nr, state &state, const std::vector<word> &w) {

  //Performs an AddRoundkey before the 10,12, or 14 rounds of AES
  aes::state roundKey = spliceKey(0, w);
  add_round_key(state, roundKey);
  
  //performs 9, 11 or 13 rounds of AES
  for (std::size_t i = 1; i < Nr; i++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    roundKey = spliceKey(i, w);
    add_round_key(state, roundKey);
  }

  //performs the last round of AES without mix columns
  sub_bytes(state);
  shift_rows(state);
  roundKey = spliceKey(Nr, w);
  add_round_key(state, roundKey);
}

void aes::decrypt(unsigned int Nr, state &state, const std::vector<word> &w) {
  
  //reverses the last round of AES
  aes::state roundKey = spliceKey(Nr, w);
  add_round_key(state, roundKey);
  inv_shift_rows(state);
  inv_sub_bytes(state);

  //reverses the first 9,11, or 13 rounds of AES
  for (std::size_t i = 1; i < Nr; i++) {
    roundKey = spliceKey(static_cast<int>(Nr - i), w);
    add_round_key(state, roundKey);
    inv_mix_columns(state);
    inv_shift_rows(state);
    inv_sub_bytes(state);
  }

  //reverses the initial roundkey
  roundKey = spliceKey(0, w);
  add_round_key(state, roundKey);
}


auto aes::get_most_sig_bit(byte s) -> uint8_t {
  uint8_t sig_bit = 0U;
  for (uint8_t i = 0U; i < 8U; i++) {
    byte temp = s >> i;
    if (temp == 1U) { //doesnt not break from for loop in order to keep constant time for any input
      sig_bit = i;
    }
  }
  return sig_bit;
}


auto aes::get_inverse(byte s) -> byte {
  return extended_euclidean_algorithm(0x1bU, s, 8U)[1];
}

//NOTE: larger element MUST be left since there is no way to represent x^8+x^4+x^3+x+1 in 8 bits so first step has left as byte 0x1b with sig bit set to 8 to account for this
auto aes::extended_euclidean_algorithm(byte left, byte right, uint8_t sigbit)
    -> std::array<byte, 2> {
  
  //0(0x00) does not have an inverse in the finite field 2^8	    
  if (right == 0U) {
    std::array<byte, 2> result = {0U, 0U};
    return result;
  }

  //base case of recursion.If the right element is 1 return r=0, t=1
  if (right == 1U) {
    std::array<byte, 2> result = {0U, 1U};
    return result;
  }
  
  //performs long division between left and right until the most significant bit of the remainder is strictly less than most significant bit of right 
  //This is not constant time. Execution depends entirely on the difference between the positions of the most significant bytes of left and right
  uint8_t quotient = 0U;
  uint8_t quotient_sig_bit = get_most_sig_bit(right);
  uint8_t diff = sigbit - quotient_sig_bit;
  quotient += 1U << diff;
  uint8_t remainder = left ^ (right << diff); // NOLINT(hicpp-signed-bitwise)
  uint8_t temp_bit = get_most_sig_bit(remainder);
  while (quotient_sig_bit <= temp_bit) {
    diff = temp_bit - quotient_sig_bit;
    remainder = remainder ^ (right << diff); // NOLINT(hicpp-signed-bitwise)
    quotient += 1U << diff;
    temp_bit = get_most_sig_bit(remainder);
  }

  //Handles the case where left and right have a gcd greater than 1. Does not come into play in this application since we are interested only in inverses modulo x^8+x^4+x^3+x+1
  if (remainder == 0U) {
    std::array<byte, 2> result = {0U, 1U};
    return result;
  }

  //recursive call with right as the new left and the remainder as the new right
  //Another part that causes algorithm to not be constant time. Number of recursive calls dependent on input bytes
  std::array<byte, 2> rt = extended_euclidean_algorithm(right, remainder, quotient_sig_bit);
  
  //Performs the reverse of the Euclidean Algorithm to get r and t such that r*left + t*right = gcd(left,right)
  byte r = rt[1];

  //Another part that causes algorithm to not be constant time. Execution time of field_multiply is dependent on what quotient is
  byte temp = field_multiply(rt[1], quotient); 
  byte t = temp ^ rt[0];
  std::array<byte, 2> result = {r, t};
  return result;
}

auto aes::get_S_BOX_value(byte s) -> byte {

  byte inverse = get_inverse(s);
  
  //Since there is no bit data type, we calculate the bits by masking the inverse and then shifting the mask so that first bit of new byte corresponds to the bit in position i
  byte b0 = inverse & 1U;
  byte b1 = (inverse & 2U) >> 1U;
  byte b2 = (inverse & 4U) >> 2U;
  byte b3 = (inverse & 8U) >> 3U;
  byte b4 = (inverse & 16U) >> 4U;
  byte b5 = (inverse & 32U) >> 5U;
  byte b6 = (inverse & 64U) >> 6U;
  byte b7 = (inverse & 128U) >> 7U;
  
  //Performs matrix multiplication specified in SubBytes section of AES standard document
  byte b_prime0 = b0 ^ b4 ^ b5 ^ b6 ^ b7; // NOLINT(hicpp-signed-bitwise)
  byte b_prime1 = b0 ^ b1 ^ b5 ^ b6 ^ b7; // NOLINT(hicpp-signed-bitwise)
  byte b_prime2 = b0 ^ b1 ^ b2 ^ b6 ^ b7; // NOLINT(hicpp-signed-bitwise)
  byte b_prime3 = b0 ^ b1 ^ b2 ^ b3 ^ b7; // NOLINT(hicpp-signed-bitwise)
  byte b_prime4 = b0 ^ b1 ^ b2 ^ b3 ^ b4; // NOLINT(hicpp-signed-bitwise)
  byte b_prime5 = b1 ^ b2 ^ b3 ^ b4 ^ b5; // NOLINT(hicpp-signed-bitwise)
  byte b_prime6 = b2 ^ b3 ^ b4 ^ b5 ^ b6; // NOLINT(hicpp-signed-bitwise)
  byte b_prime7 = b3 ^ b4 ^ b5 ^ b6 ^ b7; // NOLINT(hicpp-signed-bitwise)
  
  //rebuilds the byte
  byte temp = b_prime0;
  temp ^= (b_prime1 << 1U); // NOLINT(hicpp-signed-bitwise)
  temp ^= (b_prime2 << 2U); // NOLINT(hicpp-signed-bitwise)
  temp ^= (b_prime3 << 3U); // NOLINT(hicpp-signed-bitwise)
  temp ^= (b_prime4 << 4U); // NOLINT(hicpp-signed-bitwise)
  temp ^= (b_prime5 << 5U); // NOLINT(hicpp-signed-bitwise)
  temp ^= (b_prime6 << 6U); // NOLINT(hicpp-signed-bitwise)
  temp ^= (b_prime7 << 7U); // NOLINT(hicpp-signed-bitwise)
  
  byte result = temp ^ 0x63U;
  return result;
}

auto aes::get_inverse_S_BOX_value(byte s) -> byte {
  byte temp = s ^ 0x63U;

  //Since there is no bit data type, we calculate the bits by masking the inverse and then shifting the mask so that first bit of new byte corresponds to the bit in position i
  byte b0 = temp & 1U;
  byte b1 = (temp & 2U) >> 1U;
  byte b2 = (temp & 4U) >> 2U;
  byte b3 = (temp & 8U) >> 3U;
  byte b4 = (temp & 16U) >> 4U;
  byte b5 = (temp & 32U) >> 5U;
  byte b6 = (temp & 64U) >> 6U;
  byte b7 = (temp & 128U) >> 7U;
  
  //Performs matrix multiplication specified in InvSubBytes section of AES standard document
  byte b_prime0 = b2 ^ (b5 ^ b7); // NOLINT(hicpp-signed-bitwise)
  byte b_prime1 = (b0 ^ b3) ^ b6; // NOLINT(hicpp-signed-bitwise)
  byte b_prime2 = (b1 ^ b4) ^ b7; // NOLINT(hicpp-signed-bitwise)
  byte b_prime3 = (b0 ^ b2) ^ b5; // NOLINT(hicpp-signed-bitwise)
  byte b_prime4 = (b1 ^ b3) ^ b6; // NOLINT(hicpp-signed-bitwise)
  byte b_prime5 = (b2 ^ b4) ^ b7; // NOLINT(hicpp-signed-bitwise)
  byte b_prime6 = (b0 ^ b3) ^ b5; // NOLINT(hicpp-signed-bitwise)
  byte b_prime7 = (b1 ^ b4) ^ b6; // NOLINT(hicpp-signed-bitwise)
  
  //Rebuilds the byte
  temp = b_prime0;
  temp ^= b_prime1 << 1U; // NOLINT(hicpp-signed-bitwise)
  temp ^= b_prime2 << 2U; // NOLINT(hicpp-signed-bitwise)
  temp ^= b_prime3 << 3U; // NOLINT(hicpp-signed-bitwise)
  temp ^= b_prime4 << 4U; // NOLINT(hicpp-signed-bitwise)
  temp ^= b_prime5 << 5U; // NOLINT(hicpp-signed-bitwise)
  temp ^= b_prime6 << 6U; // NOLINT(hicpp-signed-bitwise)
  temp ^= b_prime7 << 7U; // NOLINT(hicpp-signed-bitwise)
  
  byte result = get_inverse(temp);
  return result;
}

void aes::debug_print_state(const state &state) {
  for (const auto &row : state) {
    for (byte val : row) {
      printf("0x%02x ", val);
    }
    printf("\n");
  }
  printf("\n");
}
