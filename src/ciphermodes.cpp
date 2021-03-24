#include "ciphermodes.hpp"


void ciphermodes::pad_plaintext(std::vector<aes::byte>& plaintext_bytes){
		aes::byte padNum = 16 - (plaintext_bytes.size() % 16);
        for(int i = 0; i < padNum; i++){
            plaintext_bytes.push_back(padNum);
        }
}

void ciphermodes::unpad_ciphertext(std::vector<aes::byte>& ciphertext_bytes){
		aes::byte padNum = ciphertext_bytes.back();
        for(aes::byte i = 0; i < padNum; i++){
            aes::byte check = ciphertext_bytes.back();
            if(check != padNum){
                std::cerr << "Error While Unpadding!\n"; exit(1);
            }
            ciphertext_bytes.pop_back();
        }
}

auto ciphermodes::merge_blocks(const std::vector<std::vector<aes::byte>>& ciphertext_blocks) -> std::vector<aes::byte>{
	std::vector<aes::byte> ciphertext_bytes;
    for (const auto& cipher_block : ciphertext_blocks) {
        for (const auto& block_byte : cipher_block) {
            ciphertext_bytes.push_back(block_byte);
        }
    }

    return ciphertext_bytes;
}

auto ciphermodes::create_blocks(std::vector<aes::byte> plaintext_bytes) -> std::vector<std::vector<aes::byte> >{
	std::vector<std::vector<aes::byte> > plaintext_blocks;
    std::vector<aes::byte> new_block;
    for(int i = 0; i < plaintext_bytes.size(); i++){
        if(i != 0 && i % 16 == 0){
            plaintext_blocks.push_back(new_block);
            new_block.clear();
        }
        new_block.push_back(plaintext_bytes[i]);
    }
    plaintext_blocks.push_back(new_block);
    return plaintext_blocks;
}

auto ciphermodes::convert_block_to_state(std::vector<aes::byte> block) -> aes::state{
    int index = 0;
    aes::state state;
    for(int j = 0; j < aes::NB; j++) {
        for(int i = 0; i < aes::NB; i++){
            state[i][j] = block[index++];
        }
    }
    return state;
}

auto ciphermodes::convert_state_to_block(aes::state state) -> std::vector<aes::byte>{
    std::vector<aes::byte> block;
    for(int j = 0; j < aes::NB; j++) {
        for(int i = 0; i < aes::NB; i++){
            block.push_back(state[i][j]);
        }
    }
    return block;
}

auto ciphermodes::ECB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte> {
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    pad_plaintext(plaintext_bytes);
    std::vector<std::vector<aes::byte> > plaintext_blocks = ciphermodes::create_blocks(plaintext_bytes);
    
    for(auto& plain_block : plaintext_blocks){
        aes::state state = convert_block_to_state(plain_block);
        aes::encrypt(nk_nr[1], state, expandedKey);
        plain_block = convert_state_to_block(state);
    }

    std::vector<aes::byte> ciphertext_bytes = merge_blocks(plaintext_blocks);
    return ciphertext_bytes;
}

auto ciphermodes::ECB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte> {
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    std::vector<std::vector<aes::byte> > ciphertext_blocks =  ciphermodes::create_blocks(std::move(ciphertext_bytes));
    
    for (auto& block : ciphertext_blocks) {
       aes::state state = convert_block_to_state(block);
        aes::decrypt(nk_nr[1], state, expandedKey);
        block = convert_state_to_block(state); 
    }

    std::vector<aes::byte> plaintext_bytes = merge_blocks(ciphertext_blocks);
    unpad_ciphertext(plaintext_bytes);
    return plaintext_bytes;
}