#include "ciphermodes.hpp"


void ciphermodes::pad_plaintext(std::vector<aes::byte>& plaintext_bytes){
		aes::byte padNum = 128 - (plaintext_bytes.size() % 128);
        for(int i = 0; i < padNum; i++){
            plaintext_bytes.push_back(padNum);
        }
}

void ciphermodes::create_blocks(std::vector<std::vector<aes::byte> >& plaintext_blocks,std::vector<aes::byte> plaintext_bytes){
	std::vector<aes::byte> new_block;
    for(int i = 0; i < plaintext_bytes.size(); i++){
        if(i != 0 && i % 128 == 0){
            plaintext_blocks.push_back(new_block);
            new_block.clear();
        }
        new_block.push_back(plaintext_bytes[i]);
    }
    plaintext_blocks.push_back(new_block);
}