#include "ciphermodes.hpp"
#include "yandom.hpp"


auto ciphermodes::genKey(int keySize) -> std::vector<aes::byte>{
    int keySizeInBytes = keySize / 8;
    auto key = randgen<256>();
    std::vector<aes::byte> temp;
    for(auto byte: key){
        temp.push_back(byte);
    }
    std::vector<aes::byte> keyBytes = {temp.begin(), temp.begin() + keySizeInBytes}; 
    return keyBytes;
}

void ciphermodes::print_blocks(std::vector<aes::byte> vec){
    for (std::size_t i = 0; i < vec.size(); ++i) {
        if (i % 16 == 0){
            printf("\n");     
        }
        printf("0x%02x ", vec[i]);
    }
    std::cout << std::endl;
}

void ciphermodes::pad_plaintext(std::vector<aes::byte>& plaintext_bytes){
		aes::byte padNum = 16 - (plaintext_bytes.size() % 16);
        for(std::size_t i = 0; i < padNum; i++){
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

std::vector<aes::byte> ciphermodes::xor_blocks(std::vector<aes::byte> block1,std::vector<aes::byte> block2){
    for(int i = 0; i < ((block1.size() < block2.size()) ? block1.size() : block2.size()); i++){
            block1[i] ^= block2[i];
    }
    return block1;
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
    for(std::size_t i = 0; i < plaintext_bytes.size(); i++){
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
    for(std::size_t j = 0; j < aes::NB; j++) {
        for(std::size_t i = 0; i < aes::NB; i++){
            state[i][j] = block[index++];
        }
    }
    return state;
}

auto ciphermodes::convert_state_to_block(aes::state state) -> std::vector<aes::byte>{
    std::vector<aes::byte> block;
    for(std::size_t j = 0; j < aes::NB; j++) {
        for(std::size_t i = 0; i < aes::NB; i++){
            block.push_back(state[i][j]);
        }
    }
    return block;
}

auto ciphermodes::create_CTR(std::array<aes::byte,12> nonce, aes::word counter)->aes::state{
	std::vector<aes::byte> block;
	std::array<aes::byte,4> temp = aes::splitWord(counter);
	for(auto byte: nonce){
		block.push_back(byte);
	}
	for(auto byte:temp){
		block.push_back(byte);
	}
	aes::state CTR = convert_block_to_state(block);
	return CTR;
}

auto ciphermodes::create_nonce_blocks(std::vector<aes::byte> ciphertext_bytes)->aes::Tuple<std::array<aes::byte, 12>, std::vector<std::vector<aes::byte>>>{
	aes:: Tuple<std::array<aes::byte, 12>, std::vector<std::vector<aes::byte>>> result;
	for(std::size_t i=0; i<12; i++){
		result.element1[i]= ciphertext_bytes[i];
	}
	std::vector<aes::byte> new_block;
    	for(std::size_t i =12; i < ciphertext_bytes.size(); i++){
        	if((i-12) != 0 && (i-12) % 16 == 0){
            	result.element2.push_back(new_block);
            	new_block.clear();
        	}
        	new_block.push_back(ciphertext_bytes[i]);
    	}
	if(new_block.size()>0){
    		result.element2.push_back(new_block);
	}
	return result;
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

auto ciphermodes::CTR_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
	std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
	std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
	aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
	std::vector<std::vector<aes::byte>> plaintext_blocks = ciphermodes::create_blocks(plaintext_bytes);
	aes::word counter= 0U;
	auto temp = randgen<128>();
	std::array <aes::byte, 12> nonce;
	for(size_t i =0; i<12; i++){
	       nonce[i]=temp[i];
	}	       
	for(auto& plain_block: plaintext_blocks){
		aes::state CTR = create_CTR(nonce, counter);
		aes::encrypt(nk_nr[1], CTR, expandedKey);
		std::vector<aes::byte> encrypted_block = convert_state_to_block(CTR);
		plain_block= xor_blocks(plain_block, encrypted_block);
		counter++;
	}
	std::vector<aes::byte> ciphertext_bytes = merge_IV_blocks<12>(nonce, plaintext_blocks);
	return ciphertext_bytes;	
}

auto ciphermodes::CTR_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
	std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
        std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
        aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
	aes::Tuple<std::array<aes::byte, 12>, std::vector<std::vector<aes::byte>>> nonce_cipherblocks = create_nonce_blocks(ciphertext_bytes);
	aes::word counter = 0U;
	for(auto& cipher_block: nonce_cipherblocks.element2){
		aes::state CTR = create_CTR(nonce_cipherblocks.element1, counter);
		aes::encrypt(nk_nr[1], CTR, expandedKey);
		std::vector<aes::byte> encrypted_block = convert_state_to_block(CTR);
		cipher_block = xor_blocks(cipher_block,encrypted_block);
		counter++;
	}
	std::vector<aes::byte> plaintext_bytes = merge_blocks(nonce_cipherblocks.element2);
	return plaintext_bytes;
}

auto ciphermodes::CBC_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    pad_plaintext(plaintext_bytes);
    std::vector<std::vector<aes::byte> > plaintext_blocks = ciphermodes::create_blocks(plaintext_bytes);
    
    auto IV = randgen<128>();
    std::vector<aes::byte> temp;
    for(auto byte: IV){
	    temp.push_back(byte);
    }
    
    plaintext_blocks.insert(plaintext_blocks.begin(), temp);

    for(int i = 1; i < plaintext_blocks.size(); i++){
        plaintext_blocks[i] = xor_blocks(plaintext_blocks[i],plaintext_blocks[i-1]);
        aes::state state = convert_block_to_state(plaintext_blocks[i]);
        aes::encrypt(nk_nr[1], state, expandedKey);
        plaintext_blocks[i] = convert_state_to_block(state);
    }
    std::vector<aes::byte> ciphertext_bytes = merge_blocks(plaintext_blocks);
    return ciphertext_bytes;
}


auto ciphermodes::CBC_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    std::vector<std::vector<aes::byte> > ciphertext_blocks =  ciphermodes::create_blocks(std::move(ciphertext_bytes));
    
    for(int i =  ciphertext_blocks.size() - 1; i > 0; i--){
        aes::state state = convert_block_to_state(ciphertext_blocks[i]);
        aes::decrypt(nk_nr[1], state, expandedKey);
        ciphertext_blocks[i] = convert_state_to_block(state);
        ciphertext_blocks[i] = xor_blocks(ciphertext_blocks[i],ciphertext_blocks[i-1]);
    }

    ciphertext_blocks.erase(ciphertext_blocks.begin());
    std::vector<aes::byte> plaintext_bytes = merge_blocks(ciphertext_blocks);
    unpad_ciphertext(plaintext_bytes);
    return plaintext_bytes;
}

auto ciphermodes::CFB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);

    auto IV = randgen<128>();
    std::vector<aes::byte> temp;
    for(auto byte: IV){
	    temp.push_back(byte);
    }
    std::vector<std::vector<aes::byte> > plaintext_blocks = ciphermodes::create_blocks(plaintext_bytes);
    for(size_t i=0; i< plaintext_blocks.size(); i++){
	    aes::state state = convert_block_to_state(temp);
	    aes::encrypt(nk_nr[1], state, expandedKey);
	    temp = convert_state_to_block(state);
	    temp = xor_blocks(plaintext_blocks[i], temp);
	    plaintext_blocks[i] = temp;
    }
    std::vector<aes::byte> ciphertext_bytes = merge_IV_blocks<16>(IV, plaintext_blocks);
    return ciphertext_bytes;
}

auto ciphermodes::CFB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    std::vector<std::vector<aes::byte> > ciphertext_blocks =  create_blocks(ciphertext_bytes);
    std::vector<std::vector<aes::byte> > plaintext_blocks;
    for(size_t i=1; i < ciphertext_blocks.size(); i++){
	    aes::state state = convert_block_to_state(ciphertext_blocks[i-1]);
	    aes::encrypt(nk_nr[1], state, expandedKey);
	    std::vector<aes::byte> temp = convert_state_to_block(state);
	    temp = xor_blocks(ciphertext_blocks[i], temp);
	    plaintext_blocks.push_back(temp);
    }
    std::vector<aes::byte> plaintext_bytes = merge_blocks(plaintext_blocks);
    return plaintext_bytes;
}

auto ciphermodes::OFM_Encrypt(const std::vector<aes::byte>& plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte> {
    using block_vector = std::vector<std::vector<aes::byte>>; // Shorthand notation

    const auto NK_NR = aes::get_Nk_Nr(key_bytes.size());
    const int NK = NK_NR[0];
    const int NR = NK_NR[1];

    // Key expansion
    std::vector<aes::word> expanded_key(aes::NB * (NR + 1));
    aes::key_expansion(key_bytes, expanded_key, NK, NR);

    block_vector plaintext_blocks = create_blocks(plaintext_bytes);

    block_vector ciphertext_blocks{};

    auto IV = randgen<128>(); // Random nonce used in first iteration of OFM

    // Prepare ciphertext_blocks[0] as encrypted IV XOR m[0]
    auto IV_state = convert_block_to_state<128>(IV);
    aes::encrypt(NR, IV_state, expanded_key);
    ciphertext_blocks.emplace_back(
        xor_blocks(
            plaintext_blocks[0],
            convert_state_to_block(IV_state)            
        )
    );

    // Iterate from 1...N blocks
    for (std::size_t i = 1; i < plaintext_blocks.size(); ++i) {

        // Encrypt the result of XORing the previous cipher and plaintext blocks
        aes::state prev_xor_state = convert_block_to_state(
            xor_blocks(
                ciphertext_blocks[i - 1],
                plaintext_blocks[i - 1]
            )
        ); 
        aes::encrypt(NR, prev_xor_state, expanded_key);

        // New cipher is the XOR of current plaintext block and prev_xor_state
        ciphertext_blocks.emplace_back(
            xor_blocks(
                plaintext_blocks[i],
                convert_state_to_block(prev_xor_state)
            )    
        );
    }

    return merge_IV_blocks<16>(IV, ciphertext_blocks);
}

auto ciphermodes::OFM_Decrypt(const std::vector<aes::byte>& ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte> {
    using block_vector = std::vector<std::vector<aes::byte>>; // Shorthand notation

    const auto NK_NR = aes::get_Nk_Nr(key_bytes.size());
    const int NK = NK_NR[0];
    const int NR = NK_NR[1];

    // Key expansion
    std::vector<aes::word> expanded_key(aes::NB * (NR + 1));
    aes::key_expansion(key_bytes, expanded_key, NK, NR);
    block_vector ciphertext_blocks = create_blocks(ciphertext_bytes);
    block_vector plaintext_blocks{};

    // Extract IV from the ciphertext's block (the first) and remove it from the ciphertext_blocks
    std::vector<aes::byte> IV{ciphertext_blocks[0]};
    ciphertext_blocks.erase(ciphertext_blocks.begin());

    // Prepare message_blocks[0] as XOR of cipher[0] and encrypted IV
    auto IV_state = convert_block_to_state(IV);
    aes::encrypt(NR, IV_state, expanded_key);

    plaintext_blocks.emplace_back(
        xor_blocks(
            ciphertext_blocks[0],
            convert_state_to_block(IV_state)
        )
    );

    // std::cout << ciphertext_blocks.size() << std::endl;
    // std::cout << plaintext_blocks.size() << std::endl;
    // Iterate from 1...N blocks
    for (std::size_t i = 1; i < ciphertext_blocks.size(); ++i) {

        // Encrypt the result of XORing the previous cipher and plaintext blocks
        aes::state prev_xor_state = convert_block_to_state(
            xor_blocks(
                ciphertext_blocks[i - 1],
                plaintext_blocks[i - 1]
            )
        ); 
        aes::encrypt(NR, prev_xor_state, expanded_key);

        // New plaintext block is the XOR of current cipher block and prev_xor_state
        plaintext_blocks.emplace_back(
            xor_blocks(
                ciphertext_blocks[i],
                convert_state_to_block(prev_xor_state)
            )    
        );
    }

    return merge_blocks(plaintext_blocks);
}