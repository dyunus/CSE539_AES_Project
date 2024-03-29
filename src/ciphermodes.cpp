#include "ciphermodes.hpp"
#include "aes_exceptions.hpp"
#include "yandom.hpp"


auto ciphermodes::genKey(int keySize) -> std::vector<aes::byte>{
    int keySizeInBytes = keySize / 8;
    
    //generate a random 256 bit key
    auto key = randgen<256>();

    //convert the key into a byte vector
    std::vector<aes::byte> temp;
    for(auto byte: key){
        temp.push_back(byte);
    }

    //truncate to the desired key length passed in (128,192,or 256)
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
        //number of padding bytes needed is equal to the block length - the number of bytes in the last partial block of the message
		aes::byte padNum = 16 - (plaintext_bytes.size() % 16);
        //add hex representation of number of bytes added b times where b is the number of padding bytes needed
        for(std::size_t i = 0; i < padNum; i++){
            plaintext_bytes.push_back(padNum);
        }
}

void ciphermodes::unpad_ciphertext(std::vector<aes::byte>& ciphertext_bytes){
		//store the value of the last byte of padding, since according to PKCS#7 padding format, that value should appear as many times
        //as its value from right to left
        aes::byte padNum = ciphertext_bytes.back();
        //remove the padding bytes from right to left and assert that the value follows PKCS#7 format
        for(aes::byte i = 0; i < padNum; i++){
            aes::byte check = ciphertext_bytes.back();
            if(check != padNum){
                throw aes_error("Error While Unpadding!\n");
            }
            ciphertext_bytes.pop_back();
        }
}

auto ciphermodes::xor_blocks(std::vector<aes::byte> block1,std::vector<aes::byte> block2) -> std::vector<aes::byte> {
    for(std::size_t i = 0; i < ((block1.size() < block2.size()) ? block1.size() : block2.size()); i++){
            block1[i] ^= block2[i];
    }
    return block1;
}

auto ciphermodes::merge_blocks(const std::vector<std::vector<aes::byte>>& ciphertext_blocks) -> std::vector<aes::byte>{
	//new vector to store the combined bytes of every block
    std::vector<aes::byte> ciphertext_bytes;
    //iterate through all blocks
    for (const auto& cipher_block : ciphertext_blocks) {
        //iterate throught the bytes of each block and add them to the comvined vector
        for (const auto& block_byte : cipher_block) {
            ciphertext_bytes.push_back(block_byte);
        }
    }
    //returned the combined bytes of every block
    return ciphertext_bytes;
}

auto ciphermodes::create_blocks(std::vector<aes::byte> plaintext_bytes) -> std::vector<std::vector<aes::byte> >{
	//new vector of vectors to store the plaintext as a vector of blocks (each block is a vector of bytes)
    std::vector<std::vector<aes::byte> > plaintext_blocks;
    
    //temp variable to build the current block
    std::vector<aes::byte> new_block;
    
    //iterate through the plaintext
    for(std::size_t i = 0; i < plaintext_bytes.size(); i++){
        //every 128 bits (16 bytes), the completed block is added to the vector of vectors
        if(i != 0 && i % 16 == 0){
            plaintext_blocks.push_back(new_block);
            new_block.clear();
        }
        new_block.push_back(plaintext_bytes[i]);
    }
    plaintext_blocks.push_back(new_block);
    //returned the vector of blocks correspodning to the plaintext
    return plaintext_blocks;
}

auto ciphermodes::convert_block_to_state(std::vector<aes::byte> block) -> aes::state{
    int index = 0;
    aes::state state;
    //in AES, a block's contents are populated column after column as opposed to row after row
    for(std::size_t j = 0; j < aes::NB; j++) {
        for(std::size_t i = 0; i < aes::NB; i++){
            state[i][j] = block[index++];
        }
    }
    return state;
}

auto ciphermodes::convert_state_to_block(aes::state state) -> std::vector<aes::byte>{
    std::vector<aes::byte> block;
    //in AES, a block's contents are populated column after column as opposed to row after row
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

	block.reserve(sizeof(aes::byte) * 16);

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
	
	//gets the 12 bytes of the CTR IV from the first 12 bytes of the ciphertext
	for(std::size_t i=0; i<12; i++){
		result.element1.at(i) = ciphertext_bytes[i];
	}

	//creates the blocks that will be decrypted from the remaining bytes in the ciphertext
	std::vector<aes::byte> new_block;
    	for(std::size_t i =12; i < ciphertext_bytes.size(); i++){
        	if((i-12) != 0 && (i-12) % 16 == 0){
            	result.element2.push_back(new_block);
            	new_block.clear();
        	}
        	new_block.push_back(ciphertext_bytes[i]);
    	}
	if(!new_block.empty()){
    		result.element2.push_back(new_block);
	}
	return result;
}



auto ciphermodes::ECB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte> {
    
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 
    
    //key expansion
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    
    //pad the plaintext and separate plaintext into blocks for encryption
    pad_plaintext(plaintext_bytes);
    std::vector<std::vector<aes::byte> > plaintext_blocks = ciphermodes::create_blocks(plaintext_bytes);
    
    //iterate through all the blocks
    for(auto& plain_block : plaintext_blocks){
        aes::state state = convert_block_to_state(plain_block);
        //encrypt each block
        aes::encrypt(nk_nr[1], state, expandedKey);
        plain_block = convert_state_to_block(state);
    }

    //return the encrypted ciphertext
    std::vector<aes::byte> ciphertext_bytes = merge_blocks(plaintext_blocks);
    return ciphertext_bytes;
}

auto ciphermodes::ECB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte> {
    
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 

    //expand key
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);

    /**
     * In accordance with EXP63-CPP. Do not rely on the value of a moved-from object
     * While move semantics are great for efficient usage of larger data structures,
     * the incorrect use of move-semantics, that is using a moved object in the moved-from state,
     * has undefined behavior. We made sure to only utilize move semantics in places where:
     * 1) the data structure is sufficiently large to warrant for an efficiency gain
     * 2) the data structure is never used afterwards where it was moved from 
     **/
    //Separate ciphertext into blocks of 128 bits
    std::vector<std::vector<aes::byte> > ciphertext_blocks =  ciphermodes::create_blocks(std::move(ciphertext_bytes));
    
    //iterate through all blocks of the cipher text
    for (auto& block : ciphertext_blocks) {
        //decrypt each block
       aes::state state = convert_block_to_state(block);
        aes::decrypt(nk_nr[1], state, expandedKey);
        block = convert_state_to_block(state); 
    }
    //removes padding and returns the decrypted plaintext
    std::vector<aes::byte> plaintext_bytes = merge_blocks(ciphertext_blocks);
    unpad_ciphertext(plaintext_bytes);
    return plaintext_bytes;
}

auto ciphermodes::CTR_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
	std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
	
	//Key Expansion
	std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
	aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
	std::vector<std::vector<aes::byte>> plaintext_blocks = ciphermodes::create_blocks(std::move(plaintext_bytes));
	

	if(plaintext_blocks.size() > 4294967296){
		throw aes_error("Plaintext too large to securely encrypt with CTR.\n");
	}

	//counter starting at 0
	aes::word counter= 0U;

	//Create the 96 bit nonce for CTR mode
	auto temp = randgen<128>();
	std::array <aes::byte, 12> nonce{};
	for(size_t i =0; i<12; i++){
	       nonce.at(i) = temp.at(i);
	}

	//iterates over all plaintext blocks
	for(auto& plain_block: plaintext_blocks){
		aes::state CTR = create_CTR(nonce, counter); //appends the nonce with current value of the counter as a state matrix for encryption
		aes::encrypt(nk_nr[1], CTR, expandedKey);
		
		//takes the encrypted state and xors it with the plaintext
		std::vector<aes::byte> encrypted_block = convert_state_to_block(CTR);
		plain_block= xor_blocks(plain_block, encrypted_block);
		counter++;
	}
	//creates ciphertext by appending the 96bit IV to the beginning of the encrypted plaintext blocks
	std::vector<aes::byte> ciphertext_bytes = merge_IV_blocks<12>(nonce, plaintext_blocks);
	return ciphertext_bytes;	
}

auto ciphermodes::CTR_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
	std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
        
	//Key Expansion
	std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
        aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
	
	//extracts the IV from the first 12 ciphertext bytes and organizes the remaining bytes into blocks of 128 bits
	aes::Tuple<std::array<aes::byte, 12>, std::vector<std::vector<aes::byte>>> nonce_cipherblocks = create_nonce_blocks(std::move(ciphertext_bytes));
	
	//counter starting at 0
	aes::word counter = 0U;

	for(auto& cipher_block: nonce_cipherblocks.element2){
		aes::state CTR = create_CTR(nonce_cipherblocks.element1, counter); //appends nonce and counter as state matrix for encryption
		aes::encrypt(nk_nr[1], CTR, expandedKey);

		//take encrypted state and xors with ciphertext to get back original plaintext
		std::vector<aes::byte> encrypted_block = convert_state_to_block(CTR);
		cipher_block = xor_blocks(cipher_block,encrypted_block);
		counter++;
	}

	//returns decrypted plaintext
	std::vector<aes::byte> plaintext_bytes = merge_blocks(nonce_cipherblocks.element2);
	return plaintext_bytes;
}

auto ciphermodes::CBC_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 
    
    //key expansion
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    
    pad_plaintext(plaintext_bytes);

    //separate plaintext into blocks for encryption
    std::vector<std::vector<aes::byte> > plaintext_blocks = ciphermodes::create_blocks(plaintext_bytes);
    
    //get random IV
    auto IV = randgen<128>();
    std::vector<aes::byte> temp;
    temp.reserve(sizeof(aes::byte) * IV.size());
    for(auto byte: IV){
	    temp.push_back(byte);
    }
    
    //prepend the IV to the plaintext blocks for encryption to begin the cipher chain
    plaintext_blocks.insert(plaintext_blocks.begin(), temp);

    //iterates through all plaintext blocks
    for(std::size_t i = 1; i < plaintext_blocks.size(); i++){
        //xor the current block with the encrypted previous block (or the IV for the first block)
        plaintext_blocks[i] = xor_blocks(plaintext_blocks[i],plaintext_blocks[i-1]);
        aes::state state = convert_block_to_state(plaintext_blocks[i]);
        aes::encrypt(nk_nr[1], state, expandedKey);
        plaintext_blocks[i] = convert_state_to_block(state);
    }

    //returns the encrypted ciphertext
    std::vector<aes::byte> ciphertext_bytes = merge_blocks(plaintext_blocks);
    return ciphertext_bytes;
}


auto ciphermodes::CBC_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size()); 

    //key expansion
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);

    //Separate ciphertext into blocks of 128 bits where the first block is the IV
    std::vector<std::vector<aes::byte> > ciphertext_blocks =  ciphermodes::create_blocks(std::move(ciphertext_bytes));
    
    //iterates through ciphertext blocks starting at 1 since first block is the IV
    for(std::size_t i =  ciphertext_blocks.size() - 1; i > 0; i--){
        aes::state state = convert_block_to_state(ciphertext_blocks[i]);
        //decrypts the ciphertextr block
        aes::decrypt(nk_nr[1], state, expandedKey);
        ciphertext_blocks[i] = convert_state_to_block(state);
        ciphertext_blocks[i] = xor_blocks(ciphertext_blocks[i],ciphertext_blocks[i-1]);
    }

    //remove the IV from the plaintext
    ciphertext_blocks.erase(ciphertext_blocks.begin());
    
    //returns decrypted plaintext after removing padding
    std::vector<aes::byte> plaintext_bytes = merge_blocks(ciphertext_blocks);
    unpad_ciphertext(plaintext_bytes);
    return plaintext_bytes;
}

auto ciphermodes::CFB_Encrypt(std::vector<aes::byte> plaintext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
    
    //key expansion
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);

    //get random IV
    auto IV = randgen<128>();
    std::vector<aes::byte> temp;
    temp.reserve(sizeof(aes::byte) * IV.size());
    for(auto byte: IV){
	    temp.push_back(byte);
    }
    
    //separate plaintext into blocks for encryption
    std::vector<std::vector<aes::byte> > plaintext_blocks = ciphermodes::create_blocks(std::move(plaintext_bytes));
    
    //iterates through all plaintext blocks
    for(auto& plaintext_block : plaintext_blocks) {
	    
	    aes::state state = convert_block_to_state(temp);
	    aes::encrypt(nk_nr[1], state, expandedKey);
	    temp = convert_state_to_block(state);

	    //encrypted block becomes input of AES for next block's encryption
	    temp = xor_blocks(plaintext_block, temp);
	    plaintext_block = temp;
    }

    //creates ciphertext by appending the 96bit IV to the beginning of the encrypted plaintext blocks
    std::vector<aes::byte> ciphertext_bytes = merge_IV_blocks<16>(IV, plaintext_blocks);
    return ciphertext_bytes;
}

auto ciphermodes::CFB_Decrypt(std::vector<aes::byte> ciphertext_bytes, const std::vector<aes::byte>& key_bytes) -> std::vector<aes::byte>{
    std::array<int, 2> nk_nr = aes::get_Nk_Nr(key_bytes.size());
    
    //Key expansion
    std::vector<aes::word> expandedKey(aes::NB*(nk_nr[1]+1));
    aes::key_expansion(key_bytes, expandedKey, nk_nr[0], nk_nr[1]);
    
    //Separate ciphertext into blocks of 128 bits where the first block is the IV
    std::vector<std::vector<aes::byte> > ciphertext_blocks =  create_blocks(std::move(ciphertext_bytes));
    std::vector<std::vector<aes::byte> > plaintext_blocks;

    //iterates through ciphertext blocks starting at 1 since first block is the IV
    for(size_t i=1; i < ciphertext_blocks.size(); i++){
	    aes::state state = convert_block_to_state(ciphertext_blocks[i-1]);
	    aes::encrypt(nk_nr[1], state, expandedKey);
	    
	    //decryption of ciphertext
	    std::vector<aes::byte> temp = convert_state_to_block(state);
	    temp = xor_blocks(ciphertext_blocks[i], temp);
	    plaintext_blocks.push_back(temp);
    }

    //returns decrypted plaintext
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
