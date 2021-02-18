//
//  main.h
//  CSE539_AES_Project
//
//  Created by Danial Yunus on 2/17/21.
//

#ifndef main_h
#define main_h


#endif /* main_h */

#include <string>
using namespace std;

string cipher(string plaintext){
    int key = 2;
    string ciphertext = "";
    for(char& c : plaintext){
        ciphertext += c ^ key;
    }
    return ciphertext;
}
