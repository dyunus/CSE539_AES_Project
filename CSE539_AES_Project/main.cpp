//
//  main.cpp
//  CSE539_AES_Project
//
//  Created by Danial Yunus on 2/17/21.
//


#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <algorithm> //std::sorting
#include <vector> //std::vector
#include "main.h"

using namespace std;


int main(int argc, const char * argv[]) {
    // insert code here...
    cout << "Hello, World!\n";
    vector<int> plaintextBytes;
    ifstream plaintextFile(argv[1], ios::binary);
    while (plaintextFile) { //read file
        char byte = '\0';
        plaintextFile.get(byte);
        plaintextBytes.push_back(int(byte));
    }
    cout << cipher(plaintextBytes) << endl;
    return 0;
}
