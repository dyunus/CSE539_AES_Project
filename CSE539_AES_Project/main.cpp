//
//  main.cpp
//  CSE539_AES_Project
//
//  Created by Danial Yunus on 2/17/21.
//


#include <iostream>
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
    string plaintext = argv[1];
    cout << cipher(plaintext) << endl;
    return 0;
}
