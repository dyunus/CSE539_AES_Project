# CSE539_AES_Project

Team Members:
- Bailey Capuano
- Luis Prieto
- Danial Yunus

Dependencies:
```
CMake >= v3.13
clang-tidy
Suggested compiler: clang >= v10
Linux, Mac, and Windows support
```

Compilation:
```
cd build && ./build.sh
```

How To Use:
```
echo -ne "\x70\x6f\x67\x67" > plaintext    

Usage: aes_exec [OPTION]...
-h, --help                               Display this help text
-g <argument>, --gen <argument>          Generate random key of argument bit length and stores it in file named genkey
-e, --encrypt                            Encrypt a given input
-d, --decrypt                            Decrypt a given input
-m <ecb | cbc | ctr | cfb | ofm>         Designate a mode of operation
-in <argument>                           Input filename
-out <argument>                          Output filename
-k <argument>                            Specify key for AES
-iv <argument>                           Specify Initialazion Vector for certain modes of operation

EXAMPLE:
aes_exec --gen 256
aes_exec --encrypt -m ecb -in plaintext -k genkey -out encryptedMessage
aes_exec --decrypt -m ecb -in encryptedMessage -k genkey -out decryptedMessage
```

