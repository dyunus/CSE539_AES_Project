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
Linux, Mac, and (maybe) Windows support
```

Compilation:
```
cd build && ./build.sh
```

How To Use:
```
echo -ne "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10" > plaintext  

Usage: aes_exec [OPTION]...
-h, --help                               Display this help text
-g <argument>, --gen <argument>          Generate random key of argument bit length and stores it in file named genkey
-e, --encrypt                            Encrypt a given input
-d, --decrypt                            Decrypt a given input
-m <ecb | cbc | ctr | cfb | ofm>         Designate a mode of operation
-in <argument>                           Input filename
-out <argument>                          Output filename
-k <argument>                            Specify key for AES

EXAMPLE:
aes_exec --gen 256
aes_exec --encrypt -m ecb -in plaintext -k genkey -out encryptedMessage
aes_exec --decrypt -m ecb -in encryptedMessage -k genkey -out decryptedMessage
diff plaintext decryptedMessage
```

