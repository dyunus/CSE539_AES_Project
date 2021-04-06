# CSE539_AES_Project

Team Members:
- Bailey Capuano
- Luis Prieto
- Danial Yunus

Compilation:
```
cd build && ./build.sh
```

How To Use:
```
echo -ne "\x70\x6f\x67\x67" > plaintext    
echo -ne "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4" > keyfile3
Usage: aes_exec [OPTION]...
-h, --help                               Display this help text
-e, --encrypt                            Encrypt a given input
-d, --decrypt                            Decrypt a given input
-m <ecb | cbc | ctr | cfb | ofm>         Designate a mode of operation
-in <argument>                           Input filename
-out <argument>                          Output filename
-k <argument>                            Specify key for AES
-iv <argument>                           Specify Initialazion Vector for certain modes of operation

EXAMPLE:
aes_exec --encrypt -m ecb -in plaintext -k keyfile3 -out encryptedMessage
aes_exec --decrypt -m ecb -in encryptedMessage -k keyfile3 -out decryptedMessage
```

