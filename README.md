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
bin/aes_exec plaintext keyfile3
```

