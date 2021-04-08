import pwn
import os
import time 


def padding_oracle():
    p = pwn.process(["bin/aes_exec", "-in", "attempt","-k", "keyfile", "-m", "cbc","-out", "decrypted", "-d", "-iv", "IV"])
    prog_output = p.clean()
    p.kill()
    if os.path.exists("attempt"):
        os.remove("attempt")
    if(prog_output == b'Error While Unpadding!\n'):
        return False
    return True

if os.path.exists("attempt"):
    os.remove("attempt")

if os.path.exists("ciphertext"):
    os.remove("ciphertext")

if os.path.exists("IV"):
    os.remove("IV")

if os.path.exists("decrypted"):
    os.remove("decrypted")
#encrypt a message 
p = pwn.process(["bin/aes_exec", "-in", "testinput","-k", "keyfile", "-m", "cbc","-out", "ciphertext", "-e"])
p.clean()
p.kill()


#attempt to discover the length of the message
f = open("ciphertext", "rb")
byteArray = bytearray(f.read())
fileSize = len(byteArray)
start = (int)((fileSize / 16)-2)*16
end = (int)((fileSize / 16)-1)*16
f.close()
block_length = -1


for i in range(16):
    tempArray = byteArray.copy()
    for j in range(start,start+i+1):
        tempArray[j] ^= 0xff;

    f = open("attempt","wb")
    f.write(tempArray)
    f.close()
    
    if(not padding_oracle()):
        block_length = i
        break


output = ""
arr = []

for k in range(0, block_length):
    b = 16 - block_length + k 
    for i in range(256):
        tempArray2 = byteArray.copy()
        tempArray2[start + (16-b) - 1 ] ^= i; 
        
        for j in range(0, len(arr)):
            tempArray2[start + (16-b)  + j ] ^= arr[j] ^ (b+1)

        for j in range(start + (16-b)  + len(arr),end):
            tempArray2[j] ^= (16 - block_length) ^ (b+1)
        
        f = open("attempt","wb")
        f.write(tempArray2)
        f.close()
        
        if(padding_oracle()):
            arr.insert(0,i ^ (b+1))
            output += chr(i ^ (b+1))
            break

print("The last block of the message is: " + output[::-1])