import pwn
import os
import time 

# Requirements:
# plaintext in a file named "testinput"
# key in a file named "keyfile"


# padding oracle which wraps our AES implementation
def padding_oracle():
    # attempts to decrypt a modified ciphertext in the file "attempt"
    p = pwn.process(["bin/aes_exec", "-in", "attempt","-k", "keyfile", "-m", "cbc","-out", "decrypted", "-d"])
    prog_output = p.clean()
    p.kill()

    # returns true or false depending on if a padding error occurs
    if os.path.exists("attempt"):
        os.remove("attempt")
    if(prog_output == b'Error While Unpadding!\n'):
        return False
    return True

#remove any existing files 
if os.path.exists("attempt"):
    os.remove("attempt")

if os.path.exists("ciphertext"):
    os.remove("ciphertext")

if os.path.exists("decrypted"):
    os.remove("decrypted")

#encrypt a message that is in the file named "testinput" and output to a file named "ciphertext"
p = pwn.process(["bin/aes_exec", "-in", "testinput","-k", "keyfile", "-m", "cbc","-out", "ciphertext", "-e"])
p.clean()
p.kill()


#attempt to discover the length of the message
f = open("ciphertext", "rb")
byteArray = bytearray(f.read()) #store the ciphertext
fileSize = len(byteArray) #length of the ciphertext
start = (int)((fileSize / 16)-2)*16 #start index of the last block
end = (int)((fileSize / 16)-1)*16 #end index of the last block
f.close()
block_length = -1

# We modify each byte iteratively until we modify the padding and incur a padding error
for i in range(16):
    tempArray = byteArray.copy()
    for j in range(start,start+i+1):
        tempArray[j] ^= 0xff;

    f = open("attempt","wb")
    f.write(tempArray)
    f.close()
    
    if(not padding_oracle()): #This means that we have successfully modified the first byte of the padding
        #We have discovered the length of the last block of the encrypted message.
        block_length = i
        break


output = ""
arr = []

#attempt to increase the padding iteratively
for k in range(0, block_length):
    b = 16 - block_length + k  #increase the number of padding bytes
    for i in range(256): # attempt to brute force the value which XOR'd with the byte we are trying to discover is equal to the new padding byte
        tempArray2 = byteArray.copy()
        tempArray2[start + (16-b) - 1 ] ^= i; 
        
        for j in range(0, len(arr)): #for the bytes that we have already discovered their value, modify the ciphertext to change these into padding bytes of the new length
            tempArray2[start + (16-b)  + j ] ^= arr[j] ^ (b+1)

        for j in range(start + (16-b)  + len(arr),end): #modify the original padding bytes to be of value of the new padding byte length
            tempArray2[j] ^= (16 - block_length) ^ (b+1)
        
        f = open("attempt","wb")
        f.write(tempArray2)
        f.close()
        
        if(padding_oracle()): #if no padding error is incurred, we have can compute the value of this byte
            arr.insert(0,i ^ (b+1))
            output += chr(i ^ (b+1))
            break

print("The last block of the message is: " + output[::-1])