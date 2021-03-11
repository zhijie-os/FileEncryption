from Crypto import Random
from Crypto.Cipher import AES
import hashlib
from base64 import b64encode, b64decode


class AEShandler():
    
    def __init__(self, key, file_in, file_out,direction):
        self.key = hashlib.sha256(key.encode()).digest()
        self.block_size = AES.block_size
        self.file_in = file_in
        self.file_out = file_out
        self.direction = direction
        self.decision()

    # Using ISO/IEC 7816 for padding
    def padding(self, plaintext):
        # determine the number of bytes to be padded
        toPad = self.block_size - len(plaintext) % self.block_size
        if toPad > 0:
            # pad 0x80 as first octets
            padded_text = plaintext+b"\x80"
            toPad -= 1
            # pad 0x00 toPad times that follows 0x80 
            for i in range(toPad):
                padded_text = padded_text+b"\x00"
                
        # return the padded text
        return padded_text

    # remove ISO/IEC 7816 padded bytes by finding the first none-zero bytes from right to left
    def unpadding(self, padded_text):
        # start from the most right 1
        i = 1
        # search from right to left until the first none-zero octets
        while int(padded_text[-i]) == 0:
            i += 1
        
        # truncate the stream
        unpadded_text = padded_text[:-i:]
        
        # return the unpadded text 
        return unpadded_text
   
    # encrypt a binary string with CBC mode 
    def encrypt(self, plaintext):
        # pad the text
        padded_text = self.padding(plaintext)
        # initialize a random IV
        initialVector = Random.new().read(AES.block_size)
        # encrypt with AES CBC mode
        aes = AES.new(self.key, AES.MODE_CBC, initialVector)
        ciphertext = aes.encrypt(padded_text)
        
        # encode IV and ciphertext together, and return the encoded ciphertext 
        return b64encode(initialVector+ciphertext)

    # decrypt a binary string with CBC mode
    def decrypt(self, ciphertext):
        # seperate IV and ciphertext
        ciphertext = b64decode(ciphertext)
        initialVector = ciphertext[:self.block_size]
        
        # decrypt with AES CBC mode
        aes = AES.new(self.key, AES.MODE_CBC, initialVector)
        padded_text = aes.decrypt(ciphertext[self.block_size:])
        
        # unpad the padded plaintext
        unpadded_text = self.unpadding(padded_text)
        
        # return the plaintext
        return unpadded_text

    # encrypt a file
    def encrypt_file(self):
        # open a file and read its contents as binary string
        with open(self.file_in, 'rb') as file:
            plaintext = file.read()

        # encrypt the binary string
        ciphertext = self.encrypt(plaintext)

        # open a file and write the binary string ciphertext into it
        with open(self.file_out, 'wb') as file:
            file.write(ciphertext)

    # decrytp a file
    def decrypt_file(self):
        # open a file and read its contents as binary string
        with open(self.file_in, 'rb') as file:
            ciphertext = file.read()
        
        # decrypt the binary string
        plaintext = self.decrypt(ciphertext)
        
        # open a file and write the binary string plaintext into it
        with open(self.file_out,'wb') as file:
            file.write(plaintext)
              
    # decide whether to encrypt or to decrypt 
    def decision(self):
        # if the direction is 1, encrypt
        if self.direction==1:
            self.encrypt_file()
        else:#else decrypt
            self.decrypt_file()
    
    
AEShandler("abcd","foo.mkv","foo_encrypted",1)
AEShandler("abcd","foo_encrypted","foo_decrypted",0)