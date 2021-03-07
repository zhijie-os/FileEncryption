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

    def padding(self, plaintext):
        toPad = self.block_size - len(plaintext) % self.block_size
        if toPad > 0:
            padded_text = plaintext+b"\x80"
            toPad -= 1
            for i in range(toPad):
                padded_text = padded_text+b"\x00"
            return padded_text

    def encrypt(self, plaintext):
        padded_text = self.padding(plaintext)
        initialVector = Random.new().read(AES.block_size)
        aes = AES.new(self.key, AES.MODE_CBC, initialVector)
        ciphertext = aes.encrypt(padded_text)
        return b64encode(initialVector+ciphertext)

    def unpadding(self, padded_text):
        i = 1
        while int(padded_text[-i]) == 0:
            i += 1
        unpadded_text = padded_text[:-i:]
        return unpadded_text

    def decrypt(self, ciphertext):
        ciphertext = b64decode(ciphertext)
        initialVector = ciphertext[:self.block_size]
        aes = AES.new(self.key, AES.MODE_CBC, initialVector)
        padded_text = aes.decrypt(ciphertext[self.block_size:])
        unpadded_text = self.unpadding(padded_text)
        return unpadded_text

    def encrypt_file(self):
        with open(self.file_in, 'rb') as file:
            plaintext = file.read()

        ciphertext = self.encrypt(plaintext)

        with open(self.file_out, 'wb') as file:
            file.write(ciphertext)

    def decrypt_file(self):
        with open(self.file_in, 'rb') as file:
            ciphertext = file.read()
        
        plaintext = self.decrypt(ciphertext)
        
        with open(self.file_out,'wb') as file:
            file.write(plaintext)
              
    def decision(self):
        if self.direction==1:
            self.encrypt_file()
        else:
            self.decrypt_file()
    
    

AEShandler("abcd","foo.mkv","foo_encrypted",1)
AEShandler("abcd","foo_encrypted","foo_decrypted",0)