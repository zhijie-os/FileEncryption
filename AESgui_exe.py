#!/usr/bin/env python

import os
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from Crypto import Random
from Crypto.Cipher  import AES
from base64 import b64encode, b64decode


class AEShandler:
    def __init__(self, user_file, user_key, direction):
        # get the path to input file
        self.user_file = user_file

        self.user_key = hashlib.sha256(user_key.encode()).digest()
        self.block_size = AES.block_size
        self.direction = direction
    
        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
            + "." + self.file_extension + ".ciph"

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
            + "_decrypted_." + self.decrypt_output_file[-1]

        self.decision()
        

    def padding(self, plaintext):
        toPad = self.block_size - len(plaintext) % self.block_size
        if toPad > 0:
            padded_text = plaintext+b"\x80"
            toPad -= 1
            for i in range(toPad):
                padded_text = padded_text+b"\x00"
            return padded_text
            
    def unpadding(self, padded_text):
        i = 1
        while int(padded_text[-i]) == 0:
            i += 1
        unpadded_text = padded_text[:-i:]
        return unpadded_text

    def encrypt(self):
        self.abort()
        
        with open(self.user_file, 'rb') as file:
            #print("encrypt(): opening & reading input file")
            plaintext = file.read()
        
        #print("encrypt(): DONE opening & reading input file")
        
        padded_text = self.padding(plaintext)
        initialVector = Random.new().read(AES.block_size)
        aes = AES.new(self.user_key, AES.MODE_CBC, initialVector)
        ciphertext = aes.encrypt(padded_text)
        encrypted_text = b64encode(initialVector+ciphertext)
        
        #print("encrypt(): DONE encrypting text")

        with open(self.encrypt_output_file, 'ab') as file:
            #print("encrypt(): opening & reading encrypted output file")
            file.write(encrypted_text)
        
        #print("encrypt(): DONE opening & reading encrypted output file")
        
        del aes
        #print("encrypt(): Deleted aes instance")

    def decrypt(self):
        self.abort() # if the output file already exists, remove it first
        
        with open(self.user_file, 'rb') as file:
            plaintext = file.read()
        
        plaintext = b64decode(plaintext)
        initialVector = plaintext[:self.block_size]
        aes = AES.new(self.user_key, AES.MODE_CBC, initialVector)
        padded_text = aes.decrypt(plaintext[self.block_size:])
        unpadded_text = self.unpadding(padded_text)

        with open(self.decrypt_output_file,'xb') as file:
            file.write(unpadded_text)      
            
        del aes

    def decision(self):
        if self.direction==1:
            self.encrypt()
        else:
            self.decrypt()
            
    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

class MainWindow:

    # configure root directory path relative to file
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        # frozen
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        # unfrozen
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self._AES_cipher = None
        self._file_path = tk.StringVar()
        self._secret_user_key = tk.StringVar()
        self._percent_status = tk.StringVar()
        self._percent_status.set("----")

        self.cancel_function = False

        root.title("AES Cipher Application")
        root.configure(bg="#eeeeee")

        try:
            icon_img = tk.Image(
                "photo",
                file=self.THIS_FOLDER_G + "/images/lock_icon.png"
            )
            root.call(
                "wm",
                "iconphoto",
                root._w,
                icon_img
            )
        except Exception:
            pass

        self.menu_bar = tk.Menu(
            root,
            bg="#eeeeee",
            relief=tk.FLAT
        )
        self.menu_bar.add_command(
            label="Quit!",
            command=root.quit
        )

        root.configure(
            menu=self.menu_bar
        )

        self.file_path_entry_label = tk.Label(
            root,
            text="Enter File Path OR Click SELECT FILE Button",
            bg="#eeeeee",
            anchor=tk.W
        )
        self.file_path_entry_label.grid(
            padx=14,
            pady=(10, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.file_path_entry = tk.Entry(
            root,
            textvariable=self._file_path,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.file_path_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.select_button = tk.Button(
            root,
            text="SELECT FILE",
            command=self.select_file_path_cb,
            width=42,
            bg="#1089ff",
            fg="#303030",
            bd=2,
            relief=tk.FLAT
        )
        self.select_button.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.secret_user_key_entry_label = tk.Label(
            root,
            text="Enter Secret Key",
            bg="#eeeeee",
            anchor=tk.W
        )
        self.secret_user_key_entry_label.grid(
            padx=14,
            pady=(10, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.secret_user_key_entry = tk.Entry(
            root,
            textvariable=self._secret_user_key,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.secret_user_key_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.encrypt_button = tk.Button(
            root,
            text="ENCRYPT",
            command=self.encrypt_file_cb,
            bg="#ce0000",
            fg="#303030",
            bd=2,
            relief=tk.FLAT
        )
        self.encrypt_button.grid(
            padx=(15, 6),
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=0,
            columnspan=2,
            sticky=tk.W+tk.E+tk.N+tk.S
        )
        
        self.decrypt_button = tk.Button(
            root,
            text="DECRYPT",
            command=self.decrypt_file_cb,
            bg="#00af00",
            fg="#303030",
            bd=2,
            relief=tk.FLAT
        )
        self.decrypt_button.grid(
            padx=(6, 15),
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=2,
            columnspan=2,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.reset_button = tk.Button(
            root,
            text="RESET",
            command=self.reset_cb,
            bg="#00af00",
            fg="#303030",
            bd=2,
            relief=tk.FLAT
        )
        self.reset_button.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=8,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.percent_status_label = tk.Label(
            root,
            textvariable=self._percent_status,
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350
        )
        self.percent_status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

    def select_file_path_cb(self):
        try:
            name = filedialog.askopenfile()
            self._file_path.set(name.name)
            # print(name.name)
        except Exception as e:
            self._percent_status.set(e)
            self.percent_status_label.update()
    
    def disable_function(self):
        self.file_path_entry.configure(state="disabled")
        self.secret_user_key_entry.configure(state="disabled")
        self.select_button.configure(state="disabled")
        self.encrypt_button.configure(state="disabled")
        self.decrypt_button.configure(state="disabled")
        self.reset_button.configure(text="CANCEL", command=self.cancel_function_cb,
            fg="#ed3833", bg="#fafafa")
        self.percent_status_label.update()
    
    def reenable_function(self):
        self.file_path_entry.configure(state="normal")
        self.secret_user_key_entry.configure(state="normal")
        self.select_button.configure(state="normal")
        self.encrypt_button.configure(state="normal")
        self.decrypt_button.configure(state="normal")
        self.reset_button.configure(text="RESET", command=self.reset_cb,
            fg="#ffffff", bg="#aaaaaa")
        self.percent_status_label.update()

    def encrypt_file_cb(self):
        self.disable_function()

        try:
            self._AES_cipher = AEShandler(
                self._file_path.get(),
                self._secret_user_key.get(),
                1
            )
            for percentage in self._AES_cipher.encrypt():
                if self.cancel_function:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._percent_status.set(percentage)
                self.percent_status_label.update()
            self._percent_status.set("File Encrypted!")
            if self.cancel_function:
                self._AES_cipher.abort()
                self._percent_status.set("Cancelled!")
            self._AES_cipher = None
            self.cancel_function = False
        except Exception as e:
            self._percent_status.set(e)

        self.reenable_function()

    def decrypt_file_cb(self):
        self.disable_function()

        try:
            self._AES_cipher = AEShandler(
                self._file_path.get(),
                self._secret_user_key.get(),
                0
            )
            for percentage in self._AES_cipher.decrypt():
                if self.cancel_function:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._percent_status.set(percentage)
                self.percent_status_label.update()
            self._percent_status.set("File Decrypted!")
            if self.cancel_function:
                self._AES_cipher.abort()
                self._percent_status.set("Cancelled!")
            self._AES_cipher = None
            self.cancel_function = False
        except Exception as e:
            # print(e)
            self._percent_status.set(e)
        
        self.reenable_function()

    def reset_cb(self):
        self._AES_cipher = None
        self._file_path.set("")
        self._secret_user_key.set("")
        self._percent_status.set("----")
    
    def cancel_function_cb(self):
        self.cancel_function = True

if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()
