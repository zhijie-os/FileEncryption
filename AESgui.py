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

class AEShandler():
    def __init__(self, key, file_name, direction):
        self.key = hashlib.sha256(key.encode()).digest()
        self.block_size = AES.block_size
        self.file_name = file_name
        self.direction = direction
        self.decision()
        # get the file extension
        self.file_extension = self.file_name.split(".")[-1]
        # encrypted file name
        self.encrypted_output_file = ".".join(self.file_name.split(".")[:-1]) \
            + "." + self.file_extension + ".encry"

        # decrypted file name
        self.decrypt_output_file = self.file_name[:-5].split(".")
        self.decrypted_output_file = ".".join(self.decrypt_output_file[:-1]) \
            + "__decrypted__." + self.decrypt_output_file[-1]
        
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
        with open(self.file_name, 'rb') as file:
            plaintext = file.read()

        ciphertext = self.encrypt(plaintext)

        with open(self.encrypted_output_file, 'ab') as file:
            file.write(ciphertext)

    def decrypt_file(self):
        with open(self.file_name, 'rb') as file:
            ciphertext = file.read()
        
        plaintext = self.decrypt(ciphertext)
        
        with open(self.decrypted_output_file,'xb') as file:
            file.write(plaintext)
          
    def decision(self):
        if self.direction==1:
            self.encrypt_file()
        else:
            self.decrypt_file()
        
class MainWindow:
    # configure root directory path relative to this file
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        # freeze
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        # unfreeze
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self.__cipher = None
        self.__file__path = tk.StringVar()
        self.__secret__key = tk.StringVar()
        self.__status__percentage = tk.StringVar()
        self.__status__percentage.set("******")

        self._canceled = False

        root.title("AESApp")
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

        self.menu_border = tk.Menu(
            root,
            bg="#eeeeee",
            relief=tk.FLAT
        )
        self.menu_border.add_command(
            label="Quit!",
            command=root.quit
        )

        root.configure(
            menu=self.menu_border
        )

        self.file_label = tk.Label(
            root,
            text="Enter File Path Or Click SELECT FILE Button",
            bg="#eeeeee",
            anchor=tk.W
        )
        self.file_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.file_entry = tk.Entry(
            root,
            textvariable=self.__file__path,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.file_entry.grid(
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
            command=self.file_select_cb,
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

        self.key_entry_label = tk.Label(
            root,
            text="Enter Secret Key (ONLY FOR DECRYPTION)",
            bg="#eeeeee",
            anchor=tk.W
        )
        self.key_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W+tk.E+tk.N+tk.S
        )

        self.key_entry = tk.Entry(
            root,
            textvariable=self.__secret__key,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.key_entry.grid(
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
            command=self.file_encrypt_cb,
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
            command=self.file_decrypt_cb,
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
            command=self.reset_callback,
            bg="#aaaaaa",
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

        self.status_percentage_label = tk.Label(
            root,
            textvariable=self.__status__percentage,
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350
        )
        self.status_percentage_label.grid(
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

    def file_select_cb(self):
        try:
            name = filedialog.askopenfile()
            self.__file__path.set(name.name)
            print(name.name)
        except Exception as e:
            self.__status__percentage.set(e)
            self.status_percentage_label.update()
    
    def freeze_controls(self):
        self.file_entry.configure(state="disabled")
        self.key_entry.configure(state="disabled")
        self.select_button.configure(state="disabled")
        self.encrypt_button.configure(state="disabled")
        self.decrypt_button.configure(state="disabled")
        self.reset_button.configure(text="CANCEL", command=self.cancel_callback,
            fg="#ed3833", bg="#fafafa")
        self.status_percentage_label.update()
    
    def unfreeze_controls(self):
        self.file_entry.configure(state="normal")
        self.key_entry.configure(state="normal")
        self.select_button.configure(state="normal")
        self.encrypt_button.configure(state="normal")
        self.decrypt_button.configure(state="normal")
        self.reset_button.configure(text="RESET", command=self.reset_callback,
            fg="#ffffff", bg="#aaaaaa")
        self.status_percentage_label.update()

    def file_encrypt_cb(self):
        self.freeze_controls()

        try:
            self.__cipher = AEShandler(
                self.__secret__key.get(),
                self.__file__path.get(),
                1
            )
            for percentage in self.__cipher.encrypt_file():
                if self._canceled:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self.__status__percentage.set(percentage)
                self.status_percentage_label.update()
            self.__status__percentage.set("File Encrypted!")
            if self._canceled:
                self.__cipher.abort()
                self.__status__percentage.set("Cancelled!")
            self.__cipher = None
            self._canceled = False
        except Exception as e:
            # print(e)
            self.__status__percentage.set(e)

        self.unfreeze_controls()

    def file_decrypt_cb(self):
        self.freeze_controls()

        try:
            self.__cipher = AEShandler(
                self.__secret__key.get(),
                self.__file__path.get(),
                0
            )
            for percentage in self.__cipher.decrypt_file():
                if self._canceled:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self.__status__percentage.set(percentage)
                self.status_percentage_label.update()
            self.__status__percentage.set("File Decrypted!")
            if self._canceled:
                self.__cipher.abort()
                self.__status__percentage.set("Cancelled!")
            self.__cipher = None
            self._canceled = False
        except Exception as e:
            # print(e)
            self.__status__percentage.set(e)
        
        self.unfreeze_controls()

    def reset_callback(self):
        self.__cipher = None
        self.__file__path.set("")
        self.__secret__key.set("")
        self.__status__percentage.set("******")
    
    def cancel_callback(self):
        self._canceled = True

if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()