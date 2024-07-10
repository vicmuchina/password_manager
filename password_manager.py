from cryptography.fernet import Fernet 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64
from cryptography.fernet import InvalidToken

class SaltManager(object):
    def __init__(self, generate_salt, path='.salt'):
        self.generate_salt = generate_salt
        self.path = path

    def get(self):
        if not os.path.exists(self.path) or self.generate_salt:
            return self._generate_and_store()
        return self._read()

    def _generate_and_store(self):
        salt = os.urandom(16)
        with open(self.path, 'wb') as f:
            f.write(salt)
        return salt

    def _read(self):
        with open(self.path, 'rb') as f:
            return f.read()

def derive_key(passphrase, generate_salt=False):
    salt = SaltManager(generate_salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.get(),
        iterations=1000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase))

from cryptography.fernet import InvalidToken

def view():
    passphrase = input("What is the masterKey: ").encode()
    key = derive_key(passphrase)
    f = Fernet(key)
    try:
        with open("passwords.txt", "r") as file:
            for line in file.readlines():
                data = line.rstrip()
                parts = data.split("|")
                if len(parts) == 3:
                    website, username, password = parts
                    try:
                        decrypted_password = f.decrypt(password.encode()).decode()
                        print("website: " + website + " username: " + username + ", password: " + decrypted_password)
                    except InvalidToken:
                        print("Error: Invalid master key provided.")
                else:
                    print("Error: Incorrect data format in passwords.txt")
    except FileNotFoundError:
        print("No passwords stored yet.")

        
def add():
    passphrase = input("What is the masterKey: ").encode()
    f = Fernet(derive_key(passphrase))
    website = input("Name of the website? ")
    username = input("What is the username? ")
    password = input("What is the password? ")

    with open("passwords.txt", "a") as file:
        file.write(website+"|"+ username + "|" + f.encrypt(password.encode()).decode() + "\n")

while True:
    options = input("Do you want to 1.view or 2.add a password? or 3.quit: ").lower()
    if options == "quit":
        quit()
    elif options == "view":
        view()
    elif options == "add":
        add()
    else:
        print("Invalid input")