
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from password_generator import generate_password

def write_key():
    master_pwd = input("Create master password: ").encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pwd))
    with open("key.key", "wb") as key_file:
        key_file.write(key + "\n".encode() + salt)
    return key

def load_key():
    master_pwd = input("Enter master password: ").encode()
    with open("key.key", "rb") as file:
        old_key = file.readline().rstrip()
        salt = file.readline().rstrip()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    new_key = base64.urlsafe_b64encode(kdf.derive(master_pwd))
    return new_key if new_key == old_key else quit("Wrong master password")

key = load_key()
f = Fernet(key)

def view():
    with open("passwords.txt", "r") as file:
        for line in file.readlines():
            data = line.rstrip()
            user, pwd = data.split("|")
            print(f"Account: {user} | Password: {f.decrypt(pwd).decode()}")

def add():
    user = input("Account: ")
    pwd = input("Would you like to use an auto-generated password? (y/n): ")
    if pwd == "n":
        pwd = input("Password: ").encode()
    else:
        pwd = generate_password().encode()

    with open("passwords.txt", "a") as file:
        file.write(user + "|" + f.encrypt(pwd).decode() + "\n")

def delete():
    option = int(input("Which account do you want to delete? (line number): "))
    with open("passwords.txt", "r") as file:
        lines = file.readlines()
    
    with open("passwords.txt", "w") as file:
        for number, line in enumerate(lines):
            if number + 1 not in [option]:
                file.write(line)

while True:
    mode = input(
        "What would you like to do? (view/add/delete), press q to quit: ").lower()
    if mode == "q":
        break

    if mode == "view":
        view()
    elif mode == "add":
        add()
    elif mode == "delete":
        delete()
    else:
        print("Invalid mode.")
        continue
