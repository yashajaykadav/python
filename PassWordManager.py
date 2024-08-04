from cryptography.fernet import Fernet
import os
import json

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("Key file not found. Generating a new key.")
        generate_key()
        return open("secret.key", "rb").read()

def encrypt_message(message: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_message).decode()
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

def save_password(website: str, username: str, password: str, key: bytes):
    encrypted_password = encrypt_message(password, key)
    password_data = {
        "website": website,
        "username": username,
        "password": encrypted_password.decode()
    }
    if not os.path.exists("passwords.json"):
        with open("passwords.json", "w") as file:
            json.dump([], file)
    
    with open("passwords.json", "r+") as file:
        data = json.load(file)
        data.append(password_data)
        file.seek(0)
        json.dump(data, file, indent=4)

def retrieve_passwords(key: bytes):
    if not os.path.exists("passwords.json"):
        print("No passwords saved yet.")
        return

    with open("passwords.json", "r") as file:
        data = json.load(file)
        for entry in data:
            website = entry["website"]
            username = entry["username"]
            password = decrypt_message(entry["password"].encode(), key)
            if password is not None:
                print(f"Website: {website}, Username: {username}, Password: {password}")
            else:
                print(f"Website: {website}, Username: {username}, Password: [Decryption Failed]")

def main():
    key = load_key()

    while True:
        print("\nPassword Manager")
        print("1. Save a new password")
        print("2. Retrieve saved passwords")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            website = input("Enter the website: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            save_password(website, username, password, key)
        elif choice == "2":
            retrieve_passwords(key)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
