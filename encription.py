import os
import json
import random
import base64
import hashlib
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
from faker import Faker
import re
from pathlib import Path

# TODO:
# ->  see where to store the key, OR have a diff key for every user
# //->  DONE:some validation on the user input? ( see that username is unique for each user)
# ->  maybe mimic an attack
# ->  see another option for the menu cause now there are a lot of prints


key = "StrongEncryptionKey"
faker = Faker()
file_path = "user_data.json"


def validate_username(username):
    existing_usernames = get_usernames_from_json()
    # print("THE LIST WITH ALL USERNAMES")
    # print(existing_usernames)
    if (len(existing_usernames) > 0):
        if username in existing_usernames:
            return False
    return True


def validate_name(name):
    if re.fullmatch(r"[a-zA-Z]+", name):
        return True
    print("Invalid name. Only letters are allowed.")
    return False


def validate_age(age):
    try:
        age = int(age)
        if age > 0:
            return True
        else:
            print("Invalid age. Age must be greater than 0.")
            return False
    except ValueError:
        print("Invalid age. Age must be an integer.")
        return False


def validate_password(password):
    """
    5 characters, a digit and a special character
    """
    if len(password) < 5:
        print("Invalid password. Password must be at least 5 characters long.")
        return False

    if not re.search(r"\d", password):
        print("Invalid password. Password must contain at least one digit.")
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Invalid password. Password must contain at least one special character.")
        return False

    return True


def validate_user_data(username, name, age, password):
    is_name_valid = validate_name(name)
    is_age_valid = validate_age(age)
    is_username_valid = validate_username(username)
    is_password_valid = validate_password(password)

    if (is_name_valid and is_age_valid and is_username_valid and is_password_valid):
        print("All data provided is valid, creating user")
        return True
    else:
        print("Some invalid data, cannot create user")
        return False


def read_json_file(file_path):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error: File '{file_path}' contains invalid JSON.")
        return None


def get_usernames_from_json():
    usernames = []
    file_path_path = Path(file_path)
    if (file_path_path.is_file()):
        data = read_json_file(file_path)
        for user in data:
            usernames.append(user.get("username"))

    return usernames


# Function to write to a JSON file
def write_json_file(file_path, newdata):
    try:
        # Load existing data
        with open(file_path, 'r') as file:
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                existing_data = []  # If the file is empty, initialize as an empty list
    except FileNotFoundError:
        existing_data = []  # If the file doesn't exist, initialize as an empty list

    # Check if existing data is a list; otherwise, raise an error
    if isinstance(existing_data, list):
        # Append new data to the list
        existing_data.append(newdata)
    elif isinstance(existing_data, dict):
        # For dictionaries, merge the new data
        existing_data.update(newdata)
    else:
        raise ValueError("The JSON file must contain either a list or a dictionary.")

    # Write the updated data back to the file
    with open(file_path, 'w') as file:
        json.dump(existing_data, file, indent=4)
    print("Data has been appended successfully.")


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


# XOR Encrypt function
def xor_encrypt(plaintext, key):
    key_len = len(key)
    encrypted = ''.join(
        format(ord(char) ^ ord(key[i % key_len]), '08b') for i, char in enumerate(plaintext)
    )
    return encrypted


# XOR Decrypt function
def xor_decrypt(binary_data, key):
    key_len = len(key)
    decrypted = ''.join(
        chr(int(binary_data[i:i + 8], 2) ^ ord(key[i // 8 % key_len])) for i in range(0, len(binary_data), 8)
    )
    return decrypted


# Password encryption function
def encrypt_password(password, key):
    hashed_key = hash_key(key)[:16]  # Truncate hashed key to 16 characters
    encrypted_password = xor_encrypt(password, hashed_key)
    return encrypted_password


# Password decryption function
def decrypt_password(encrypted_password, key):
    hashed_key = hash_key(key)[:16]  # Truncate hashed key to 16 characters
    decrypted_password = xor_decrypt(encrypted_password, hashed_key)
    return decrypted_password


def retrieve_user_data(file_path, username, key):
    data = read_json_file(file_path)

    # Search for the user by username
    for user in data:
        if user["username"] == username:
            try:
                # Decrypt the user's password
                decrypted_password = decrypt_password(user["password"], key)
                user[
                    "password"] = decrypted_password  # Replace the encrypted password with the decrypted one and same for the honey ones
                decrypted_honey_passwords = []
                for encrypted_honey_password in user["honey_passwords"]:
                    decrypted_honey_password = decrypt_password(encrypted_honey_password, key)
                    decrypted_honey_passwords.append(decrypted_honey_password)

                user["honey_passwords"] = decrypted_honey_passwords
                return user  # Return the complete user data
            except ValueError:
                print("Error: Unable to decrypt the password. Invalid key.")
                return None

    print(f"Error: No user found with username '{username}'.")
    return None


def create_user_data_for_json(name, username, age, password):
    honey_words = generate_similar_passwords(password)
    honey_words.append(password)
    encrypted_password = encrypt_password(password, key)
    encrypted_honey_words = []

    for honey_word in honey_words:
        encrypted_hw = encrypt_password(honey_word, key)
        encrypted_honey_words.append(encrypted_hw)

    random.shuffle(encrypted_honey_words)
    user_data = {
        "name": name,
        "age": age,
        "username": username,
        "password": encrypted_password,
        "honey_passwords": encrypted_honey_words
    }
    return user_data


def generate_similar_passwords(real_password, num_variations=5):
    similar_passwords = set()

    while len(similar_passwords) < num_variations:
        variation = list(real_password)
        choice = random.choice(["swap", "replace", "add", "remove"])
        if choice == "swap" and len(real_password) > 1:
            i = random.randint(0, len(real_password) - 2)
            variation[i], variation[i + 1] = variation[i + 1], variation[i]
        elif choice == "replace" and len(real_password) > 0:
            i = random.randint(0, len(real_password) - 1)
            variation[i] = random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        elif choice == "add":
            variation.insert(random.randint(0, len(real_password)), random.choice("0123456789"))
        elif choice == "remove" and len(real_password) > 1:
            del variation[random.randint(0, len(real_password) - 1)]

        similar_passwords.add("".join(variation))

    return list(similar_passwords)


def print_user_data(user_data, show_honey_passwords=False):
    if not user_data:
        print("No user data to display.")
        return

    print("User Information:")
    print(f"Name       : {user_data.get('name', 'N/A')}")
    print(f"Age        : {user_data.get('age', 'N/A')}")
    print(f"Username   : {user_data.get('username', 'N/A')}")
    print(f"Password   : {user_data.get('password', 'N/A')}")  # Decrypted password

    if show_honey_passwords:  # Decrypted honey passwords
        print("\nHoney Passwords (Fake Passwords):")
        for i, honey_password in enumerate(user_data.get("honey_passwords", []), start=1):
            print(f"  Fake Password {i}: {honey_password}")

    print("\n--- End of User Information ---")


def generate_fake_data():
    return {
        "name": faker.name(),
        "age": faker.random_int(min=18, max=80),
        "username": faker.user_name(),
        "password": faker.password(length=10),
        "honey_passwords": [faker.password(length=10) for _ in range(5)],
    }


def ui():

    while True:
        user_choice = input("1. I want to register\n2. I want to login \n3. I want to exit \n")
        if user_choice == "3":
            break
        elif user_choice == "2":
            username = input("Username: ")
            data = retrieve_user_data(file_path, username, key)
            if data is not None:
                print("We will give you some passwords, please enter your password from the ones presented above.\n")

                questionable_password = input("Your choice:   ")
                if questionable_password == data.get("password"):
                    print_user_data(data, True)
                else:
                    if questionable_password in data.get("honey_passwords"):
                        fake_data = generate_fake_data()
                        print_user_data(fake_data)
                    else:
                        print("The password you entered is incorrect.")
            else:
                print("Try again.")
        elif user_choice == "1":
            name = input("enter your name:   ")
            age = input("enter your age:    ")
            username = input("enter your username:     ")
            password = input("enter your password:    ")
            is_user_data_valid = validate_user_data(username, name, age, password)
            if not is_user_data_valid:
                continue

            user_data = create_user_data_for_json(name, username, age, password)
            write_json_file(file_path, user_data)
            print(f"User data saved successfully: {user_data}")
        else:
            print("Invalid choice.")
