import tkinter as tk
from tkinter import messagebox
import json
import os
from pathlib import Path
from encription import (validate_user_data, create_user_data_for_json, write_json_file,
                        retrieve_user_data, encrypt_password, decrypt_password, generate_fake_data, file_path, key,
                        validate_name, validate_age, validate_password, validate_username)

from collections import deque

# Define file path for tracking wrong passwords
WRONG_PASSWORDS_FILE = "wrong_passwords.json"


# Load existing wrong password entries
def load_wrong_passwords():
    if os.path.exists(WRONG_PASSWORDS_FILE):
        with open(WRONG_PASSWORDS_FILE, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}


# Save wrong password entries
def save_wrong_passwords(data):
    with open(WRONG_PASSWORDS_FILE, "w") as file:
        json.dump(data, file, indent=4)


# Function to manage wrong password attempts
def track_wrong_password(password, username):
    wrong_passwords = load_wrong_passwords()
    queue = deque(wrong_passwords.items(), maxlen=5)
    encrypted_password = encrypt_password(password, key)

    if encrypted_password in wrong_passwords:
        return wrong_passwords[encrypted_password]["data"]  # Return existing fake data if password was used before

    fake_data = generate_fake_data()  # Assume this function generates fake user data
    fakee = {}
    fakee["name"] = fake_data["name"]
    fakee["age"] = fake_data["age"]
    queue.append((encrypted_password, {"username": username, "data": fakee}))

    wrong_passwords = dict(queue)
    save_wrong_passwords(wrong_passwords)
    return fake_data


# Load existing users
def load_users():
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return []
    return []


def register(root):
    clear_window(root)

    tk.Label(root, text="Register", font=("Arial", 16)).pack(pady=10)
    tk.Label(root, text="Name:").pack()
    name_entry = tk.Entry(root)
    name_entry.pack()

    tk.Label(root, text="Username:").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password:").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    tk.Label(root, text="Age:").pack()
    age_entry = tk.Entry(root)
    age_entry.pack()

    def submit():
        name = name_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        age = age_entry.get().strip()

        if not validate_name(name):
            messagebox.showerror("Error", "Invalid name. Only letters are allowed.")
            return
        if not validate_username(username):
            messagebox.showerror("Error", "Username already exists. Please try another username.")
        elif not validate_password(password):
            messagebox.showerror("Error", "Invalid password. \n - Password must be at least 5 characters "
                                          "long.\n - Password must contain at least one digit. \n"
                                          " - Password must contain at least one special character.")
            return
        elif not validate_age(age):
            messagebox.showerror("Error", "Invalid age. Age must be grater than 0 and an integer.")
            return
        is_valid = validate_user_data(username, name, age, password)
        if not is_valid:
            messagebox.showerror("Error", "Some invalid data, can not create user.")
            return

        user_data = create_user_data_for_json(name, username, age, password)
        write_json_file(file_path, user_data)
        messagebox.showinfo("Success", "Registration successful!")
        show_main_page(root)

    tk.Button(root, text="Submit", command=submit).pack(pady=10)
    tk.Button(root, text="Back", command=lambda: show_main_page(root)).pack(pady=5)


def login_step1(root):
    """ Step 1: User enters the username """
    clear_window(root)

    tk.Label(root, text="Login", font=("Arial", 16)).pack(pady=10)
    tk.Label(root, text="Username:").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    def validate_username():
        username = username_entry.get().strip()
        user_data = retrieve_user_data(file_path, username, key)

        if not user_data:
            messagebox.showerror("Error", "Invalid username!")
            return

        login_step2(root, username, user_data)

    tk.Button(root, text="Next", command=validate_username).pack(pady=10)
    tk.Button(root, text="Back", command=lambda: show_main_page(root)).pack(pady=5)


def login_step2(root, username, user_data):
    """ Step 2: Show honey passwords & request actual password """
    clear_window(root)

    tk.Label(root, text=f"Welcome {username}, enter your password", font=("Arial", 14)).pack(pady=10)
    tk.Label(root, text="Honey Passwords:").pack()

    honey_passwords = user_data.get("honey_passwords", [])
    for hp in honey_passwords:
        tk.Label(root, text=f"- {hp}").pack()

    tk.Label(root, text="Password:").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    def validate_password():
        password = password_entry.get().strip()
        if password == user_data.get("password"):
            login_success(root, username, user_data)
        elif password in honey_passwords:
            fake_data = track_wrong_password(password, username)
            login_success(root, username, fake_data)
        else:
            messagebox.showerror("Error", "Invalid password.")

    tk.Button(root, text="Submit", command=validate_password).pack(pady=10)

def login_success(root, username, user_data):
    """ Step 3: Show user data upon successful login """
    clear_window(root)

    tk.Label(root, text=f"Welcome, {username}!", font=("Arial", 16), anchor="center").pack(pady=10)
    tk.Label(root, text=f"Name: {user_data.get('name')}").pack()
    tk.Label(root, text=f"Age: {user_data.get('age')}").pack()
    tk.Button(root, text="Logout", command=lambda: show_main_page(root)).pack(pady=10)

def clear_window(root):
    for widget in root.winfo_children():
        widget.destroy()


def show_main_page(root):
    clear_window(root)
    tk.Label(root, text="Login & Register GUI", font=("Arial", 16)).pack(pady=20)
    tk.Button(root, text="Register", command=lambda: register(root), width=20, height=2).pack(pady=10)
    tk.Button(root, text="Login", command=lambda: login_step1(root), width=20, height=2).pack(pady=10)


def gui():
    root = tk.Tk()
    root.title("Login & Register GUI")
    root.geometry("400x300")
    show_main_page(root)
    root.mainloop()