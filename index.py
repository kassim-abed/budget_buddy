import customtkinter as ctk
import os
import re
import bcrypt

# Configure the appearance
ctk.set_appearance_mode("dark")

# Create the main window
root = ctk.CTk()
root.title("Budget Buddy")
root.geometry("800x600")

# Add a label
label = ctk.CTkLabel(root, text="Hello")
label.pack(padx=20, pady=20)

# Add an entry widget
name_entry = ctk.CTkEntry(root, placeholder_text="Enter your name")
name_entry.pack(padx=20, pady=10)
password_entry = ctk.CTkEntry(root, placeholder_text="Enter your password", show="*")
password_entry.pack(padx=20, pady=10)

# Function to validate password
def validate_password(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one digit."
    if not re.search(r'[@$!%*?&#.]', password):
        return "Password must contain at least one special character."
    return "Valid"

# Function to hash the password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Function to execute when the button is clicked
def execute_action():
    input_name = name_entry.get()
    input_password = password_entry.get()
    validation = validate_password(input_password)
    
    if validation == "Valid":
        hashed_password = hash_password(input_password)
        print(f"User: {input_name}")
        print("Hashed Password:", hashed_password)
    else:
        print(validation)

# Add a button
button = ctk.CTkButton(root, text="Connexion", command=execute_action)
button.pack(padx=20, pady=10)

# Function to open the sign-up page if the user doesn't have an account
def open_signup():
    # Create a new top-level window for registration
    signup_window = ctk.CTkToplevel(root)
    signup_window.title("Register Account")
    signup_window.geometry("400x300")
    
    # Add a simple label to the sign-up page
    signup_label = ctk.CTkLabel(signup_window, text="Registration Page")
    signup_label.pack(padx=20, pady=20)
    # Add registration fields
    reg_name = ctk.CTkEntry(signup_window, placeholder_text="Enter your name")
    reg_name.pack(padx=20, pady=10)
    reg_password = ctk.CTkEntry(signup_window, placeholder_text="Enter your password", show="*")
    reg_password.pack(padx=20, pady=10)
    
    def register_user():
        reg_input_name = reg_name.get()
        reg_input_password = reg_password.get()
        reg_validation = validate_password(reg_input_password)
        
        if reg_validation == "Valid":
            hashed_reg_password = hash_password(reg_input_password)
            print(f"Registered User: {reg_input_name}")
            print("Hashed Password:", hashed_reg_password)
        else:
            print(reg_validation)
    
    # Add a registration button
    reg_button = ctk.CTkButton(signup_window, text="Register", command=register_user)
    reg_button.pack(padx=20, pady=10)

# Add a "Register" button acting like a link
signup_button = ctk.CTkButton(
    root,
    text="Don't have an account? Register here",
    command=open_signup,
    fg_color="transparent"
)
signup_button.pack(padx=20, pady=10)

root.mainloop()
