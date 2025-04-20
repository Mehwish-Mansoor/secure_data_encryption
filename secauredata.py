import streamlit as st 
import hashlib
import json 
import os
import time
from cryptography.fernet import Fernet 
from base64 import urlsafe_b64encode 
from hashlib import pbkdf2_hmac 

#======= data information of user=============
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

#=========section login detail ==============
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None 
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0  # Fixed typo in failed_attempts
    
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0 
    
#==========if data is load ======
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}  # Fixed indentation and return empty dict if file doesn't exist
    
def save_data(data):
    with open(DATA_FILE, "w") as f:  # Fixed "W" to "w"
        json.dump(data, f)
            
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)
        
def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()  # Fixed function name

# ============cryptography.fernet used =========== 
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None 

# Load stored data
stored_data = load_data()
    
#=========navigation ======= 
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)
    
if choice == "Home":
    st.subheader("Welcome to my Data Encryption System using streamlit")
    st.markdown("This app allows you to securely store and retrieve your data.")
        
# =========user registration ===========
elif choice == "Register":
    st.subheader("®️Register New User") 
    username = st.text_input("Choose Username") 
    password = st.text_input("Choose Password", type="password")
        
    if st.button("Register"):
        if username and password: 
            if username in stored_data:
                st.warning("⚠️User already exists.")
            else:
                stored_data[username] = {  # Fixed dictionary assignment
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✔️User registered successfully!")
        else:
            st.error("Both fields required.")

# =========Login Section ===========
elif choice == "Login":
    st.subheader("🔑 Login")
    
    # Check if user is locked out
    if time.time() - st.session_state.lockout_time < LOCKOUT_DURATION:
        remaining_time = int(LOCKOUT_DURATION - (time.time() - st.session_state.lockout_time))
        st.error(f"Account is locked. Please try again in {remaining_time} seconds.")
    else:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success("✔️ Logged in successfully!")
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time()
                    st.error("Too many failed attempts. Account locked for 60 seconds.")
                else:
                    st.error("Invalid username or password.")

# =========Store Data Section ===========
elif choice == "Store Data":
    if st.session_state.authenticated_user:
        st.subheader("📝 Store Encrypted Data")
        data_key = st.text_input("Data Key/Label")
        data_value = st.text_area("Data Content")
        encryption_key = st.text_input("Encryption Key", type="password")
        
        if st.button("Store Data"):
            if data_key and data_value and encryption_key:
                encrypted_data = encrypt_text(data_value, encryption_key)
                stored_data[st.session_state.authenticated_user]["data"].append({
                    "key": data_key,
                    "value": encrypted_data
                })
                save_data(stored_data)
                st.success("✔️ Data stored successfully!")
            else:
                st.error("All fields are required.")
    else:
        st.warning("Please login first.")

# =========Retrieve Data Section ===========
elif choice == "Retrieve Data":
    if st.session_state.authenticated_user:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data[st.session_state.authenticated_user]["data"]
        
        if user_data:
            data_keys = [item["key"] for item in user_data]
            selected_key = st.selectbox("Select data to retrieve", data_keys)
            decryption_key = st.text_input("Decryption Key", type="password")
            
            if st.button("Retrieve Data"):
                if decryption_key:
                    selected_data = next((item for item in user_data if item["key"] == selected_key), None)
                    if selected_data:
                        decrypted_data = decrypt_text(selected_data["value"], decryption_key)
                        if decrypted_data:
                            st.success("Data retrieved successfully!")
                            st.write("Decrypted Data:", decrypted_data)
                        else:
                            st.error("Invalid decryption key.")
                else:
                    st.error("Please enter decryption key.")
        else:
            st.info("No stored data found.")
    else:
        st.warning("Please login first.")