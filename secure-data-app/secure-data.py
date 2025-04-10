import streamlit as st
import hashlib
import base64
import json
from cryptography.fernet import Fernet
from pathlib import Path

# ---------------------- Configs ----------------------
DATA_FILE = Path("secure_data.json")
SALT = b"secure_salt_123"
MAX_ATTEMPTS = 3
LOGIN_CREDENTIALS = {"admin": "admin123"}  # Simple login

# ---------------------- Utils ----------------------
def get_key_from_passkey(passkey: str) -> bytes:
    kdf = hashlib.pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return base64.urlsafe_b64encode(kdf)

def encrypt_data(plain_text: str, passkey: str) -> str:
    key = get_key_from_passkey(passkey)
    f = Fernet(key)
    return f.encrypt(plain_text.encode()).decode()

def decrypt_data(cipher_text: str, passkey: str) -> str:
    key = get_key_from_passkey(passkey)
    f = Fernet(key)
    return f.decrypt(cipher_text.encode()).decode()

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_data_id(username: str, encrypted_text: str) -> str:
    return hashlib.sha256((username + encrypted_text).encode()).hexdigest()

def load_data():
    if DATA_FILE.exists():
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ---------------------- UI Styling ----------------------
st.markdown(
    """
    <style>
    body {
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
    }
    .stButton>button {
        background: linear-gradient(to right, #43cea2, #185a9d);
        color: white;
        border-radius: 10px;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(to bottom right, #373B44, #4286f4);
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------------------- Session State ----------------------
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0
if 'decrypt_attempts' not in st.session_state:
    st.session_state.decrypt_attempts = 0
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"

# ---------------------- Pages ----------------------
def login_page():
    st.title("🔐 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if LOGIN_CREDENTIALS.get(username) == password:
            st.session_state.is_logged_in = True
            st.session_state.decrypt_attempts = 0
            st.session_state.current_page = "Home"
            st.success("Logged in successfully!")
            st.rerun()
        else:
            st.error("Invalid credentials")

def home_page():
    st.title("🏠 Welcome to the Secure Data Encryption System")
    st.image("https://www.shutterstock.com/image-photo/glowing-digital-lock-surrounded-by-600nw-2517566697.jpg", caption="Securing Your Data With Intelligence")
    st.markdown("""
    ## 🔐 About This App
    This secure data storage system allows users to encrypt and decrypt their sensitive information using modern cryptographic techniques like Fernet encryption and PBKDF2 hashing. 
    Your data is protected, login-secured, and neatly stored in JSON format — no external databases needed!
    """)

    st.markdown("---")
    st.success("Welcome! You're successfully logged in.")

# ---------------------- Insert Data ----------------------
def insert_data_page():
    st.subheader("📝 Store New Encrypted Data")
    username = st.text_input("Username")
    text = st.text_area("Enter Text to Encrypt")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Encrypt & Store"):
        if username and text and passkey:
            data = load_data()
            encrypted = encrypt_data(text, passkey)
            data_id = generate_data_id(username, encrypted)
            data[data_id] = {
                "username": username,
                "encrypted_text": encrypted,
                "passkey": hash_passkey(passkey)
            }
            save_data(data)
            st.success("Data encrypted and stored successfully!")
            st.code(data_id, language="text")
            st.caption("Use this Data ID to retrieve your message.")
            st.button("📋 Copy Data ID", on_click=lambda: st.write("Copied (manually use Ctrl+C)!"))
        else:
            st.warning("Please fill all fields.")

# ---------------------- Retrieve Data ----------------------
def retrieve_data_page():
    st.subheader("🔐 Retrieve Decrypted Data")
    data_id = st.text_input("Enter Data ID")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Retrieve Message"):
        data = load_data()
        if data_id in data:
            stored_hash = data[data_id]["passkey"]
            if hash_passkey(passkey) == stored_hash:
                decrypted = decrypt_data(data[data_id]["encrypted_text"], passkey)
                st.success(f"Decrypted Text: {decrypted}")
                st.session_state.decrypt_attempts = 0
            else:
                st.session_state.decrypt_attempts += 1
                st.error("Incorrect passkey")
                if st.session_state.decrypt_attempts >= MAX_ATTEMPTS:
                    st.session_state.is_logged_in = False
                    st.warning("Too many failed attempts. Redirecting to login...")
                    st.rerun()
        else:
            st.error("Data ID not found")

# ---------------------- Navigation ----------------------
if st.session_state.is_logged_in:
    with st.sidebar:
        st.title("🔍 Navigation")
        page = st.radio("Go to", ["Home", "Insert Data", "Retrieve Data", "Logout"])
        st.session_state.current_page = page

    if st.session_state.current_page == "Home":
        home_page()
    elif st.session_state.current_page == "Insert Data":
        insert_data_page()
    elif st.session_state.current_page == "Retrieve Data":
        retrieve_data_page()
    elif st.session_state.current_page == "Logout":
        st.session_state.is_logged_in = False
        st.session_state.current_page = "Home"
        st.rerun()
else:
    login_page()
