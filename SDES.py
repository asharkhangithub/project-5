import streamlit as st
import hashlib
from cryptography.fernet import Fernet


KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None


st.title("🔐 Secure Data Encryption System - All in One")

st.markdown("Use this tool to **securely store and retrieve sensitive information** using a passkey.")

option = st.radio("Select Action:", ["Store Data", "Retrieve Data"])

st.divider()

if option == "Store Data":
    st.subheader("📥 Store Encrypted Data")
    user_data = st.text_area("Enter Data to Store")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored securely.")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill in both fields.")


elif option == "Retrieve Data":
    st.subheader("🔓 Retrieve Encrypted Data")
    
    
    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.error("❌ Too many failed attempts. Reauthorization required.")
        master_pass = st.text_input("Enter Master Password", type="password")
        if st.button("Reauthorize"):
            if master_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.session_state.reauthorized = True
                st.success("✅ Reauthorized successfully.")
            else:
                st.error("Incorrect password.")
    else:
        encrypted_text = st.text_area("Paste Encrypted Text")
        passkey = st.text_input("Enter Passkey", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                result = decrypt_data(encrypted_text, passkey)
                if result:
                    st.success("✅ Decrypted Data:")
                    st.code(result, language="text")
                    st.session_state.reauthorized = False
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                    if attempts_left == 0:
                        st.warning("🔐 Too many failed attempts! Please reauthorize to continue.")
            else:
                st.warning("⚠️ Please enter both fields.")

