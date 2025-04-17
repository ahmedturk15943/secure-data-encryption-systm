import streamlit as st
import base64
import hashlib
import os
from cryptography.fernet import Fernet  # <-- Ye line error de rahi thi

# Password to Key Conversion
def get_key(password):
    salt = b'ahmed_secure_salt'  # Same salt for consistency
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(key)

# App UI
st.title("🔐 Ahmed's Encryption Vault")
st.write("100% Offline - No Data Leaves Your Computer")

# Password Input
pwd = st.text_input("Set Master Key:", type="password")
if not pwd:
    st.stop()

# Operations
tab1, tab2 = st.tabs(["🔒 Encrypt", "🔓 Decrypt"])

with tab1:
    plain_text = st.text_area("Message to Encrypt:")
    if st.button("Lock Message"):
        try:
            f = Fernet(get_key(pwd))
            cipher_text = f.encrypt(plain_text.encode())
            st.code(cipher_text.decode())
        except Exception as e:
            st.error(f"Error: {str(e)}")

with tab2:
    cipher_text = st.text_area("Encrypted Message:")
    if st.button("Unlock Message"):
        try:
            f = Fernet(get_key(pwd))
            decrypted = f.decrypt(cipher_text.encode())
            st.success(decrypted.decode())
        except:
            st.error("❌ Wrong Key or Corrupted Message!")

# Footer
st.divider()
st.caption("Developed by Ahmed © 2023")
