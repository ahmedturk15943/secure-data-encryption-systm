# import streamlit as st
# import base64
# import hashlib
# import os
# from cryptography.fernet import Fernet  # <-- Ye line error de rahi thi

# # Password to Key Conversion
# def get_key(password):
#     salt = b'ahmed_secure_salt'  # Same salt for consistency
#     key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
#     return base64.urlsafe_b64encode(key)

# # App UI
# st.title("🔐 Ahmed's Encryption Vault")
# st.write("100% Offline - No Data Leaves Your Computer")

# # Password Input
# pwd = st.text_input("Set Master Key:", type="password")
# if not pwd:
#     st.stop()

# # Operations
# tab1, tab2 = st.tabs(["🔒 Encrypt", "🔓 Decrypt"])

# with tab1:
#     plain_text = st.text_area("Message to Encrypt:")
#     if st.button("Lock Message"):
#         try:
#             f = Fernet(get_key(pwd))
#             cipher_text = f.encrypt(plain_text.encode())
#             st.code(cipher_text.decode())
#         except Exception as e:
#             st.error(f"Error: {str(e)}")

# with tab2:
#     cipher_text = st.text_area("Encrypted Message:")
#     if st.button("Unlock Message"):
#         try:
#             f = Fernet(get_key(pwd))
#             decrypted = f.decrypt(cipher_text.encode())
#             st.success(decrypted.decode())
#         except:
#             st.error("❌ Wrong Key or Corrupted Message!")

# # Footer
# st.divider()
# st.caption("Developed by Ahmed © 2023")




























# 🔐 Ahmed's 100% Working Encryption Vault
import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

# ----- Constants -----
SALT = b'ahmed_secure_salt_123'  # Never change this!
ITERATIONS = 100_000

# ----- Key Generation -----
def make_key(password):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'), 
        SALT,
        ITERATIONS
    )
    return base64.urlsafe_b64encode(key)

# ----- App UI -----
st.set_page_config(
    page_title="Ahmed's Vault",
    page_icon="🔒",
    layout="centered"
)

st.title("🔐 Ahmed's Secure Vault")
st.caption("100% Offline - No Data Leaves Your Computer")

# Password Input
pwd = st.text_input(
    "Your Master Key:", 
    value="ahmed",  # Default for testing
    type="password"
)

if not pwd:
    st.warning("⚠️ Please set a master key")
    st.stop()

# Tabs Interface
enc_tab, dec_tab = st.tabs(["🔒 Encrypt Message", "🔓 Decrypt Message"])

with enc_tab:
    msg = st.text_area("Message to Encrypt:", "hi")  # Default message
    if st.button("Encrypt Now"):
        try:
            cipher = Fernet(make_key(pwd))
            encrypted = cipher.encrypt(msg.encode('utf-8'))
            st.code(encrypted.decode('utf-8'), language="text")
        except Exception as e:
            st.error(f"Error: {str(e)}")

with dec_tab:
    enc_msg = st.text_area("Paste Encrypted Message:")
    if st.button("Decrypt Now"):
        try:
            cipher = Fernet(make_key(pwd))
            decrypted = cipher.decrypt(enc_msg.encode('utf-8'))
            st.success(decrypted.decode('utf-8'))
        except:
            st.error("❌ Wrong Key or Invalid Message!")

# Footer
st.divider()
st.caption("Developed by Ahmed | AR Security © 2023")
