import streamlit as st
from cryptography.fernet import Fernet
import base64, hashlib, os

def make_key(password):
    salt = b'my_special_salt'  # Change this to anything!
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000  # Standard iteration count
    )
    return base64.urlsafe_b64encode(key)

st.set_page_config(
    page_title="My Secret Vault",
    page_icon="🔏",
    layout="centered"
)

st.title("🔐 Private Message Vault")
st.write("Works 100% offline - No data leaves your computer")

pwd = st.text_input("Your secret key:", type="password")
if not pwd or len(pwd) < 4:
    st.error("⚠️ Key must be 4+ characters")
    st.stop()

enc_tab, dec_tab = st.tabs(["Lock 🔒", "Unlock 🔓"])

with enc_tab:
    msg = st.text_area("Message to lock:")
    if st.button("Encrypt"):
        cipher = Fernet(make_key(pwd))
        locked = cipher.encrypt(msg.encode())
        st.code(locked.decode(), language="text")
        
with dec_tab:
    locked_msg = st.text_area("Paste locked message:")
    if st.button("Decrypt"):
        try:
            cipher = Fernet(make_key(pwd))
            unlocked = cipher.decrypt(locked_msg.encode())
            st.success(unlocked.decode())
        except:
            st.error("❌ Wrong key or broken message!")

# Footer
st.divider()
st.caption("Developed with Python 🐍 by Ahmed Raza")
