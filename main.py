import streamlit as st
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

KEY_DIR = "chaves/"

def ensure_key_directory():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
        st.write(f"Diretório {KEY_DIR} criado.")

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    password = st.text_input("Digite uma senha para encriptar a chave privada:", type="password")
    if st.button("Gerar chaves"):
        save_private_key(private_key, password=password)
        save_public_key(public_key)
        st.success("Novo par de chaves gerado e salvo com sucesso.")

def save_private_key(private_key, filename="private_key.pem", password=None):
    ensure_key_directory()
    encryption = serialization.BestAvailableEncryption(password.encode())    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    with open(os.path.join(KEY_DIR, filename), 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename="public_key.pem"):
    ensure_key_directory()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(KEY_DIR, filename), 'wb') as f:
        f.write(pem)

def load_public_key(filename="public_key.pem"):
    try:
        with open(os.path.join(KEY_DIR, filename), 'rb') as f:
            return serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        st.error(f"Erro ao carregar a chave pública: {e}")
        return None

def load_private_key(filename="private_key.pem", password=None):
    try:
        with open(os.path.join(KEY_DIR, filename), 'rb') as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend()
            )
    except Exception as e:
        st.error(f"Erro ao carregar a chave privada: {e}")
        return None

def decrypt_text(ciphertext_hex, private_key):
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = private_key.decrypt(
            ciphertext,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except Exception as e:
        st.error(f"Erro ao descriptografar o texto: {e}")
        return None

# Interface com Streamlit
st.title("Gerenciamento de Chaves RSA")
if st.button("Verificar e criar diretório de chaves"):
    ensure_key_directory()

if st.button("Gerar novo par de chaves"):
    generate_keys()

text = st.text_area("Texto para criptografar:")
if st.button("Criptografar"):
    public_key = load_public_key()
    if public_key:
        ciphertext = public_key.encrypt(
            text.encode(),
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        st.text_area("Texto Criptografado", ciphertext.hex(), height=300)

password = st.text_input("Digite a senha da chave privada para descriptografia:", type="password")
ciphertext_hex = st.text_area("Cole o texto criptografado em hexadecimal aqui:")
if st.button("Descriptografar"):
    private_key = load_private_key(password=password)
    if private_key:
        plaintext = decrypt_text(ciphertext_hex, private_key)
        if plaintext:
            st.text_area("Texto Descriptografado", plaintext, height=300)
