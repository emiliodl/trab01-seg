from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os



def load_private_key(path):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Mude para sua senha se sua chave estiver protegida
            backend=default_backend()
        )
    return private_key

def load_public_key(path):
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_message(message, public_key_path):
    public_key = load_public_key(public_key_path)
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(encrypted_message, private_key_path):
    private_key = load_private_key(private_key_path)
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()

def generate_and_save_keys():
    # Geração das chaves
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialização das chaves
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Salvar as chaves em arquivos
    with open("private_key.pem", "wb") as f:
        f.write(pem_private)
    with open("public_key.pem", "wb") as f:
        f.write(pem_public)

generate_and_save_keys()


def save_existing_keys(private_key_text, public_key_text):
    with open("stored_private_key.pem", "w") as f:
        f.write(private_key_text)
    with open("stored_public_key.pem", "w") as f:
        f.write(public_key_text)

private_key_text = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkMqJJLrxXQz9e
r6oMx21wkOgY3P1WFb9dvuBxK+/EUn/Jri7dsLfBv/eS2fUZBsmGyfqwSdJNYwNP
... dFrNqgwYq00n53+f5V6sKNEhKWXN7a0OJm9yrc4YXXuyKKgzXPh5Rff7droj/xUF
-----END PRIVATE KEY-----"""

public_key_text = """-----BEGIN PUBLIC KEY-----
dFrNqgwYq00n53+f5V6sKNEhKWXN7a0OJm9yrc4YXXuyKKgzXPh5Rff7droj/xUF
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkMqJJLrxXQz9e
.... r6oMx21wkOgY3P1WFb9dvuBxK+/EUn/Jri7dsLfBv/eS2fUZBsmGyfqwSdJNYwNP
-----END PUBLIC KEY-----"""

save_existing_keys(private_key_text, public_key_text)

def main():
    while True:
        choice = input("Você gostaria de criptografar (C) ou descriptografar (D) uma mensagem? (C/D): ").upper()
        if choice not in ['C', 'D']:
            print("Escolha inválida, tente novamente.")
            continue

        if choice == 'C':
            message = input("Digite a mensagem que você gostaria de criptografar: ")
            encrypted_msg = encrypt_message(message, "public_key.pem")
            print("Mensagem Criptografada:", encrypted_msg.hex())
        elif choice == 'D':
            hex_data = input("Digite a mensagem criptografada (em hexadecimal): ")
            encrypted_msg = bytes.fromhex(hex_data)
            try:
                decrypted_msg = decrypt_message(encrypted_msg, "private_key.pem")
                print("Mensagem Descriptografada:", decrypted_msg)
            except Exception as e:
                print("Falha ao descriptografar a mensagem:", str(e))

        if input("Deseja continuar? (s/n): ").lower() == 'n':
            break

if _name_ == "_main_":
    main()