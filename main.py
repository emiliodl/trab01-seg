from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import glob
import getpass

KEY_DIR = "chaves/"  # Diretório para armazenar chaves

def ensure_key_directory():
    """
    Verifica se o diretório de chaves existe, cria se não existir.
    """
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
        print(f"Diretório {KEY_DIR} criado.")

def generate_keys():
    """
    Gera um par de chaves privada e pública.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename="private_key.pem", password="emilianoewladimir"):
    """
    Salva a chave privada em um arquivo, com a opção de adicionar uma senha para encriptação.
    """
    ensure_key_directory()
    encryption = serialization.BestAvailableEncryption(password.encode())    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    with open(os.path.join(KEY_DIR, filename), 'wb') as f:
        f.write(pem)
        print(f"Chave privada salva como {filename}.")

def save_public_key(public_key, filename="public_key.pem"):
    """
    Salva a chave pública em um arquivo.
    """
    ensure_key_directory()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(KEY_DIR, filename), 'wb') as f:
        f.write(pem)
        print(f"Chave pública salva como {filename}.")

def load_private_key(filename="private_key.pem", password=None):
    """
    Carrega uma chave privada de um arquivo, solicitando uma senha se necessário.
    (Modificado temporariamente para usar input() para compatibilidade)
    """
    if password is None:
        password = input("Digite a senha para desbloquear a chave privada: ")  # Temporário para desenvolvimento

    try:
        with open(os.path.join(KEY_DIR, filename), 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode(),
                backend=default_backend()
            )
        print("Chave privada carregada com sucesso.")
        return private_key
    except Exception as e:
        print(f"Erro ao carregar a chave privada: {e}")
        return None


def load_public_key(filename="public_key.pem"):
    """
    Carrega uma chave pública de um arquivo.
    """
    try:
        with open(os.path.join(KEY_DIR, filename), 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"Erro ao carregar a chave pública: {e}")
        return None

def encrypt_file(input_filename, output_filename, public_key):
    """
    Criptografa um arquivo usando a chave pública RSA.
    """
    try:
        with open(input_filename, 'rb') as f:
            plaintext = f.read()

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_filename, 'wb') as f:
            f.write(ciphertext)
        print(f"Arquivo criptografado salvo como {output_filename}.")
    except Exception as e:
        print(f"Erro ao criptografar o arquivo: {e}")

def decrypt_file(input_filename, output_filename, private_key, password=None):
    """
    Descriptografa um arquivo usando a chave privada RSA.
    """
    try:
        with open(input_filename, 'rb') as f:
            ciphertext = f.read()

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_filename, 'wb') as f:
            f.write(plaintext)
        print(f"Arquivo descriptografado salvo como {output_filename}.")
    except Exception as e:
        print(f"Erro ao descriptografar o arquivo: {e}")

def get_user_input_and_save(filename):
    """
    Solicita ao usuário o texto em claro e salva em um arquivo.
    """
    user_input = input("Digite o texto que deseja criptografar: ")
    with open(filename, 'w') as file:
        file.write(user_input)
    print(f"Texto salvo em {filename}.")

def main():
    # Gera chaves se necessário
    if not os.listdir(KEY_DIR):
        private_key, public_key = generate_keys()
        save_private_key(private_key)
        save_public_key(public_key)
    else:
        public_key = load_public_key()
        private_key = load_private_key()  # Removida a senha codificada

    plaintext_filename = 'plaintext.txt'
    encrypted_filename = 'encrypted.txt'
    decrypted_filename = 'decrypted.txt'

    get_user_input_and_save(plaintext_filename)
    encrypt_file(plaintext_filename, encrypted_filename, public_key)
    decrypt_file(encrypted_filename, decrypted_filename, private_key)  # Removida a senha codificada

if __name__ == "__main__":
    main()
