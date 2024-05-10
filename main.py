from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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
    """
    if password is None:
        # Altere para input() temporariamente se getpass não estiver funcionando
        password = input("Digite a senha para desbloquear a chave privada: ")  # Usar em caso de falha de getpass

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

def list_keys():
    """
    Lista todos os arquivos de chave no diretório de chaves.
    """
    ensure_key_directory()
    files = glob.glob(f"{KEY_DIR}*.pem")
    keys = [os.path.basename(file) for file in files]
    return keys

def search_key(keyword):
    """
    Pesquisa arquivos de chave que contêm a palavra-chave fornecida no nome.
    """
    all_keys = list_keys()
    found_keys = [key for key in all_keys if keyword in key]
    return found_keys

def delete_key(key_name):
    """
    Apaga um arquivo de chave específico, se existir.
    """
    key_path = os.path.join(KEY_DIR, key_name)
    if os.path.exists(key_path):
        os.remove(key_path)
        print(f"Chave {key_name} apagada com sucesso.")
    else:
        print("Chave não encontrada.")

# Exemplo de uso das funções
private_key, public_key = generate_keys()
save_private_key(private_key)  # Salva com a senha especificada
save_public_key(public_key)

loaded_private_key = load_private_key()  # Carrega solicitando a senha
loaded_public_key = load_public_key()
