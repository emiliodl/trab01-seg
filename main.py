from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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

def save_private_key(private_key, filename="private_key.pem", password=None):
    """
    Salva a chave privada em um arquivo, com a opção de adicionar uma senha para encriptação.
    """
    if password is not None:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename="public_key.pem"):
    """
    Salva a chave pública em um arquivo.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename="private_key.pem", password=None):
    """
    Carrega uma chave privada de um arquivo, com a opção de usar uma senha se a chave foi encriptada.
    """
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    return private_key

def load_public_key(filename="public_key.pem"):
    """
    Carrega uma chave pública de um arquivo.
    """
    with open(filename, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# Exemplo de uso das funções
private_key, public_key = generate_keys()
save_private_key(private_key, password="senha_segura")  # Opção com senha
save_public_key(public_key)

loaded_private_key = load_private_key(password="senha_segura")
loaded_public_key = load_public_key()
