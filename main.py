from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
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
    save_private_key(private_key)
    save_public_key(public_key)
    print("Novo par de chaves gerado e salvo com sucesso.")

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

def load_private_key(filename="private_key.pem", password=None):
    """
    Carrega uma chave privada de um arquivo, solicitando uma senha se necessário.
    Modificado temporariamente para usar input() devido a problemas de ambiente.
    """
    if password is None:
        password = input("Digite a senha para desbloquear a chave privada (temporário): ")  # Usando input temporariamente

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

def encrypt_text_directly(text, output_filename, hex_output_filename, public_key):
    """
    Criptografa texto diretamente usando a chave pública RSA e salva o resultado criptografado.
    Salva também o resultado em formato hexadecimal em um arquivo separado.
    """
    try:
        ciphertext = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Salvar o texto criptografado em um arquivo
        with open(output_filename, 'wb') as f:
            f.write(ciphertext)
        print(f"Texto criptografado salvo como {output_filename}.")

        # Salvar a versão hexadecimal do texto criptografado
        with open(hex_output_filename, 'w') as f:
            f.write(ciphertext.hex())
        print(f"Texto criptografado em hexadecimal salvo como {hex_output_filename}.")
    except Exception as e:
        print(f"Erro ao criptografar o texto: {e}")

def decrypt_text_directly(hex_input, output_filename, private_key):
    """
    Descriptografa texto em formato hexadecimal usando a chave privada RSA.
    """
    try:
        ciphertext = bytes.fromhex(hex_input)

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
        print(f"Texto descriptografado salvo como {output_filename}.")
    except Exception as e:
        print(f"Erro ao descriptografar o texto: {e}")

def menu():
    while True:
        print("\nMenu:")
        print("1. Gerar novo par de chaves")
        print("2. Criptografar texto inserido")
        print("3. Descriptografar texto hexadecimal inserido")
        print("4. Sair")

        choice = input("Escolha uma opção (1-4): ")

        if choice == '1':
            generate_keys()
        elif choice == '2':
            text = input("Digite o texto que deseja criptografar: ")
            encrypted_filename = 'encrypted.txt'
            encrypted_hex_filename = 'encrypted_hex.txt'  # Novo arquivo para salvar o hexadecimal
            public_key = load_public_key()
            if public_key:
                encrypt_text_directly(text, encrypted_filename, encrypted_hex_filename, public_key)
            else:
                print("Falha ao carregar a chave pública.")
        elif choice == '3':
            hex_input = input("Cole o texto criptografado em hexadecimal: ")
            decrypted_filename = 'decrypted.txt'
            private_key = load_private_key()
            if private_key:
                decrypt_text_directly(hex_input, decrypted_filename, private_key)
            else:
                print("Falha ao carregar a chave privada.")
        elif choice == '4':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Por favor, tente novamente.")

def main():
    if not os.listdir(KEY_DIR):
        print("Nenhum par de chaves encontrado. Gerando um novo par...")
        generate_keys()
    menu()

if __name__ == "__main__":
    main()
