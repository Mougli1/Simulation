#code fonctionnel

from cryptography.fernet import Fernet

def generate_key():
    """
    Génère une clé secrète pour le chiffrement.
    """
    return Fernet.generate_key()

def encrypt_message(message, key):
    """
    Chiffre un message avec une clé donnée.
    """
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    """
    Déchiffre un message avec une clé donnée.
    """
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

def main():
    key = generate_key()
    print(f"Clé générée : {key.decode()}")

    message = input("Entrez un message à chiffrer: ")
    encrypted = encrypt_message(message, key)
    print(f"Message chiffré: {encrypted.decode()}")

    decrypted = decrypt_message(encrypted, key)
    print(f"Message déchiffré: {decrypted}")

if __name__ == "__main__":
    main()
