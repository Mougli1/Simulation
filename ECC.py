#code fonctionnel extrêmement complexe

import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def generate_keys():
    # Générer une clé privée pour l'utilisateur
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("ecc_private_key.pem", "wb") as file_out:
        file_out.write(pem_private)

    # Générer une clé publique pour l'utilisateur
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("ecc_public_key.pem", "wb") as file_out:
        file_out.write(pem_public)

def load_private_key():
    with open("ecc_private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_peer_public_key():
    with open("ecc_public_key.pem", "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

def derive_key():
    private_key = load_private_key()
    peer_public_key = load_peer_public_key()

    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

def encrypt_message():
    message = message_entry.get()
    if not message:
        messagebox.showerror("Erreur", "Le message est requis")
        return

    derived_key = derive_key()
    iv = os.urandom(16)  # Vecteur d'initialisation

    # Chiffrement du message
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_message_hex = encrypted_message.hex()
    iv_hex = iv.hex()

    result_label.config(text=f"Message chiffré: {encrypted_message_hex}")
    encrypted_entry.delete(0, tk.END)
    encrypted_entry.insert(0, f"{iv_hex}:{encrypted_message_hex}")

def decrypt_message():
    encrypted_data = encrypted_entry.get()
    if not encrypted_data:
        messagebox.showerror("Erreur", "Le message chiffré est requis")
        return

    iv_hex, encrypted_message_hex = encrypted_data.split(':')
    iv = bytes.fromhex(iv_hex)
    encrypted_message = bytes.fromhex(encrypted_message_hex)

    derived_key = derive_key()

    # Déchiffrement du message
    try:
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

        result_label.config(text=f"Message déchiffré: {decrypted_message.decode()}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Déchiffrement échoué: {str(e)}")

root = tk.Tk()
root.title("Application de Cryptographie ECC")

generate_keys_button = tk.Button(root, text="Générer des clés ECC", command=generate_keys)
generate_keys_button.pack()

tk.Label(root, text="Message à chiffrer:").pack()
message_entry = tk.Entry(root, width=50)
message_entry.pack()

encrypt_button = tk.Button(root, text="Chiffrer", command=encrypt_message)
encrypt_button.pack()

tk.Label(root, text="Message chiffré à déchiffrer:").pack()
encrypted_entry = tk.Entry(root, width=50)
encrypted_entry.pack()

decrypt_button = tk.Button(root, text="Déchiffrer", command=decrypt_message)
decrypt_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()
