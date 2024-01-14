#code fonctionnel extrêmement complexe

import tkinter as tk
from tkinter import messagebox, font
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
# Déclaration des variables globales
message_entry = None
encrypted_entry = None
result_label = None
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


def create_main_window():
    global message_entry, encrypted_entry, result_label

    root = tk.Tk()
    root.title("Application de Cryptographie ECC")

    main_font = font.Font(family="Arial", size=12)

    # Cadre pour les clés
    frame_keys = tk.Frame(root, padx=5, pady=5)
    generate_keys_button = tk.Button(frame_keys, text="Générer des clés ECC", command=generate_keys, font=main_font)
    generate_keys_button.pack(fill=tk.X)
    frame_keys.pack(fill=tk.X)

     # Cadre pour le chiffrement
    frame_encrypt = tk.Frame(root, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Message à chiffrer:", font=main_font).pack(anchor='w')
    message_entry = tk.Entry(frame_encrypt, width=50, font=main_font)
    message_entry.pack(fill=tk.X)
    encrypt_button = tk.Button(frame_encrypt, text="Chiffrer", command=encrypt_message, font=main_font)
    encrypt_button.pack(fill=tk.X)
    frame_encrypt.pack(fill=tk.X)

    # Cadre pour le déchiffrement
    frame_decrypt = tk.Frame(root, padx=5, pady=5)
    tk.Label(frame_decrypt, text="Message chiffré à déchiffrer:", font=main_font).pack(anchor='w')
    encrypted_entry = tk.Entry(frame_decrypt, width=50, font=main_font)
    encrypted_entry.pack(fill=tk.X)
    decrypt_button = tk.Button(frame_decrypt, text="Déchiffrer", command=decrypt_message, font=main_font)
    decrypt_button.pack(fill=tk.X)
    frame_decrypt.pack(fill=tk.X)

    # Résultat
    frame_result = tk.Frame(root, padx=5, pady=5)
    result_label = tk.Label(frame_result, text="", font=main_font)
    result_label.pack()
    frame_result.pack(fill=tk.X)

    return root

root = create_main_window()
root.mainloop()
