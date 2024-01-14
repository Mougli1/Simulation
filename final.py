import tkinter as tk
import tkinter as tk
from tkinter import ttk, messagebox, font
import random

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

from ANIMATEDRSA import encrypt, decrypt

def is_prime(n, k=128):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for _ in range(k):
        if not miller_test(d, n):
            return False

    return True

def miller_test(d, n):
    a = 2 + random.randint(1, n - 4)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True

    while d != n - 1:
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

    return False


def generate_prime_number(n):
    while True:
        prime = random.randrange(2**(n-1), 2**n)
        if is_prime(prime):
            return prime

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys():
    p = generate_prime_number(256)
    q = generate_prime_number(256)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return (e, n), (d, n)  # Renvoie un tuple contenant la clé publique (e, n) et la clé privée (d, n)

def rsa_algorithm():
    publicKey, privateKey = generate_keys()

    def encrypt_message():
        user_message = txt_input.get("1.0", "end-1c")
        encrypted_msg = encrypt(user_message, publicKey)
        txt_encrypted.delete("1.0", tk.END)
        txt_encrypted.insert(tk.END, ' '.join(map(str, encrypted_msg)))

    def decrypt_message():
        encrypted_msg = map(int, txt_encrypted.get("1.0", "end-1c").split())
        decrypted_msg = decrypt(encrypted_msg, privateKey)
        txt_decrypted.delete("1.0", tk.END)
        txt_decrypted.insert(tk.END, decrypted_msg)


    rsa_window = tk.Toplevel()
    rsa_window.title("RSA Encryption/Decryption")
    rsa_window.configure(bg="#333333")
    customFont = font.Font(family="Helvetica", size=12)

    lbl_input = tk.Label(rsa_window, text="Enter Message:", bg="#333333", fg="#ffffff", font=customFont)
    lbl_input.pack(pady=10)
    txt_input = tk.Text(rsa_window, height=5, width=40, font=customFont)
    txt_input.pack(padx=10, pady=10)
    btn_encrypt = tk.Button(rsa_window, text="Encrypt", command=encrypt_message, font=customFont, bg="#4CAF50", fg="white")
    btn_encrypt.pack(pady=5)
    lbl_encrypted = tk.Label(rsa_window, text="Encrypted Message:", bg="#333333", fg="#ffffff", font=customFont)
    lbl_encrypted.pack(pady=10)
    txt_encrypted = tk.Text(rsa_window, height=5, width=40, font=customFont)
    txt_encrypted.pack(padx=10, pady=10)
    btn_decrypt = tk.Button(rsa_window, text="Decrypt", command=decrypt_message, font=customFont, bg="#008CBA", fg="white")
    btn_decrypt.pack(pady=5)
    lbl_decrypted = tk.Label(rsa_window, text="Decrypted Message:", bg="#333333", fg="#ffffff", font=customFont)
    lbl_decrypted.pack(pady=10)
    txt_decrypted = tk.Text(rsa_window, height=5, width=40, font=customFont)
    txt_decrypted.pack(padx=10, pady=10)
pass
def ecc_algorithm():
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
pass

def fernet_algorithm():
    def generate_key():
        key = Fernet.generate_key()
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key.decode())

    def encrypt_message():
        key = key_entry.get()
        message = message_entry.get()
        if not key or not message:
            messagebox.showerror("Erreur", "La clé et le message sont requis")
            return
        f = Fernet(key.encode())
        encrypted_message = f.encrypt(message.encode())
        result_label.config(text=f"Message chiffré: {encrypted_message.decode()}")
        encrypted_entry.delete(0, tk.END)
        encrypted_entry.insert(0, encrypted_message.decode())

    def decrypt_message():
        key = key_entry.get()
        encrypted_message = encrypted_entry.get()
        if not key or not encrypted_message:
            messagebox.showerror("Erreur", "La clé et le message chiffré sont requis")
            return
        f = Fernet(key.encode())
        try:
            decrypted_message = f.decrypt(encrypted_message.encode()).decode()
            result_label.config(text=f"Message déchiffré: {decrypted_message}")
        except:
            messagebox.showerror("Erreur", "Déchiffrement échoué. Vérifiez la clé et le message chiffré.")

    # Configuration de l'interface graphique
    root = tk.Tk()
    root.title("Application de Cryptographie")

    tk.Label(root, text="Clé:").pack()
    key_entry = tk.Entry(root, width=50)
    key_entry.pack()
    generate_key_button = tk.Button(root, text="Générer une clé", command=generate_key)
    generate_key_button.pack()

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
    # Intégrer ici le code de l'algorithme Fernet
    pass

def quantum_key_distribution(root):
    def generate_bits_and_bases(length):
        bits = [random.randint(0, 1) for _ in range(length)]
        bases = [random.choice(['rectiligne', 'diagonale']) for _ in range(length)]
        return bits, bases

    def encode_qubits(bits, bases):
        # Simule l'encodage des qubits
        qubits = []
        for bit, base in zip(bits, bases):
            if base == 'rectiligne':
                qubits.append('|0>' if bit == 0 else '|1>')
            else:
                qubits.append('|+>' if bit == 0 else '|->')
        return qubits

    length = 10  # Longueur de la clé
    alice_bits, alice_bases = generate_bits_and_bases(length)
    qubits = encode_qubits(alice_bits, alice_bases)

    def bob_measure_qubits(qubits):
        bob_bases = [random.choice(['rectiligne', 'diagonale']) for _ in qubits]
        return bob_bases

    bob_bases = bob_measure_qubits(qubits)

    def compare_bases(alice_bases, bob_bases):
        matching_indices = []
        for i in range(len(alice_bases)):
            if alice_bases[i] == bob_bases[i]:
                matching_indices.append(i)
        return matching_indices

    matching_indices = compare_bases(alice_bases, bob_bases)

    def generate_key(bits, indices):
        return [bits[i] for i in indices]

    alice_key = generate_key(alice_bits, matching_indices)
    bob_key = generate_key(alice_bits, matching_indices)  # Bob aurait normalement les mêmes bits pour ces indices

    # Vérification de la correspondance des clés
    print("Alice's Key:", alice_key)
    print("Bob's Key  :", bob_key)
    result_window = tk.Toplevel(root)
    result_window.title("Quantum Key Distribution Results")
    tk.Label(result_window, text=f"Alice's Key: {alice_key}").pack()
    tk.Label(result_window, text=f"Bob's Key  : {bob_key}").pack()
pass

def vigenere_cipher(root):
    # code fonctionnel

    def generate_key(message, key):
        key = list(key)
        if len(message) == len(key):
            return key
        else:
            for i in range(len(message) - len(key)):
                key.append(key[i % len(key)])
        return "".join(key)

    def cipher_text(message, key):
        cipher_text = []
        k_index = 0
        for i in range(len(message)):
            if message[i].isalpha():
                shift = ord(key[k_index]) - ord('A')
                base = ord('A') if message[i].isupper() else ord('a')
                cipher_char = chr((ord(message[i]) - base + shift) % 26 + base)
                cipher_text.append(cipher_char)
                k_index = (k_index + 1) % len(key)
            else:
                cipher_text.append(message[i])
        return "".join(cipher_text)

    def original_text(cipher_text, key):
        orig_text = []
        k_index = 0
        for i in range(len(cipher_text)):
            if cipher_text[i].isalpha():
                shift = ord(key[k_index]) - ord('A')
                base = ord('A') if cipher_text[i].isupper() else ord('a')
                original_char = chr((ord(cipher_text[i]) - base - shift) % 26 + base)
                orig_text.append(original_char)
                k_index = (k_index + 1) % len(key)
            else:
                orig_text.append(cipher_text[i])
        return "".join(orig_text)

    # Exemple d'utilisation
    message = "Bonjour, ceci est un message secret!"
    key = "clef"
    key = generate_key(message, key)
    ciphered = cipher_text(message, key)
    deciphered = original_text(ciphered, key)

    print("Message original:", message)
    print("Message chiffré :", ciphered)
    print("Message déchiffré:", deciphered)

    # Interface graphique pour le chiffrement de Vigenère

    vigenere_window = tk.Toplevel(root)
    vigenere_window.title("Vigenère Cipher")
    tk.Label(vigenere_window, text="Enter Message:").pack()
    message_entry = tk.Entry(vigenere_window, width=50)
    message_entry.pack()

    tk.Label(vigenere_window, text="Enter Key:").pack()
    key_entry = tk.Entry(vigenere_window, width=50)
    key_entry.pack()

    result_label = tk.Label(vigenere_window, text="")
    result_label.pack()

    def encrypt_and_decrypt():
        message = message_entry.get()
        key = key_entry.get()
        generated_key = generate_key(message, key)
        encrypted_message = cipher_text(message, generated_key)
        decrypted_message = original_text(encrypted_message, generated_key)
        result_label.config(text=f"Encrypted: {encrypted_message}\nDecrypted: {decrypted_message}")

    encrypt_decrypt_button = tk.Button(vigenere_window, text="Encrypt & Decrypt", command=encrypt_and_decrypt)
    encrypt_decrypt_button.pack()
    # Intégrer ici le code du chiffre de Vigenère
    pass



# Main GUI


def main():
    root = tk.Tk()
    root.title("Application de Cryptographie")

    # Configuration du style
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TCombobox', font=('Helvetica', 12))
    style.configure
    # Suite de la configuration du style
    style.configure('TButton', font=('Helvetica', 12), background='#4CAF50', foreground='white')
    style.configure('TLabel', font=('Helvetica', 12), background='#333333', foreground='#ffffff')

    # Configuration de la fenêtre principale
    root.configure(bg='#333333')
    root.geometry("400x250")  # Taille de la fenêtre

    # Titre
    title = ttk.Label(root, text="Choisissez un Algorithme de Cryptographie", background='#333333',
                      foreground='#ffffff', font=('Helvetica', 16))
    title.pack(pady=20)

    # Sélection de l'algorithme
    algorithm_choice = ttk.Combobox(root,
                                    values=["RSA", "ECC", "Fernet", "Quantum Key Distribution", "Vigenère Cipher"],
                                    state='readonly', font=('Helvetica', 12))
    algorithm_choice.pack(pady=10)

    # Fonction de sélection
    def select_algorithm(event):
        selected_algo = algorithm_choice.get()
        if selected_algo == "RSA":
            rsa_algorithm()
        elif selected_algo == "ECC":
            ecc_algorithm()
        elif selected_algo == "Fernet":
            fernet_algorithm()
        elif selected_algo == "Quantum Key Distribution":
            quantum_key_distribution()
        elif selected_algo == "Vigenère Cipher":
            vigenere_cipher()

    algorithm_choice.bind("<<ComboboxSelected>>", select_algorithm)

    # Bouton pour lancer l'algorithme
    start_button = ttk.Button(root, text="Lancer", command=lambda: select_algorithm(None))
    start_button.pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    main()



















