import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet

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
