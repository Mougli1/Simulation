#code fonctionnel

import random
import tkinter as tk
from tkinter import font

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
    return ((e, n), (d, n))

def encrypt(message, public_key):
    e, n = public_key
    message = [pow(ord(char), e, n) for char in message]
    return message

def decrypt(message, private_key):
    d, n = private_key
    message = ''.join([chr(pow(char, d, n)) for char in message])
    return message

def main():
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

    root = tk.Tk()
    root.title("RSA Encryption/Decryption")
    root.configure(bg="#333333")

    customFont = font.Font(family="Helvetica", size=12)

    lbl_input = tk.Label(root, text="Enter Message:", bg="#333333", fg="#ffffff", font=customFont)
    lbl_input.pack(pady=10)

    txt_input = tk.Text(root, height=5, width=40, font=customFont)
    txt_input.pack(padx=10, pady=10)

    btn_encrypt = tk.Button(root, text="Encrypt", command=encrypt_message, font=customFont, bg="#4CAF50", fg="white")
    btn_encrypt.pack(pady=5)

    lbl_encrypted = tk.Label(root, text="Encrypted Message:", bg="#333333", fg="#ffffff", font=customFont)
    lbl_encrypted.pack(pady=10)

    txt_encrypted = tk.Text(root, height=5, width=40, font=customFont)
    txt_encrypted.pack(padx=10, pady=10)

    btn_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message, font=customFont, bg="#008CBA", fg="white")
    btn_decrypt.pack(pady=5)

    lbl_decrypted = tk.Label(root, text="Decrypted Message:", bg="#333333", fg="#ffffff", font=customFont)
    lbl_decrypted.pack(pady=10)

    txt_decrypted = tk.Text(root, height=5, width=40, font=customFont)
    txt_decrypted.pack(padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    publicKey, privateKey = generate_keys()
    main()
