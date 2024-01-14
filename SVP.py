#code presque fonctionnel
import numpy as np

def generate_private_key(size=4):
    """
    Génère une clé privée pour la cryptographie basée sur les réseaux.
    Retourne une matrice carrée aléatoire.
    """
    return np.random.randint(-5, 5, (size, size))

def generate_public_key(private_key):
    """
    Génère une clé publique en ajoutant des erreurs à la clé privée.
    """
    error_matrix = np.random.randint(-1, 2, private_key.shape)
    return private_key + error_matrix

def encrypt(message, public_key):
    """
    Chiffre le message en utilisant la clé publique.
    """
    return np.dot(message, public_key)

def decrypt(ciphertext, private_key):
    """
    Déchiffre le message en utilisant la clé privée.
    """
    inverse_key = np.linalg.inv(private_key)
    return np.round(np.dot(ciphertext, inverse_key)).astype(int)

# Exemple d'utilisation
key_size = 4
private_key = generate_private_key(key_size)
public_key = generate_public_key(private_key)

# Créer un message (vecteur)
message = np.random.randint(0, 10, key_size)

# Chiffrement
encrypted_message = encrypt(message, public_key)

# Déchiffrement
decrypted_message = decrypt(encrypted_message, private_key)

# Afficher les résultats
print("Message original:", message)
print("Message chiffré :", encrypted_message)
print("Message déchiffré:", decrypted_message)
