import numpy as np
from scipy.linalg import hadamard

def generate_goppa_keypair(n, m):
    """
    Generate a key pair for a simplified Goppa code-based cryptosystem.

    :param n: Length of the code (number of columns in the generator matrix)
    :param m: Number of message bits (number of rows in the generator matrix)
    :return: A tuple of (public_key, private_key)
    """

    # Ensure m is less than n
    if m >= n:
        raise ValueError("m must be less than n for the code to work.")

    # Generate a random binary matrix for G
    G = np.random.randint(0, 2, (m, n))

    # Generate a random permutation matrix P
    P = np.eye(n)
    np.random.shuffle(P)

    # The public key is the product G*P
    public_key = np.dot(G, P) % 2

    # The private key is (G, P)
    private_key = (G, P)

    return public_key, private_key

# Example parameters
n = 16  # Length of the code
m = 8   # Number of message bits

public_key, private_key = generate_goppa_keypair(n, m)
public_key, private_key

def encrypt_message(message, public_key):
    """
    Encrypt a message using the public key.

    :param message: A binary array representing the message
    :param public_key: The public key matrix
    :return: The encrypted message
    """
    if len(message) != public_key.shape[0]:
        raise ValueError("The length of the message must be equal to the number of rows in the public key.")

    # Encrypt the message by multiplying with the public key
    encrypted_message = np.dot(message, public_key) % 2
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    """
    Decrypt an encrypted message using the private key.

    :param encrypted_message: The encrypted message
    :param private_key: The private key tuple (G, P)
    :return: The decrypted message
    """
    G, P = private_key

    # Inverse the permutation matrix P
    P_inv = np.linalg.inv(P)

    # Decrypt the message
    decrypted_message = np.dot(encrypted_message, P_inv) % 2

    # Attempt to decode the message (this step is simplified)
    # In a real scenario, more complex error-correction and decoding would be required
    decoded_message = np.dot(decrypted_message, np.linalg.pinv(G).round()) % 2

    return decoded_message.round().astype(int)

# Example of encryption and decryption
example_message = np.random.randint(0, 2, m)  # Generate a random message
print("Original Message:", example_message)

encrypted_message = encrypt_message(example_message, public_key)
print("Encrypted Message:", encrypted_message)

decrypted_message = decrypt_message(encrypted_message, private_key)
print("Decrypted Message:", decrypted_message)
