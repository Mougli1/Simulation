#code non fonctionnel

import random

def is_prime(n):
    """ Vérifie si un nombre est premier. """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_prime_candidate(length):
    """ Génère un nombre impair aléatoire. """
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    """ Génère un nombre premier. """
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    """ Calcule le PGCD de deux nombres. """
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    """ Calcule l'inverse modulaire. """
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    
    if temp_phi == 1:
        return d + phi

def generate_keypair(p, q):
    """ Génère une paire de clés RSA. """
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Les nombres doivent être premiers.')
    elif p == q:
        raise ValueError('p et q ne peuvent pas être égaux')
    # n = pq
    n = p * q

    # Phi est le totient de n
    phi = (p-1) * (q-1)

    # Choisissez un entier e tel que e et phi(n) soient copremiers
    e = random.randrange(1, phi)

    # Utiliser l'algorithme d'Euclide pour vérifier que e et phi(n) sont copremiers
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Utiliser l'extension de l'algorithme d'Euclide pour générer l'inverse privé
    d = multiplicative_inverse(e, phi)
    
    # La paire de clés publique est (e, n) et la clé privée est (d, n)
    return ((e, n), (d, n))

# Exemple d'utilisation
p = generate_prime_number(1024)
q = generate_prime_number(1024)
public, private = generate_keypair(p, q)
public, private
