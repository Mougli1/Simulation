#code non fonctionnel

import hashlib
import secrets

class EllipticCurve:
    """
    Classe pour représenter une courbe elliptique.
    Utilisée pour la cryptographie sur les courbes elliptiques.
    """
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p  # La caractéristique du champ fini

    def is_on_curve(self, x, y):
        """
        Vérifie si un point est sur la courbe.
        """
        return (y * y) % self.p == (x * x * x + self.a * x + self.b) % self.p

# Exemple de paramètres pour une courbe elliptique
a = -3
b = 2455155546008943817740293915197451784769108058161191238065
p = 6277101735386680763835789423207666416083908700390324961279

# Initialisation de la courbe
curve = EllipticCurve(a, b, p)

class Point:
    """
    Classe pour représenter un point sur une courbe elliptique.
    """
    def __init__(self, x, y):
        self.x = x
        self.y = y
def inverse_mod(k, p):
    """
    Calcule l'inverse modulaire de k modulo p.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k inversé est négatif, donc on le rend positif
        return p - inverse_mod(-k, p)

    # Algorithme d'Euclide étendu
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p

def point_addition(p1, p2, curve):
    """
    Additionne deux points sur une courbe elliptique.
    """
    if p1.x == p2.x and p1.y == -p2.y:
        return Point(float('inf'), float('inf'))

    if p1.x == p2.x and p1.y == p2.y:
        # Point doubling
        slope = (3 * p1.x * p1.x + curve.a) * pow(2 * p1.y, -1, curve.p)
    else:
        # Point addition
        slope = (p2.y - p1.y) * inverse_mod(p2.x - p1.x, curve.p)
    x3 = (slope * slope - p1.x - p2.x) % curve.p
    y3 = (slope * (p1.x - x3) - p1.y) % curve.p
    return Point(x3, y3)

def multiply_point(point, multiplier, curve):
    """
    Multiplie un point par un entier en utilisant l'algorithme "double and add".
    """
    result = Point(float('inf'), float('inf'))  # Point à l'infini
    addend = point

    while multiplier:
        if multiplier & 1:
            result = point_addition(result, addend, curve)
        addend = point_addition(addend, addend, curve)
        multiplier >>= 1

    return result

# Point de base pour ECC (exemple)
G = Point(602046282375688656758213480587526111916698976636884684818,
         174050332293622031404857552280219410364023488927386650641)

# Génération de la clé privée (nombre aléatoire)
private_key = secrets.randbelow(curve.p)

# Génération de la clé publique en utilisant la multiplication de points
public_key = multiply_point(G, private_key, curve)

# Chiffrement du message (modifié pour utiliser multiply_point)
def encrypt_point(point, public_key, curve):
    k = secrets.randbelow(curve.p)
    c1 = multiply_point(G, k, curve)
    c2 = point_addition(point, multiply_point(public_key, k, curve), curve)
    return c1, c2

# Déchiffrement du message (modifié pour utiliser multiply_point)
def decrypt_point(c1, c2, private_key, curve):
    s = multiply_point(c1, private_key, curve)
    s_inverse = Point(s.x, -s.y % curve.p)
    original_point = point_addition(c2, s_inverse, curve)
    return original_point

# Exemple de message converti en point (simplifié)
message_point = Point(123456, 789012)

# Chiffrement du message
encrypted_point = encrypt_point(message_point, public_key, curve)

# Déchiffrement du message
decrypted_point = decrypt_point(encrypted_point[0], encrypted_point[1], private_key, curve)

# Vérification
print("Message original:", message_point.x, message_point.y)
print("Message déchiffré:", decrypted_point.x, decrypted_point.y)
