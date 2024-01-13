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
        slope = (p2.y - p1.y) * pow(p2.x - p1.x, -1, curve.p)

    x3 = (slope * slope - p1.x - p2.x) % curve.p
    y3 = (slope * (p1.x - x3) - p1.y) % curve.p
    return Point(x3, y3)

# Point de base pour ECC (exemple)
G = Point(602046282375688656758213480587526111916698976636884684818,
         174050332293622031404857552280219410364023488927386650641)

# Génération de la clé privée (nombre aléatoire)
private_key = secrets.randbelow(curve.p)

# Génération de la clé publique (multiplication du point de base par la clé privée)
public_key = G
for _ in range(private_key - 1):
    public_key = point_addition(public_key, G, curve)
def encrypt_point(point, public_key, curve):
    """
    Chiffre un point en utilisant la clé publique.
    """
    k = secrets.randbelow(curve.p)
    c1 = G
    for _ in range(k - 1):
        c1 = point_addition(c1, G, curve)

    c2 = point
    for _ in range(k - 1):
        c2 = point_addition(c2, public_key, curve)

    return c1, c2

def decrypt_point(c1, c2, private_key, curve):
    """
    Déchiffre un point en utilisant la clé privée.
    """
    s = c1
    for _ in range(private_key - 1):
        s = point_addition(s, c1, curve)

    # Inverser le point s
    s_inverse = Point(s.x, -s.y % curve.p)

    # Additionner c2 et s_inverse pour obtenir le point original
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
