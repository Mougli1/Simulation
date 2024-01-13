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
