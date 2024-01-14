#code fonctionnel

import random

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
