import random
from sympy import randprime
# Function to convert a plaintext message to a number
def message_to_number(message):
 # calculate the remainder
    # converted=[]
    # groups = [message[i:i+5] for i in range(0, len(message), 5)]  # split into groups of 5 characters
    # for i in range(len(groups)):
    each_message=0
    for j in range(5):
        char =message[j]
        each_message += char_to_number(char) * (37 ** (4 - j))
    #  converted.append(each_message)
    # print(f"asmi:{converted}")
    return each_message

# Function to convert a number to a plaintext message
def number_to_message(group):
    message=""
    number = int(group)
    for i in range(4, -1, -1):
        quotient = number // (37 ** i)
        number = number % (37 ** i)
        message += number_to_char(quotient)
    return message
# Function to convert a character to a number
def char_to_number(char):
    if char.isnumeric():
        return int(char)
    elif char == " ":
        return 36
    else:
        return ord(char) - 87

# Function to convert a number to a character
def number_to_char(number):
    if number < 10:
        return str(number)
    elif number == 36:
        return " "
    else:
        # print(number)
        return chr(number + 87)

# Function to generate a pair of public and private keys for RSA encryption
def generate_keys(nbits):
    # Choose two large prime numbers
    p = randprime(pow(2,(nbits)), pow(2,(nbits+1)))
    q = randprime(pow(2,(nbits)), pow(2,(nbits+1)))

    # Compute n = pq and phi(n) = (p-1)(q-1)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    # print(f"fayzeft:{phi_n}")
    # Choose a random integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = random.randrange(2, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    # Compute the modular inverse of e, d, such that ed = 1 (mod phi(n))
    d = mod_inverse(e, phi_n)

    # Return public and private keys
    return ((n, e), (n, d))

# Function to compute the greatest common divisor of two numbers
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
    
#Computes the modular inverse of a number a (mod m). Returns None if a and m are not coprime.
def extended_gcd(a, b):
    """
    Returns a tuple (r, s, t) such that a*r + b*s = gcd(a,b) = r
    """
    if b == 0:
        return (a, 1, 0)
    else:
        (q, r) = divmod(a, b)
        (g, s, t) = extended_gcd(b, r)
        return (g, t, s - q * t)

def mod_inverse(a, m):
    """
    Returns the modular inverse of a modulo m, if it exists.
    """
    g, s, t = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return s % m
#You can call the mod_inverse(a, m) function with your a and m values to get the modular inverse of a modulo m. If the modular inverse does not exist, the function raises a ValueError exception.

# Function to encrypt a message using RSA algorithm
def Encrypt(message, public_key):
    # ciphertext_number=[]
    n, e = public_key
    message_number = message_to_number(message)
    # print(f"message to number :{message_number}")
    # for i in range(len(message_number)):
    ciphertext_number=pow(message_number,e,n)
    return ciphertext_number

# Function to decrypt a ciphertext using RSA algorithm
def Decrypt(ciphertext_number, private_key):
    n, d = private_key
    # for i in range(len(ciphertext_number)):
    message=pow(int(ciphertext_number),d,n)
    message =number_to_message(message)
    return message