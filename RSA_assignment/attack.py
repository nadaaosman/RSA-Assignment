import math
from RSA_ import mod_inverse, Decrypt


publickey_client = []
plaintexts_client = []
ciphertexts_client = []

publickey_server = []
plaintexts_server = []
ciphertexts_server = []


def prime_factorization(n):
    factors = []
    
    # Find the prime factors of n
    while n % 2 == 0:
        factors.append(2)
        n //= 2
        
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        while n % i == 0:
            factors.append(i)
            n //= i
    
    # If n is still greater than 2, it is a prime factor
    if n > 2:
        factors.append(n)
    
    return factors

                    # attack for plotting

def attack_for_plot(ciphertexts,publickey,plaintext):
    (n,e)=publickey
    prime_numbers = prime_factorization(n)
    phi_n = (prime_numbers[0] - 1) * (prime_numbers[1] - 1)
    d = mod_inverse(e, int(phi_n))
    message_decrypted = ""
    for one_ciphertext in ciphertexts:
         message_decrypted += Decrypt(one_ciphertext, (n, d))
    if message_decrypted == plaintext:
        return message_decrypted  
     
# client ----> publickey
with open("publickey_client.txt", "r") as f:
    for line in f:
        values = line.strip().split()
        publickey_client.append(values)
f.close()

# server ----> publickey
with open("publickey_server.txt", "r") as f:
    for line in f:
        values = line.strip().split()
        publickey_server.append(values)
f.close()

# client ----> plaintext
with open("plaintext_client.txt", "r") as f:
    line = f.readline()
    while line:
        plaintexts_client.append(line.rstrip("\n"))
        line = f.readline()
f.close()

# server ----> plaintext
with open("plaintext_server.txt", "r") as f:
    line = f.readline()
    while line:
        plaintexts_server.append(line.rstrip("\n"))
        line = f.readline()
f.close()

# client ----> ciphertexts
with open("ciphertext_client.txt", "r") as f:
    for line in f:
        values = line.strip().split()
        ciphertexts_client.append(values)
f.close()

# server ----> ciphertexts
with open("ciphertext_server.txt", "r") as f:
    for line in f:
        values = line.strip().split()
        ciphertexts_server.append(values)
f.close()


# attack server
with open('attacked_text_server.txt', 'a') as file:
    for i, ciphertext_of_one_msg in enumerate(ciphertexts_server):
        prime_numbers = prime_factorization(int(publickey_client[i][1]))
        phi_n = (prime_numbers[0] - 1) * (prime_numbers[1] - 1)
        d = mod_inverse(int(publickey_client[i][0]), int(phi_n))
        message_decrypted = ""
        for one_ciphertext in ciphertext_of_one_msg:
            message_decrypted += Decrypt(one_ciphertext, (int(publickey_client[i][1]), d))
        if message_decrypted == plaintexts_server[i]:
            file.write(f'{message_decrypted}\n')
file.close()

# attack client
with open('attacked_text_client.txt', 'a') as file:
    for i, ciphertext_of_one_msg in enumerate(ciphertexts_client):
        prime_numbers = prime_factorization(int(publickey_server[i][1]))
        phi_n = (prime_numbers[0] - 1) * (prime_numbers[1] - 1)
        d = mod_inverse(int(publickey_server[i][0]), int(phi_n))
        message_decrypted = ""
        for one_ciphertext in ciphertext_of_one_msg:
            message_decrypted += Decrypt(one_ciphertext, (int(publickey_server[i][1]), d))
        if message_decrypted == plaintexts_client[i]:
            file.write(f'{message_decrypted}\n')
file.close()

