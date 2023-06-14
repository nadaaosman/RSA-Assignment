import socket
import pickle
from RSA_ import Encrypt,generate_keys,Decrypt
import time
#server
# j=0
# e=0
# n=0
# create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# (n,e),(n,d)=generate_keys()
# get local machine name
host = socket.gethostname()

# bind the socket to a public host, and a well-known port
server_socket.bind((host, 8000))

# become a server socket
server_socket.listen(1)

print("Server started. Waiting for client to connect...")
# accept connections from outside
(client_socket, address) = server_socket.accept()
print(f"Client connected: {address}")

while(1):
 data=client_socket.recv(1024)
 result_arr = pickle.loads(data)
 with open('publickey_client.txt', 'a') as file:
   file.write(f'{result_arr[0]} {result_arr[1]}\n')
 file.close()
 message = input("Enter the message to encrypt: ")
 remainder = len(message) % 5 
 if remainder != 0:
   message = message + " " * (5 - remainder)  # extend with spaces if necessary
 groups = [message[i:i+5] for i in range(0, len(message), 5)]
 with open('plaintext_server.txt', 'a') as file:
  file.write(f'{message}\n')
 file.close()
 with open('ciphertext_server.txt', 'a') as file:
  for i in range(len(groups)):
   ciphertext = Encrypt(groups[i],(result_arr[1],result_arr[0]))
   # print(f"ciphertext:{ciphertext}")
   file.write(f'{ciphertext} ')
   client_socket.send(str(ciphertext).encode())
   time.sleep(1)
  file.write("\n")
  file.close()
# finish sending
 client_socket.send(("end").encode())

                        # recieve message ------->switch

 (n,e),(n,d)=generate_keys(27)
 public_key=[e,n]
 # sending my public key
 arr_bytes = pickle.dumps(public_key)
 client_socket.send(arr_bytes)
 # recieve the data
 message=""
 data=client_socket.recv(1024)
 while(data.decode()!="end"):
   ciphertext=(data.decode())
   # print(f"my privatekey: {d}")
   message+=Decrypt(ciphertext,(n,d))
   # print(f"decrypted: {message}")
   data=client_socket.recv(1024)
 print(f"decrypted: {message}")   
# close the socket
client_socket.close()