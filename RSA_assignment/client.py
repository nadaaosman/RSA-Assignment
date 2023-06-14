import socket
import pickle
import time
from RSA_ import Decrypt,generate_keys,Encrypt
#client
# create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

# connection to hostname on the port.
client_socket.connect((host, 8000))

# receive message from the server
while(1):
 (n,e),(n,d)=generate_keys(27)
 #send my public key
 public_key=[e,n]
 ciphertext=[]
 arr_bytes = pickle.dumps(public_key)
 client_socket.send(arr_bytes)
 message=""
#  recieve the data
 data=client_socket.recv(1024)
 while(data.decode()!="end"):
  #  print(f"ana hena ya slama: {data}")
   ciphertext=(data.decode())
  #  print(f"my privatekey: {d}")
   message+=Decrypt(ciphertext,(n,d))
  #  print(f"decrypted: {message}")
   data=client_socket.recv(1024)
 print(f"decrypted: {message}")

                      # sending the message ------>switch

 data=client_socket.recv(1024)
 result_arr = pickle.loads(data)
 with open('publickey_server.txt', 'a') as file:
   file.write(f'{result_arr[0]} {result_arr[1]}\n')
 file.close()
 message = input("Enter the message to encrypt: ")
 remainder = len(message) % 5 
 if remainder != 0:
   message = message + " " * (5 - remainder)  # extend with spaces if necessary
 groups = [message[i:i+5] for i in range(0, len(message), 5)]
 with open('plaintext_client.txt', 'a') as file:
  file.write(f'{message}\n')
 file.close()
 with open('ciphertext_client.txt', 'a') as file:
  for i in range(len(groups)):
   ciphertext = Encrypt(groups[i],(result_arr[1],result_arr[0]))
   file.write(f'{ciphertext} ')
   client_socket.send(str(ciphertext).encode())
   time.sleep(1)
  file.write("\n")
  file.close()
 # finish sending
 client_socket.send(("end").encode())
# close the socket
client_socket.close()