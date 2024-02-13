# echo-server.py
 
import socket

from Crypto.Cipher import AES
 
HOST = "192.168.0.100"
PORT = 10000# Port to listen on (non-privileged ports are > 1023)


def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return cipher.nonce + tag + ciphertext

def decrypt(key, data):
    nonce = data[:AES.block_size]
    tag = data[AES.block_size:AES.block_size * 2]
    ciphertext = data[AES.block_size * 2:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    
    return cipher.decrypt_and_verify(ciphertext, tag)

key = '1111111111111111'
 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            decrypt(key, data)
            if not data:
                break
            encrypt(key, data)
            conn.sendall(data)

data2 = "90463dec54fecf62f486ebcc5860114e80ef65b24d42cf8be97b82f58f9a3d4b"
decrypt(key, data2)

