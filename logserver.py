import socket
import time
import struct
import locale

def server_program():
    host = '0.0.0.0'
    port = 5655

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(1)
    conn, address = server_socket.accept()  # accept new connection
    conn.settimeout(60) # 60 second timeout
    print("Connection from: " + str(address))

    while True:
        try:
           data = conn.recv(0x100)
           if not data:
               return
           print("[LOG] " + data.decode('utf-8'))
        except socket.timeout:
           print("[LOG] [ERROR] Timeout reached for receiving data (1 min)\n")
           return
        except socket.error:
           print("[LOG] [ERROR] Failed to read from socket\n")
           return

    conn.close()

if __name__ == '__main__':
    server_program()