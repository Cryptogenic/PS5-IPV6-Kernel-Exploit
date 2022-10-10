import socket
import time
import struct
import locale
import sys

def recv_klog():
    host = '10.0.0.169'
    port = 9081

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        while True:
            try:
                data = s.recv(0x100)
                if not data:
                    break
                print(data.decode('utf-8'))
            except socket.timeout:
                print("[ERROR] Timeout reached for receiving data (1 min)\n")
                break
            except socket.error:
                print("[ERROR] Failed to read from socket\n")
                break

    s.close()

if __name__ == '__main__':
    recv_klog()