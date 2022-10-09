import socket
import time
import struct
import locale
import sys

def send_elf():
    host = '10.0.0.169'
    port = 9020

    if len(sys.argv) < 2:
        print("Need a path to an ELF to send.")
        return

    f = open(sys.argv[1], "rb")
    data = f.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(data)
        s.close()

    f.close()

if __name__ == '__main__':
    send_elf()