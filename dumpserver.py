import socket
import time
import struct
import locale

def server_program():
    host = '0.0.0.0'
    port = 5656

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(1)
    conn, address = server_socket.accept()  # accept new connection
    conn.settimeout(60) # 60 second timeout
    print("Connection from: " + str(address))

    
    timestr = time.strftime("%Y%m%d-%H%M%S")
    print("[+] Writing dump to dump-" + timestr + ".bin...")

    total_received = 0
    with open("dump-" + timestr + ".bin", "wb") as f:
        while True:
            try:
                data = conn.recv(0x10000)
                total_received += len(data)
                print("Received " + str(total_received) + " bytes...")
                if not data:
                    break
                f.write(data);
            except:
                break
        f.close()
    conn.close()
    server_socket.close()

if __name__ == '__main__':
    server_program()