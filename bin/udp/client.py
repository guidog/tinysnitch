import socket
import sys
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = bytes(sys.argv[1], 'utf-8')
adr, port = sys.argv[2].split(':')
client_socket.sendto(msg, (adr, int(port)))
msg, adr = client_socket.recvfrom(1024)
print(msg.decode())
