import socket
import sys
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', int(sys.argv[1])))
while True:
    msg, adr = server_socket.recvfrom(1024)
    if msg == b'ping':
        server_socket.sendto(b'pong', adr)
    else:
        server_socket.sendto(b'say wut now?', adr)
