#!/usr/bin/python3
import socket

serverPort = 22
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(1)

print ('The server is ready to receive')
# Loop forever
while 1:
    connectionSocket, addr = serverSocket.accept()
    msg = connectionSocket.recv(1024)
    print('Received from '+ addr[0]+ 'the following message:'+msg)
    reply = 'Hello Client! Nice to hear you'
    connectionSocket.send(reply)