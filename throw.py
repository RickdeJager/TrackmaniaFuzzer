import os, sys
import time
from pwn import *


HOST = 'localhost'
PORT = 5001
CRASH_DIR = './qemu'

def login(p):
    print("Valid header!")

    print('Authenticating ...')
    handler = 0x80000000 # handler starts at this value

    data = b'<?xml version="1.0"?>'
    data += b'<methodCall>'
    data += b'<methodName>Authenticate</methodName>' # call the Authenticate method
    data += b'<params>'
    data += b'<param><value>SuperAdmin</value></param>' # username: SuperAdmin
    data += b'<param><value>SuperAdmin</value></param>' # password: SuperAdmin
    data += b'</params>'
    data += b'</methodCall>'

    ## build the packet
    ### pack handler, 4 bytes int, big endian
    handlerBytes = p32(handler)

    ### pack method call, xml structure
    ### compile packet
    packet = bytes()
    #### packet length
    packetLen = len(data)
    packet += p32(packetLen)
    #### handler
    packet += handlerBytes
    #### data
    packet += data

    ### Send the authentication call
    p.send(packet)

    ## recieve authentication response
    ### recieve response header, 8 bytes
    header = p.recv(8)
    #### unpack response size, 4 bytes int
    size = u32(header[:4])
    #### unpack handler, 4 bytes int
    responseHandler = u32(header[4:])
    ##### the response must have the same handler value
    if responseHandler != handler:
        print('Response handler does not match!')
        exit(0)
    #### recieve response data
    response = p.recv(size)


# connect
def throw(contents):
    p = remote(HOST, PORT)

    # recieve and validate header the gbx header
    data = p.recv(4)
    headerLength = u32(data)

    ## header data, bytes of length n=headerLength
    data = p.recv(headerLength)
    header = data.decode() # decode bytes to string

    ## the header should equal "GBXRemote 2"
    if header != "GBXRemote 2":
        print('Invalid header.')
        exit(0)

    print("Valid header!")

    print('Authenticating ...')
    login(p)
    handler = 0x80000001 # handler starts at this value

    ## build the packet
    ### pack handler, 4 bytes int, big endian
    handlerBytes = p32(handler)

    ### pack method call, xml structure
    ### compile packet
    packet = bytes()
    #### packet length
    packetLen = len(contents)
    packet += p32(packetLen)
    #### handler
    packet += handlerBytes
    #### data
    packet += contents

    ### Send the authentication call
    p.send(packet)

    header = p.recv(8)
    size = u32(header[:4])
    #### unpack handler, 4 bytes int
    responseHandler = u32(header[4:])

    #### recieve response data
    response = p.recv(size*5)
    try:
        print(response.decode().replace('\r', ''))
    except:
        print(response)


    p.close()

with open(sys.argv[1], "rb") as crash_file:
    content = crash_file.read()
    throw(content)
