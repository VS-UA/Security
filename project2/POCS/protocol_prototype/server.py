import socket
from utils import *

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))
    msg = ""
    while msg != b"Hello":
        msg, address = s.recvfrom(5)
        print(f"{address} sent Hello")
    username = s.recv(1024)
    print(f"Username: {username}")

    valid = True

    for i in range(N):
        if valid:
            print(f"----------------------{i}--------------------")
            sc = random_challenge()
            print(f"SC: {sc}" )

            s.sendto(sc, address)

            cc = s.recv( CS )
            print( f"CC: {cc}" )
            r = s.recv( 1 )
            print( f"R: {r}" )

            h = sha256( bytes (bytearray(cc) + bytearray(USERNAME) + bytearray(sc) ) )

            sr = aes256( h, sha256(PASSWORD) )
            sr = get_bit( sr, i )
            print( f"SR: {sr}" )

            r2 = None
            if sr == r: 
                h = sha256( bytes ( bytearray( r ) + sha256( PASSWORD ) + bytearray( PC1 ) ) )
                h = sha256( bytes ( bytearray ( h ) + bytearray ( cc ) + bytearray( PC2 ) ) )
                r2 = get_bit( h, i )
                print(f"{i} : OK")
            else:
                r2 = random_bit()
                valid = False
                print(f"{i} : NOT OK")

            s.sendto(r2, address)
        else:
            s.sendto( random_challenge(), address )
            cc = s.recv( CS )
            r = s.recv( 1 )
            s.sendto( random_bit(), address)

    print(f"Success: {valid}")