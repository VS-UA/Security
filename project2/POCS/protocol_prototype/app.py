import socket
from utils import *

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    address = ( HOST, PORT )
    s.connect( address )
    s.sendall( b'Hello' )
    s.sendall( USERNAME )

    valid = True

    for i in range(N):
        if valid:
            print(f"----------------------{i}--------------------")
            sc = s.recv( CS )
            print( f"SC: {sc}" )

            cc = random_challenge()
            print( f"CC: {cc}" )

            h = sha256( bytes (bytearray(cc) + bytearray(USERNAME) + bytearray(sc) ) )

            r = aes256( h, sha256(PASSWORD) )
            r = get_bit( r, i )
            print( f"R: {r}" )

            s.sendto(cc, address)
            s.sendto(r, address)

            r2 = s.recv( 1 )

            h = sha256( bytes ( bytearray( r ) + sha256( PASSWORD ) + bytearray( PC1 ) ) )
            h = sha256( bytes ( bytearray ( h ) + bytearray ( cc ) + bytearray( PC2 ) ) )
            cr2 = get_bit( h, i )

            if cr2 != r2:
                valid = False

        else:
            sc = s.recv( CS )
            s.sendto( random_challenge(), address )
            s.sendto( random_bit(), address )
            r2 = s.recv( 1 )

    print(f"Success: {valid}")
