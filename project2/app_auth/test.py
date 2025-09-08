import requests
import json
import random
import platform

from requests.models import Response
from app_cryptography import *
from argparse import ArgumentParser

CHALLENGE_SIZE = 64
OUT_SIZE = 32
PDKDF2_COUNT = 1000000
ITERATIONS = 256 

def validate_hello_response(response: Response):
    try:
        response_data = json.loads(response.text)
        if "sessionID" in response_data and "challenge" in response_data:
            sessionID = bytes.fromhex( response_data["sessionID"] )
            server_challenge = bytes.fromhex( response_data["challenge"] ) 
            return True
        print("Invalid response to hello message")
        exit(3)
    except Exception as e:
        print(e)
        exit(4)

def validate_response(response: Response, sID: str):
    try:
        response_data = json.loads(response.text)
        if "response" in response_data and "sessionID" in response_data:
            server_response = bytes.fromhex( response_data["response"] )
            sessionID = bytes.fromhex( response_data["sessionID"] )
            if sessionID == sID:
                return True
        print("Invalid response")
        exit(5)
    except Exception as e:
        print(e)
        exit(6)

def validate_ca_cert():
    ca = open("../app_auth/certs/CA.pem", "rb")
    hash = sha256(ca.read())
    ca.close()
    # the hashes seem to differ from linux to windows. probably because of line endings and stuff
    if "42089922a785a401fb031515ea269c7670e869e14533f447b17d701a390ce1e6" != hash.hex() and "de42ced6006db6fc2a3ffc0d9baf4e388af06afdd70d45259d795af8555e02a2" != hash.hex():
        print("Invalid CA certificate")
        exit(-1)

def main(args):
    try:
        validate_ca_cert()
        isValid = True

        username: str = args.username
        password: bytes = args.password.encode()
        seed: bytes = bytes.fromhex(args.seed)
        url: str = args.url
        
        my_challenge = random_challenge(CHALLENGE_SIZE)

        # https://stackoverflow.com/questions/4557444/python-random-sequence-with-seed
        random.seed(int.from_bytes(seed, byteorder='little'))
        bit_order = list(range(ITERATIONS))
        random.shuffle(bit_order)

        session = requests.Session()
        session.verify = '../app_auth/certs/CA.pem'

        response = session.get(f'{url}/e-chap?username={username}&hello=hello')
        validate_hello_response(response)

        response_data = json.loads(response.text)

        sessionID = bytes.fromhex( response_data["sessionID"] )
        server_challenge = bytes.fromhex( response_data["challenge"] )

        h1_salt = bytes ( bytearray( my_challenge ) + bytearray( server_challenge ) + bytearray( sessionID ) )
        h1 = pbkdf2( password, h1_salt, OUT_SIZE, PDKDF2_COUNT )

        h2_salt = bytes ( bytearray( sessionID ) + bytearray( my_challenge ) + bytearray( server_challenge ) )
        h2 = pbkdf2( password, h2_salt, OUT_SIZE, PDKDF2_COUNT )

        reply = get_bit(h1, bit_order[0])

        response = session.get(f'{url}/e-chap?sessionID={sessionID.hex()}&challenge={my_challenge.hex()}&response={reply.hex()}')
        validate_response(response, sessionID)

        response_data = json.loads(response.text)
        server_response = bytes.fromhex( response_data["response"] )
        if server_response != get_bit(h2, bit_order[0]):
            isValid = False

        for i in range(1, ITERATIONS):
            reply = None
            if not isValid:
                reply = random_bit()
            else:
                reply = get_bit(h1, bit_order[i])
            response = session.get(f'{url}/e-chap?sessionID={sessionID.hex()}&response={reply.hex()}')
            validate_response(response, sessionID)
            response_data = json.loads(response.text)
            server_response = bytes.fromhex( response_data["response"] )

            if server_response != get_bit(h2, bit_order[i]):
                isValid = False

        if isValid:
            print(sessionID.hex())
            exit(0)
        else:
            print("Failed")
            exit(1)
    except Exception as e:
        print(e)
        exit(2)

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('username', type=str)
    parser.add_argument('password', type=str)
    parser.add_argument('seed', type=str)
    parser.add_argument('url', type=str)

    args = parser.parse_args()
    main(args)
