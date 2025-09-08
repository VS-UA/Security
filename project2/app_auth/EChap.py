import datetime 
import uuid
import json
import random
import sys

from enum import Enum
from flask import Request
from app_cryptography import *
from auth import *

CHALLENGE_SIZE = 64
OUT_SIZE = 32
PDKDF2_COUNT = 1000000
ITERATIONS = 256 
LOGIN_TIMEOUT = 30
TIMEOUT = 15

def process_bytes(b: bytes):
    return b.hex()

def read_arg(s: str):
    return bytes.fromhex(s)

def try_read_arg(s: str):
    try:
        bytes.fromhex(s)
        return True
    except:
        return False


class ECHAPManager:
    def __init__(self, auth : Auth) -> None:
        self.auth = auth
        self.active = {}
        self.succeeded = {}

    def __new(self, username: str):
        user_data = self.auth.get_user_data(username)
        if user_data is None:
            return None

        auth = PDKDF2Auth( str(uuid.uuid4()).encode(), (user_data["username"]).encode(), (user_data["password"]).encode(), (user_data["seed"]) )
        self.active[auth.sessionID] = auth

        return auth

    def __try_get_auth_from_request(self, request: Request):
        sessionID = request.args.get("sessionID")
        if sessionID is None:
            return None
        
        sessionID = read_arg( request.args.get("sessionID") )

        if sessionID not in self.active.keys():
            return None
        auth : PDKDF2Auth = self.active[sessionID]
        return auth

    def __is_proper_hello(self, request: Request):
        if len( request.args ) != 2:
            return False

        if "hello" not in request.args.keys() or "username" not in request.args.keys():
            return False
        
        if not self.auth.does_user_exist( request.args["username"] ):
            return False

        return True

    def __is_proper_first_response(self, request: Request):
        if len( request.args ) != 3:
            return False

        if "sessionID" not in request.args.keys() or "challenge" not in request.args.keys() or "response" not in request.args.keys():
            return False

        return try_read_arg( request.args["sessionID"] ) and try_read_arg( request.args["challenge"] ) and try_read_arg( request.args["response"] )

    def __is_proper_response(self, request: Request):
        if len( request.args ) != 2:
            return False
        
        if "sessionID" not in request.args.keys() or "response" not in request.args.keys():
            return False

        return try_read_arg( request.args["sessionID"] ) and try_read_arg( request.args["response"] )

    def __succeeded(self, auth):
        self.succeeded[auth.sessionID] = auth
        del self.active[auth.sessionID]

    def __cancel_succeeded(self, auth):
        if auth.sessionID in self.succeeded.keys():
            del self.succeeded[auth.sessionID]

    def __invalidate_auth(self, auth):
        if auth.sessionID in self.active.keys():
            del self.active[auth.sessionID]

    def __remove_timed_out(self):
        now = datetime.utcnow().timestamp()
        del_list = []
        for sessionID in self.active.keys():
            auth: PDKDF2Auth = self.active[sessionID]
            if (auth.last_request_at + timedelta(seconds=TIMEOUT)).timestamp() < now:
                del_list.append(auth)
        for auth in del_list:
            print(f"Deleted timed out authentication {sessionID}")
            self.__invalidate_auth(auth)

    def try_login(self, request: Request, session: SessionMixin):
        try:
            if "sessionID" in request.form and try_read_arg( request.form["sessionID"] ):
                sessionID = read_arg( request.form["sessionID"] )
                if sessionID in self.succeeded.keys():
                    auth : PDKDF2Auth = self.succeeded[sessionID]
                    now = datetime.utcnow().timestamp()   
                    if (auth.succeeded_at + timedelta(seconds=LOGIN_TIMEOUT)).timestamp() < now:
                        print(f"Deleted expired login {auth.sessionID}")
                        self.__cancel_succeeded(auth)
                        return False 
                    if self.auth.login_chap(auth.username.decode(), session):                                                 
                        del self.succeeded[sessionID]
                        return True
            return False
        except:
            return False


    def process(self, request: Request):
        auth = None
        try:
            self.__remove_timed_out()

            auth = self.__try_get_auth_from_request(request)
            
            if auth is None:
                # try to figure out if it's an hello and if the user exists
                if self.__is_proper_hello(request) and self.auth.does_user_exist( request.args["username"] ):
                    auth = self.__new( request.args["username"] )
                    return (ECHAPRESULT.OK, auth.process_request(request))

            else:
                response = None
                match auth.status:
                    case PDKDF2AuthStatus.INVALID:
                        if self.__is_proper_first_response(request) or self.__is_proper_response(request):
                            response = auth.process_request(request)
                    case PDKDF2AuthStatus.SUCCEEDED:
                        self.__cancel_succeeded(auth)
                    case PDKDF2AuthStatus.FAILED:
                        self.__invalidate_auth(auth)
                    case PDKDF2AuthStatus.UNINITIALIZED:
                        self.__invalidate_auth(auth)
                    case PDKDF2AuthStatus.AWAITINGFIRSTRESP:
                        if self.__is_proper_first_response(request):
                            response = auth.process_request(request)
                    case PDKDF2AuthStatus.AWATINGRESP:
                        if self.__is_proper_response(request):
                            response = auth.process_request(request)

                # protocol is succesfull
                if auth.status is PDKDF2AuthStatus.SUCCEEDED: 
                    self.__succeeded(auth)
                    return (ECHAPRESULT.OK, response)

                if auth.status is PDKDF2AuthStatus.FAILED:
                    self.__invalidate_auth(auth)
                    return (ECHAPRESULT.OK, response)

                if response is not None:
                    return (ECHAPRESULT.OK, response)
                else:
                    # bad request immediately cancels the protocol
                    self.__invalidate_auth(auth)
   
            return (ECHAPRESULT.NOTOK, 400)

        except Exception as e:
            print(e)
            if auth is not None:
                self.__invalidate_auth(auth)
            return (ECHAPRESULT.NOTOK, 400)

class ECHAPRESULT(Enum):
    OK = 0
    NOTOK = 1

class PDKDF2AuthStatus(Enum):
    UNINITIALIZED = 0
    AWAITINGFIRSTRESP = 1
    AWATINGRESP = 2
    INVALID = 3
    FAILED = 4
    SUCCEEDED = 5

class PDKDF2Auth:
    def __init__(self, sessionID : bytes, username: bytes, password: bytes, seed: bytes):
        self.sessionID = sessionID
        self.username = username
        self.password = password
        self.seed = seed

        self.iteration = 0

        self.my_challenge = random_challenge(CHALLENGE_SIZE)
        self.client_challenge = None
        self.h1 = None
        self.h2 = None

        # https://stackoverflow.com/questions/4557444/python-random-sequence-with-seed
        random.seed(int.from_bytes(self.seed, byteorder='little'))
        self.bit_order = list(range(ITERATIONS))
        random.shuffle(self.bit_order)

        self.status = PDKDF2AuthStatus.UNINITIALIZED

        self.last_request_at = None
        self.succeeded_at = None
        
    def __str__(self) -> str:
        return f"""sessionID: {self.sessionID.hex()}
username: {self.username.decode()}
password: {self.password.decode()}
seed: {self.seed.decode()}
iteration: {self.iteration}
server challenge: {self.my_challenge}
client challenge: {self.client_challenge}
h1: {self.h1}
h2: {self.h2}
Status: {self.status}
Last request at: {self.last_request_at}
Succeded at: {self.succeeded_at}"""

    def process_request(self, request: Request):
        print(self.status)
        self.last_request_at = datetime.utcnow()
        match self.status:

            case PDKDF2AuthStatus.INVALID:
                self.iteration += 1
                if self.iteration == ITERATIONS:
                        self.status = PDKDF2AuthStatus.FAILED
                return json.dumps( { "response": process_bytes(random_bit()), "sessionID": process_bytes(self.sessionID) } )
            
            case PDKDF2AuthStatus.UNINITIALIZED:
                self.status = PDKDF2AuthStatus.AWAITINGFIRSTRESP

                return json.dumps( { "challenge": process_bytes(self.my_challenge), "sessionID": process_bytes(self.sessionID) } )

            case PDKDF2AuthStatus.AWAITINGFIRSTRESP:
                self.client_challenge = read_arg(request.args["challenge"])
                client_bit = read_arg(request.args["response"])

                h1_salt = bytes ( bytearray( self.client_challenge ) + bytearray( self.my_challenge ) + bytearray( self.sessionID ) )
                self.h1 = pbkdf2(self.password, h1_salt, OUT_SIZE, PDKDF2_COUNT)

                h2_salt = bytes ( bytearray( self.sessionID ) + bytearray( self.client_challenge ) + bytearray( self.my_challenge ) )
                self.h2 = pbkdf2(self.password, h2_salt, OUT_SIZE, PDKDF2_COUNT)

                bit = get_bit(self.h1, self.bit_order[self.iteration])
                server_bit = get_bit(self.h2, self.bit_order[self.iteration])
                self.iteration += 1

                if bit == client_bit:
                    self.status = PDKDF2AuthStatus.AWATINGRESP
                    return json.dumps( { "response": process_bytes(server_bit), "sessionID": process_bytes(self.sessionID) } )
                else:
                    self.status = PDKDF2AuthStatus.INVALID
                    return json.dumps( { "response": process_bytes(random_bit()), "sessionID": process_bytes(self.sessionID) } )

            case PDKDF2AuthStatus.AWATINGRESP:
                client_bit = read_arg(request.args["response"])

                bit = get_bit(self.h1, self.bit_order[self.iteration])
                server_bit = get_bit(self.h2, self.bit_order[self.iteration])

                self.iteration += 1
                
                if bit == client_bit:
                    if self.iteration == ITERATIONS:
                        self.succeeded_at = datetime.utcnow()
                        self.status = PDKDF2AuthStatus.SUCCEEDED
                    else:
                        self.status = PDKDF2AuthStatus.AWATINGRESP
                    return json.dumps( { "response": process_bytes(server_bit), "sessionID": process_bytes(self.sessionID) } )
                else:
                    if self.iteration == ITERATIONS:
                        self.status = PDKDF2AuthStatus.FAILED
                    else:
                        self.status = PDKDF2AuthStatus.INVALID
                    return json.dumps( { "response": process_bytes(random_bit()), "sessionID": process_bytes(self.sessionID) } )
        return None
