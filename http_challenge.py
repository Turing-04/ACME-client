from flask import Flask
from threading import Thread
from multiprocessing import Process



class HTTPChallenge(Process):
    def __init__(self, token, key_auth, ipv4, port=5002):
        super().__init__()
        self.key_auth = key_auth
        self.token = token
        self.ipv4 = ipv4
        self.port = port
        self.app = Flask(__name__)


    def run(self):
        @self.app.route(f"/.well-known/acme-challenge/{self.token}", methods=["GET"])    
        def acme_chall():
            # return the key authorization for the challenge
            return self.key_auth
        self.app.run(host=self.ipv4, port=self.port, debug=False)
        

