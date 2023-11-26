from flask import Flask
from threading import Thread
from multiprocessing import Process



class HTTPSServer(Process):
    def __init__(self, ipv4, certificate, port=5001):
        super().__init__()
        self.certificate = certificate
        self.ipv4 = ipv4
        self.port = port
        self.app = Flask(__name__)


    def run(self):
        @self.app.route(f"/", methods=["GET"])    
        def certif():
            # return the key authorization for the challenge
            return self.certificate
        self.app.run(host=self.ipv4, port=self.port, debug=False, ssl_context=("./certificate.pem", "./private_key.pem"))
        
        