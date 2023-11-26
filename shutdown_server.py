from flask import Flask
from threading import Thread
from multiprocessing import Process
import flask


class ShutdownServer(Process):
    def __init__(self, ipv4, port=5003):
        super().__init__()
        self.ipv4 = ipv4
        self.port = port
        self.app = Flask(__name__)

    def run(self):
        @self.app.route(f"/shutdown", methods=["GET"])    
        def server_shutdown():
            # seen on https://stackoverflow.com/questions/15562446/how-to-stop-flask-application-without-using-ctrl-c
            f= flask.request.environ.get('werkzeug.server.shutdown')
            if f is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            f()
            print("Server shutdown")
            
        self.app.run(host=self.ipv4, port=self.port, debug=False)