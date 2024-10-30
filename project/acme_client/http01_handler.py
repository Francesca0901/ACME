from http.server import BaseHTTPRequestHandler
import threading
from flask import Flask
from werkzeug.serving import make_server

# Aiming at solving HTTP01 challenge
class HTTP01Handler(BaseHTTPRequestHandler):
    def __init__(self):
        self.challenges = {}
        self.server = Flask(__name__)
        self.httpd = None

        @self.server.route('/.well-known/acme-challenge/<string:token>')
        def challenge_http(token):
            if token in self.challenges:
                return self.challenges[token]
            else:
                return "Token is not in challenge list!"
            
    def start_server(self, host, port):
        self.host = host
        self.port = port
        self.httpd = make_server(host, port, self.server)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.start()
        # self.server.run(host=host, port=port, threaded=True)

    def register_challenge(self, token, key_authorization):
        self.challenges[token] = key_authorization

    def shutdown(self):
        if self.httpd:
            print("HTTP-01 server is shutting down...")
            self.httpd.shutdown()
            self.server_thread.join()


# Aiming at providing certificate
class CertificateServer():
    def __init__(self, host, certificate):
        self.host = host
        self.certificate = certificate
        self.app = Flask(__name__)
        self.httpd = None
        self.server_thread = None

        @self.app.route('/')
        def return_certificate():
            print("Return certificate.")
            return self.certificate
    
    def start_server(self):
        context = ('cert.pem','private_key.pem')
        self.httpd = make_server(self.host, 5001, self.app, ssl_context=context)
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.start()

    def shutdown(self):
        if self.httpd:
            print("Certificate server is shutting down...")
            self.httpd.shutdown()
            self.server_thread.join()