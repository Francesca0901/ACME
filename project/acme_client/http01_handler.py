from http.server import BaseHTTPRequestHandler
from flask import Flask

# Aiming at solving HTTP01 challenge
class HTTP01Handler(BaseHTTPRequestHandler):
    def __init__(self):
        self.challenges = {}
        self.server = Flask(__name__)

        @self.server.route('/.well-known/acme-challenge/<string:token>')
        def challenge_http(token):
            if token in self.challenges:
                return self.challenges[token]
            else:
                return "Token is not in challenge list!"
            
    def start_server(self, host, port):
        self.server.run(host=host, port=port, threaded=True)

    def register_challenge(self, token, key_authorization):
        self.challenges[token] = key_authorization

# Aiming at providing certificate
class CertificateServer():
    def __init__(self, host, certificate):
        self.host = host
        self.certificate = certificate
    
    def start_server(self):
        server = Flask(__name__)

        context = ('cert.pem','public_key.pem')
        self.app = Flask(__name__)

        @server.route('/')
        def return_certificate():
            print("Return certificate.")
            return self.certificate
        
        self.app.run(host=self.host, port=5001, ssl_context=context, threaded=True)