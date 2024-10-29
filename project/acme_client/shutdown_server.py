from http.server import SimpleHTTPRequestHandler
import os
from socketserver import TCPServer
from threading import Thread

from flask import Flask, request

def shutdown_server():
    # func = request.environ.get('werkzeug.server.shutdown')
    # if func is None:
    #     raise RuntimeError('Not running with the Werkzeug Server')
    # func()

    """Forcefully terminate the application."""
    os._exit(0)

class ShutdownServer():
    def __init__(self):
        server = Flask(__name__)

        @server.route('/shutdown')
        def shutdown():
            shutdown_server()
            print("======Server shutting down======")
            return

        self.server = server

    def start_server(self, host, port):
        # start threat
        self.server.run(host=host, port=port, threaded=True)