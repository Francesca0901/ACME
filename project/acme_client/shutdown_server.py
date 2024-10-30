from flask import Flask, request
from werkzeug.serving import make_server
import threading

class ShutdownServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.server = None
        self.server_thread = None

    def run(self, host, certificate_server, dns_server, http01_handler):
        @self.app.route('/shutdown')
        def shutdown():
            print("Shutdown request received. Shutting down servers...")
            # Stop the Certificate Server
            if certificate_server:
                certificate_server.shutdown()
            # Stop the DNS Server
            if dns_server:
                dns_server.stop()
            # Stop the HTTP-01 Handler
            if http01_handler:
                http01_handler.shutdown()
            # Stop the ShutdownServer itself
            threading.Thread(target=self.shutdown_server).start()
            print("All servers shut down. Exiting application.")
            return "All servers shut down. Exiting application."

        self.server = make_server(host, 5003, self.app)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def shutdown_server(self):
        if self.server:
            self.server.shutdown()
            self.server_thread.join()
            print("Shutdown server has shut down.")
