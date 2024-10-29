from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from threading import Thread

from flask import Flask

# class ShutdownServer(SimpleHTTPRequestHandler):
#     def do_GET(self):
#         if self.path == '/shutdown':
#             print(".....Shutting down the server")
#             self.send_response(200)
#             self.end_headers()
            
#             Thread(target=self.server.shutdown).start()
#         else:
#             print(".....Invalid path")
#             self.send_response(404)
#             self.end_headers()

# def shutdown_server():
#     server_address = ('0.0.0.0', 5003)

#     with TCPServer(server_address, ShutdownServer) as httpd:
#         print("Shutdown HTTP server is now running on port 5003")

#         server_thread = Thread(target=httpd.serve_forever)
#         server_thread.daemon = True
#         server_thread.start()

#         return httpd

def shutdown_server():
    func = Flask.request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

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