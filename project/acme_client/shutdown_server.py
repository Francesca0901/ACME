from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from threading import Thread

class ShutdownServer(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/shutdown':
            print(".....Shutting down the server")
            self.send_response(200)
            self.end_headers()
            self.server.shutdown()
        else:
            print(".....Invalid path")
            self.send_response(404)
            self.end_headers()

def shutdown_server():
    server_address = ('0.0.0.0', 5003)

    with TCPServer(server_address, ShutdownServer) as httpd:
        print("Shutdown HTTP server running on port 5003")

        server_thread = Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        return httpd