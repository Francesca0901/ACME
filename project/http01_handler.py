from http.server import BaseHTTPRequestHandler

class HTTP01Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write("Hello World!".encode("utf-8"))
