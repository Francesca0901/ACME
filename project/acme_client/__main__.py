from http.server import HTTPServer
from threading import Thread
from dnslib.server import DNSServer

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler

if __name__ == "__main__":
    # Hint: You may want to start by parsing command line arguments and
    # perform some sanity checks first. The built-in `argparse` library will suffice.

    http01_server = HTTPServer(("0.0.0.0", 5002), HTTP01Handler)
    dns01_server = DNSServer(DNS01Handler(), port=10053, address="0.0.0.0")
    # Hint: You will need more HTTP servers

    http01_thread = Thread(target = http01_server.serve_forever)
    dns01_thread = Thread(target = dns01_server.server.serve_forever)
    http01_thread.daemon = True
    dns01_thread.daemon = True

    http01_thread.start()
    dns01_thread.start()

    # Your code should go here
