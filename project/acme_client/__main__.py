from http.server import HTTPServer
from threading import Thread
from dnslib.server import DNSServer

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler

from argparse import ArgumentParser

def parse_args():
    parser = ArgumentParser("ACME Client for handling certificate requests.")
    parser.add_argument('challenge_type', choices=['dns01', 'http01'])
    parser.add_argument('--dir', required=True, help='DIR_URL is the directory URL of the ACME server that should be used.')
    parser.add_argument('--record', required=True, help='IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.')
    # domain can be multiple
    parser.add_argument('--domain', required=True, action='append', help='DOMAIN is the domain for which to request the certificate.') 
    parser.add_argument('--revoke', action='store_true', help='If present, your application should immediately revoke the certificate after obtaining it..')
    
    return parser.parse_args()

if __name__ == "__main__":
    # Hint: You may want to start by parsing command line arguments and
    # perform some sanity checks first. The built-in `argparse` library will suffice.
    args = parse_args()

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
