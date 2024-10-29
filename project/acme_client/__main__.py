from http.server import HTTPServer
import os
from threading import Thread
from dnslib.server import DNSServer

from .http01_handler import HTTP01Handler
from .dns01_handler import DNS01Handler, stop_dns_server

from argparse import ArgumentParser

from dnslib import TXT
from .ACME_client import ACME_client
from .shutdown_server import ShutdownServer, shutdown_server

def parse_args():
    parser = ArgumentParser("ACME Client for handling certificate requests.")
    parser.add_argument('challenge_type', choices=['dns01', 'http01'])
    parser.add_argument('--dir', required=True, help='DIR_URL is the directory URL of the ACME server that should be used.')
    parser.add_argument('--record', required=True, help='IPv4_ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.')
    # can pass multiple domain
    parser.add_argument('--domain', required=True, action='append', help='DOMAIN is the domain for which to request the certificate.') 
    parser.add_argument('--revoke', action='store_true', help='If present, your application should immediately revoke the certificate after obtaining it..')
    
    return parser.parse_args()

if __name__ == "__main__":
    # Hint: You may want to start by parsing command line arguments and
    # perform some sanity checks first. The built-in `argparse` library will suffice.
    args = parse_args()

    http01_server = HTTPServer(("0.0.0.0", 5002), HTTP01Handler)
    http01_thread = Thread(target=http01_server.serve_forever)
    http01_thread.daemon = True
    http01_thread.start()
    print("HTTP-01 server is running on port 5002")

    dns01_handler = DNS01Handler(args.domain, args.record)
    dns01_server = DNSServer(dns01_handler, port=10053, address="0.0.0.0")
    dns01_thread = Thread(target=dns01_server.start_thread)
    dns01_thread.daemon = True
    dns01_thread.start()
    print("DNS-01 server is running on port 10053")

    # Your code should go here
    client = ACME_client(args.dir, args.record, args.domain)
    client.create_account()
    client.submit_order(args.domain)

    cert_url = client.solve_challenges(dns01_handler, http01_server)
    if cert_url:
        print("Certificate issuance successful; downloading certificate...")
        client.download_cert(cert_url)
    else:
        print("Certificate issuance failed; cannot download certificate.")

    if args.revoke:
        print("Revoking certificate...")
        client.revoke_cert()

    # Shutting down the servers
    shutdown_server = ShutdownServer()
    shutdown_server.start_server("0.0.0.0", 5003)
    stop_dns_server(dns01_server)
    
    os._exit(0)