from http.server import HTTPServer
from threading import Thread
from dnslib.server import DNSServer

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler

from argparse import ArgumentParser

from dnslib import TXT
from acme_client.ACME_client import ACME_client

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

    # if args.challenge_type == 'dns01':
    #     challenge_response = TXT("dummy_challenge_token") # TODO: Replace with actual challenge response

    #     print("DNS Servers are running...")

    #     dns01_server = DNSServer(DNS01Handler(challenge_response), port=10053, address="0.0.0.0")
    #     dns01_thread = Thread(target = dns01_server.server.serve_forever)
    #     dns01_thread.daemon = True
    #     dns01_thread.start()
    #     dns01_thread.join()

    # elif args.challenge_type == 'http01':
    #     print("HTTP Servers are running...")

    #     http01_server = HTTPServer(("0.0.0.0", 5002), HTTP01Handler)
    #     # Hint: You will need more HTTP servers
    #     http01_thread = Thread(target = http01_server.serve_forever)
    #     http01_thread.daemon = True
    #     http01_thread.start()
    #     http01_thread.join()

    # Your code should go here
    client = ACME_client(args.dir, args.record, args.domain)
    client.create_account()
    client.submit_order(args.domain)

    cert_url = client.solve_challenges()
    if cert_url:
        print("Certificate issuance successful; downloading certificate...")
        client.download_cert(cert_url)
    else:
        print("Certificate issuance failed; cannot download certificate.")