from http.server import HTTPServer
import os
from threading import Thread
from dnslib.server import DNSServer

from .http01_handler import HTTP01Handler, CertificateServer
from .dns01_handler import DNS01Handler, stop_dns_server

from argparse import ArgumentParser

from dnslib import TXT
from .ACME_client import ACME_client
from .shutdown_server import ShutdownServer

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
    if args.challenge_type == 'dns01':
        args.challenge_type = 'dns-01'
    elif args.challenge_type == 'http01':
        args.challenge_type = 'http-01'

    http01_handler = HTTP01Handler()
    http01_thread = Thread(target=http01_handler.start_server, args=("0.0.0.0", 5002))
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

    cert_url = client.solve_challenges(dns01_handler, http01_handler, args.challenge_type)
    if cert_url:
        print("Certificate issuance successful; downloading certificate...")
        client.download_cert(cert_url)
    else:
        print("Certificate issuance failed; cannot download certificate.")

    certificate_server = CertificateServer("0.0.0.0", client.cert)
    certificate_server_thread = Thread(target=certificate_server.start_server)
    certificate_server_thread.daemon = True
    certificate_server_thread.start()

    if args.revoke:
        print("Revoking certificate...")
        client.revoke_cert()

    # Start the ShutdownServer
    shutdown_server = ShutdownServer()
    shutdown_thread = Thread(
        target=shutdown_server.run,
        args=("0.0.0.0", certificate_server, dns01_server, http01_handler)
    )
    shutdown_thread.start()
    print("Shutdown server is running on port 5003")

    # Wait for the shutdown server to finish
    shutdown_thread.join()

    # Join other server threads if they haven't been joined already
    http01_thread.join()
    dns01_thread.join()
    certificate_server_thread.join()
