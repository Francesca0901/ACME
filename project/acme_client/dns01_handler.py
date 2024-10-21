from dnslib import RR, dns, QTYPE, TXT
from dnslib.server import BaseResolver, DNSServer
from threading import Thread
from dnslib import TXT

# Starts a DNS server on port 10053 and runs on all network interface
def start_dns_server(domain, txt_value, record, port=10053, address="0.0.0.0"):
    resolver = DNS01Handler(domain, txt_value, record)
    dns_server = DNSServer(resolver, port=port, address=address)
    dns_server.start_thread()
    print(f"DNS-01 Server is running on port {port}, listening on {address}")
    return dns_server

def stop_dns_server(dns01_server):
    dns01_server.stop()
    # dns01_server.server.server_close()
    print("DNS-01 Server is stopped")

class DNS01Handler(BaseResolver):
    def __init__(self, domain, challenge_response, record):
        self.challenge_response = challenge_response
        self.domain = domain
        self.record = record

        print(f"self.domain: {self.domain}")


    # Process TXT queries for ACME challenge
    def resolve(self, request, handler):
        reply = request.reply()
        qtype = request.q.qtype  # A for IP Address, TXT for DNS records
        domain = request.q.qname

        query_domain = str(domain).rstrip('.')
        target_domain = self.domain.rstrip('.')
        print(f"Received DNS query for {query_domain}, type {QTYPE[qtype]}")
        print(f"Target domain: {target_domain}")

        # if qtype == QTYPE.TXT and "_acme-challenge" in str(domain):
        if qtype == QTYPE.TXT and query_domain == target_domain:
            reply.add_answer(RR(domain, QTYPE.TXT, rdata=TXT(self.challenge_response), ttl=300))
            return reply
        else:
            return reply
