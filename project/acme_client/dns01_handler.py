from dnslib import RR, dns
from dnslib.server import BaseResolver, DNSServer

# Starts a DNS server on port 10053 and runs on all network interface
def start_dns_server(challenge_response, port=10053):
    dns_server = DNSServer(DNS01Handler(challenge_response), port, address='0.0.0.0')
    dns_server.start_thread()
    print(f"DNS-01 Server is running on port {port}")

class DNS01Handler(BaseResolver):
    def __init__(self, challenge_response):
        self.challenge_response = challenge_response
        self.zones = []

    # Process TXT queries for ACME challenge
    def resolve(self, request, handler):
        
        reply = request.reply()
        qtype = request.q.qtype  # A for IP Address, TXT for DNS records
        domain = request.q.qname

        if qtype == dns.QTYPE.TXT and "_acme-challenge" in str(domain):
            reply.add_answer(RR(domain, dns.QTYPE.TXT, rdata=self.challenge_response, ttl=300))
            return reply
        else:
            return reply
