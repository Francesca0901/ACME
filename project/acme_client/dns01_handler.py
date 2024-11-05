from dnslib import RR, dns, QTYPE, TXT, A, AAAA
from dnslib.server import BaseResolver, DNSServer
from threading import Thread
from dnslib import TXT

def stop_dns_server(dns01_server):
    if dns01_server:
        dns01_server.stop()
        print("DNS-01 Server is stopped")

class DNS01Handler(BaseResolver):
    def __init__(self, domain, record):
        # self.challenge_response = challenge_response
        self.domain = domain
        self.record = record
        self.challenge_response = None

    def set_challenge_response(self, challenge_response):
        self.challenge_response = challenge_response
        print(f"!!!!!!!!!!Challenge response set to: {self.challenge_response}")

    # Process TXT queries for ACME challenge
    # TODO: distinguish between example.com and _acme-challenge.example.com
    def resolve(self, request, handler):
        reply = request.reply()
        qtype = request.q.qtype  # A for IP Address, TXT for DNS records
        domain = request.q.qname

        query_domain = str(domain).rstrip('.')
        # target_domain = self.domain.rstrip('.')
        print(f"Received DNS query for {query_domain}, type {QTYPE[qtype]}")
        # print(f"Target domain: {target_domain}")

        # if qtype == QTYPE.TXT and "_acme-challenge" in str(domain):
        if qtype == QTYPE.TXT:
            reply.add_answer(RR(domain, QTYPE.TXT, rdata=TXT(self.challenge_response), ttl=300))
            return reply
        elif qtype == QTYPE.A:
            reply.add_answer(RR(domain, QTYPE.A, rdata=A(self.record), ttl=300))
            return reply
        else:
            # Don't reply to AAAA
            return reply

# test CICD 3