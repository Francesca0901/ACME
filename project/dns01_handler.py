from dnslib import RR

class DNS01Handler:
     def resolve(self, request, handler):
         reply = request.reply()
         reply.add_answer(*RR.fromZone("example.com 60 A 1.2.3.4"))
         return reply
