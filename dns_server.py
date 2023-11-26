from dnslib.server import DNSServer, BaseResolver
from dnslib.dns import RR, DNSRecord, A, TXT, QTYPE
        
        
        
class CustomDNS(BaseResolver):
    
    def __init__(self, domains, IPv4_ADDRESS):
        self.ipv4_address = IPv4_ADDRESS
        self.domains = domains
        self.challenges = []
        #print("DOMAINS: ", self.domains)
        
     
    def resolve(self, request, handler):
        reply = request.reply()
        for domain in self.domains:
            #print("Domain :", domain)
            reply.add_answer(RR(domain, QTYPE.A,rdata=A(self.ipv4_address), ttl=180))
        for txt_record in self.challenges:
            reply.add_answer(txt_record)
        
        #print("DNS reply: ", reply)
        
        return reply
    
    def add_TXT_record(self, domain, value):
        self.challenges.append(RR(domain, QTYPE.TXT ,rdata=TXT(value), ttl=180))

        

    
    
    
    
    