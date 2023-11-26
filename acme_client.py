import math
from typing import Any
import requests
import json
import base64
from time import sleep
# for JWS ES256 signing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util import number

from dns_server import CustomDNS
from dnslib.server import DNSServer, BaseResolver

from http_challenge import HTTPChallenge




class ACMEClient():
    def __init__(self, IPv4_ADDRESS, acme_url, domains, revoke, challenge_type):
        self.IPv4_ADDRESS = IPv4_ADDRESS
        self.domains = domains
        self.revoke = revoke
        self.acme_url= acme_url
        if challenge_type == "http01":
            self.challenge_type = "http-01"
        else:
            self.challenge_type = "dns-01"
        self.newNonce= None
        
        # ACME server directory URLs
        self.url_newNonce = None
        self.url_newAccount = None
        self.url_newOrder = None
        self.url_revokeCert = None
        
        self.url_cert = None
        
        self.key = None
        self.signer = None
        self.kid = None
        
        self.order = None
        self.authorizations = None
        self.finalize = None
        
        self.challenges_todo = []
        
        self.certif = None
        self.csr_der = None
        
    def get_directory(self):
        # GET the ACME server directory
        try:
            request = requests.get(self.acme_url, verify="./pebble.minica.pem")
        except:
            print("Error: cannot connect to the ACME server directory")
            exit()
            
        if request.status_code != 200:
            print("HTTPS request error: ", request.status_code)
            exit()
        
        response = request.json()
        
        print(json.dumps(response, indent= 4))
        
        # initialize attributes
        self.url_newNonce = response["newNonce"]
        self.url_newAccount = response["newAccount"]
        self.url_newOrder = response["newOrder"]
        self.url_revokeCert = response["revokeCert"]
        
        
    def get_newNonce(self):
        response = requests.head(self.url_newNonce, verify="./pebble.minica.pem")
        
        if response.status_code in [200,204]:
            # print(response.headers)
            self.newNonce = response.headers["Replay-Nonce"]
            #print("Successfuly received newNonce: ", self.newNonce)
            return self.newNonce
        else:
            print("New nonce error: HTTP status code ", response.status_code)
            exit() 
            
            
    def get_newAccount(self):
        # POST newAccount request
        payload = {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:admin@example.ch"]
            }
        
        protected_payload = self.create_protected_payload(payload, self.url_newAccount)                    
            
        response = requests.post(self.url_newAccount, headers={"Content-Type": "application/jose+json"},
                                 json=protected_payload, verify="./pebble.minica.pem")
        
        
        
        if response.status_code == 201:
            print("Successfuly created new account:")
            print(response.headers)
            print(response.text)
            self.kid = response.headers["Location"]
        else:
            print("New account error: HTTP status code ", response.status_code)
            print(response.text)
            exit()
    
            
    def create_protected_payload(self, payload, url, kid=None):
        
        jose_header = {
            "alg": "ES256",
            "url": url,
            "nonce": self.get_newNonce(),
            }  
        
        if not kid:
             jose_header["jwk"] = self.create_jwk()
        else:
            jose_header["kid"] = kid
        
        
        if payload == "":
            b64_payload = ""
        else:
            #create JSON web Token
            json_payload = json.dumps(payload).encode("utf-8")
            b64_payload = base64.urlsafe_b64encode(json_payload).decode("utf-8").replace("=", "")
            
        json_header = json.dumps(jose_header).encode("utf-8")
        b64_header = base64.urlsafe_b64encode(json_header).decode("utf-8").replace("=", "")
                
        # create SHA256 hash of the encoded header and payload
        to_sign = (b64_header + "." + b64_payload).encode("ascii")
        sha256_to_sign = SHA256.new(to_sign)
        
        signature = self.signer.sign(sha256_to_sign)
        b64_signature = base64.urlsafe_b64encode(signature).decode("utf-8").replace("=", "")
        
            
        # create JWS
        protected_payload = {
            "payload": b64_payload,
            "protected": b64_header,
            "signature": b64_signature
            } 
        
        return protected_payload

        
        
    def create_jwk(self):
        # adapted from https://stackoverflow.com/questions/67589495/how-to-create-jwks-public-private-key-pair-in-python
        # see also https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
        
        # generate key pair
        self.key = ECC.generate(curve='P-256') 
         
        # signing algorithm
        self.signer = DSS.new(self.key, 'fips-186-3')
        
        # pointQ is the public key
        pub_key = self.key.pointQ
        
        # extract public key coordinates and encode them in base64
        pub_key_x = pub_key.x.to_bytes()
        pub_key_y = pub_key.y.to_bytes()
        base64_pub_key_x = base64.urlsafe_b64encode(pub_key_x).decode("utf-8").replace("=", "")
        base64_pub_key_y = base64.urlsafe_b64encode(pub_key_y).decode("utf-8").replace("=", "")
               
        
        public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64_pub_key_x,
            "y": base64_pub_key_y
            }
        
        return public_jwk
            
            
    def get_newOrder(self):
        # POST newOrder request to get a certificate for the domains
        payload = {
            "identifiers": [{"type": "dns", "value": domain} for domain in self.domains]
            }
        
        kid = self.kid
        
        protected_payload = self.create_protected_payload(payload, self.url_newOrder, kid)                    
            
        response = requests.post(self.url_newOrder, headers={"Content-Type": "application/jose+json"},
                                 json=protected_payload, verify="./pebble.minica.pem")
        
        resp_json = response.json()
        
        if response.status_code == 201:
            print("Successfuly placed new order:")
            #print(response.headers)dns.stop
            print(response.text)
            print(f"Location :{response.headers['Location']}")
            
            self.authorizations = resp_json["authorizations"]
            self.finalize = resp_json["finalize"]
            self.order = response.headers["Location"]
            
        else:
            print("New order error: HTTP status code ", response.status_code)
            print(response.text)
            exit()
    
    
    def get_challenges(self):
        # retrieve challenges from the server to prove domain ownership
        payload = ""
        n=0
        

        for auth_url in self.authorizations:
            protected_payload = self.create_protected_payload(payload, auth_url, self.kid)
            response = requests.post(auth_url, headers={"Content-Type": "application/jose+json"},
                                     json=protected_payload, verify="./pebble.minica.pem")
            
            r_json = response.json()
         
            
            if response.status_code == 200:
                #print("Successfuly retrieved challenges:")     
                #print(response.text)
                for challenge in r_json["challenges"]:
                    if challenge["type"] == self.challenge_type:
                        print("challenge: ", challenge)
                        chall = {"auth_url": auth_url, "chall_url": challenge["url"], 
                                 "chall_token": challenge["token"], "status": challenge["status"]}
                        self.challenges_todo.append(chall)
                        n += 1
            else:
                print("Challenge error: HTTP status code ", response.status_code)
                print(response.text)
                exit()
        print(json.dumps(self.challenges_todo, indent=4), end="\n\n")
        return n
    
    def create_key_authorization(self, token):
        pub_key_x = self.key.pointQ.x.to_bytes()
        pub_key_y = self.key.pointQ.y.to_bytes()
        base64_pub_key_x = base64.urlsafe_b64encode(pub_key_x).decode("utf-8").replace("=", "")
        base64_pub_key_y = base64.urlsafe_b64encode(pub_key_y).decode("utf-8").replace("=", "")
        
        public_key = {
            "crv": "P-256",
            "kty": "EC",
            "x": base64_pub_key_x,
            "y": base64_pub_key_y
            }
        
        # TODO: fix format of account key 
        format_account_key = json.dumps(public_key, separators=(',', ':')).encode("utf-8")
        hashed_account_key = SHA256.new(format_account_key).digest()
        authorization = str.encode(token) + b"." + str.encode(base64.urlsafe_b64encode(hashed_account_key).decode("utf-8").replace("=", ""))
        return authorization
   
    
    
    def polling(self, url, kid):
        # poll ACME server to check if the challenge is validated
        payload = ""
        status = "invalid"
        while status != "valid":
            sleep(2)
            protected_payload = self.create_protected_payload(payload, url, kid)
            response = requests.post(url, headers={"Content-Type": "application/jose+json"},
                                        json=protected_payload, verify="./pebble.minica.pem")   
            r_json = response.json()
            status = r_json["status"]
            print("response: ", response.text)
            print("\033[1m Polling: \033[0m", status,)
            
        
        return r_json
            
        
                
                
    def validate_challenge(self):
        if self.challenge_type == "http-01":
            self.validate_http_challenge()
        else:
            self.validate_dns_challenge()
            
    
    def validate_dns_challenge(self):
        # # iterate through challenges, get the TXT record and add it to the DNS server
        # poll the ACME server to check if the challenge is validated
        # if yes, stop DNS server and go on with the next challenge
        for i,challenge in enumerate(self.challenges_todo):
            test_dns = CustomDNS(self.domains, self.IPv4_ADDRESS)
            
            # add TXT record for the challenge
            auth_key = self.create_key_authorization(challenge["chall_token"])
            hashed_key = SHA256.new(auth_key)
            txt_record = base64.urlsafe_b64encode(hashed_key.digest()).decode("utf-8").replace("=", "") 
                        
            # add token to TXT record of DNS server
            test_dns.add_TXT_record(f"_acme-challenge.{self.domains[i]}", txt_record)
                      
            # start DNS    
            server_dns = DNSServer(test_dns, port=10053, address=self.IPv4_ADDRESS)
            server_dns.start_thread()
              
            # acknowledge the challenge by sending an empty POST request to the challenge URL
            payload = {}
            protected_payload = self.create_protected_payload(payload, challenge["chall_url"], self.kid)
            response = requests.post(challenge["chall_url"], headers={"Content-Type": "application/jose+json"},
                                     json=protected_payload, verify="./pebble.minica.pem")
            
            #start polling
            self.polling(challenge["chall_url"], self.kid)
            
            sleep(1)
        print("shutting down DNS server")
        # MAYBE I SHOUDN't STOP THE DNS SERVER HERE but do it in later instead
        #server_dns.stop()
        
        
    def validate_http_challenge(self):
        # start DNS server
        test_dns = CustomDNS(self.domains, self.IPv4_ADDRESS)
        server_dns = DNSServer(test_dns, port=10053, address=self.IPv4_ADDRESS)
        server_dns.start_thread()
        
        # validate challenges
        for c in self.challenges_todo:
            key_auth = self.create_key_authorization(c["chall_token"])
            server_http = HTTPChallenge(c["chall_token"], key_auth, self.IPv4_ADDRESS)

            #server_http.challenge_update(c["chall_token"], key_auth)
            # launch HTTP server in new thread
            server_http.start()
            

            # acknowledge the challenge by sending an empty POST request to the challenge URL
            payload = {}
            protected_payload = self.create_protected_payload(payload, c["chall_url"], self.kid)
            response = requests.post(c["chall_url"], headers={"Content-Type": "application/jose+json"},
                                     json=protected_payload, verify="./pebble.minica.pem")
            
            print("response from ACME_server: ", response.text)
        
            # start polling
            self.polling(c["chall_url"], self.kid)
            
            sleep(2)
            
            print("shutting down HTTP server")
            server_http.terminate()
            server_http.join()   
            
        # stop DNS server
        #print("Stopping DNS server")
        #server_dns.stop()
        
        
        
        
        
    def get_certificate(self):
        # send Certificate Signing Request (CSR) to the ACME server
        # POST the CSR to the finalize URL
        payload = {
            "csr": self.create_csr()
            }
        
        protected_payload = self.create_protected_payload(payload, self.finalize, self.kid)
        
        response = requests.post(self.finalize, headers={"Content-Type": "application/jose+json"},
                                        json=protected_payload, verify="./pebble.minica.pem")
        
        print("response for Finalize_order: ", response.text)
        
        
        # start polling to check if the certificate is ready
        r_json = self.polling(self.order, self.kid)
        
        self.url_cert = r_json["certificate"]
        
        print("Certificate URL: ", self.url_cert)
        
    
    def retrieve_certificate(self):
        payload = ""
        protected_payload = self.create_protected_payload(payload, self.url_cert, self.kid)
        response = requests.post(self.url_cert, headers={"Content-Type": "application/jose+json"},
                                        json=protected_payload, verify="./pebble.minica.pem")
        
        print("response for certificate: ", response.text)
        #print("Certificate: ", response.headers)
        self.certif = response.text
        
        return self.certif
        
    def create_csr(self):
        sleep(1)
        # we could add a bunch of more attributes but not necessary for the project
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "acme-project"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich")]
            )).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain) for domain in self.domains]), 
                critical=False)
        
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        
        # write private key to file
        with open("private_key.pem", "wb") as f:
            f.write(signing_key.private_bytes(encoding=serialization.Encoding.PEM, 
                                               format=serialization.PrivateFormat.TraditionalOpenSSL,
                                               encryption_algorithm=serialization.NoEncryption()))
        
        csr = csr_builder.sign(signing_key, hashes.SHA256(), default_backend())
        
        # get the PEM encoded CSR
        csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
        
        # get the DER encoded CSR
        csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
        
        
        return base64.urlsafe_b64encode(csr_der).decode("utf-8").replace("=", "")
            
        
    def revoke_certificate(self):
        # POST revokeCert request 
        
        # der encoded certificate for revocation
        der_cert = x509.load_pem_x509_certificate(self.certif.encode("utf-8"), default_backend())
        encoded_cert = der_cert.public_bytes(encoding=serialization.Encoding.DER)
        
        payload = {
            "certificate": base64.urlsafe_b64encode(encoded_cert).decode("utf-8").replace("=", "")
            }
        
        protected_payload = self.create_protected_payload(payload, self.url_revokeCert, self.kid)
        
        print("payload: ", payload)
        response = requests.post(self.url_revokeCert, headers={"Content-Type": "application/jose+json"},
                                        json=protected_payload, verify="./pebble.minica.pem")
        
        if response.status_code == 200:
            print("response : " , response.headers)
        else:
            print("Certificate revocation error: HTTP status code ", response.status_code)
            print(response.text)
            exit()
            